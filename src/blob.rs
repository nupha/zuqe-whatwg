// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WHATWG `Blob` implementation.
//!
//! Conforms to the File API `Blob` spec: an immutable, type-tagged bag of
//! bytes with slicing and async consumers (`arrayBuffer`/`text`/`stream`/
//! `bytes`). Bytes are stored behind `Arc<[u8]>` so `slice()` can share the
//! underlying buffer without copying.

use std::{ptr::null_mut, sync::Arc};

use zuqe::{
    CallContext, ClassCtorDef, FieldDef, JSResult, JSValue, ScopedContext,
    builtins::{array_buffer::ArrayBuffer, promise::Promise, typed_array::TypedArray},
    def_native_object,
};

use crate::stream::JSReadableStream;

/// Immutable blob contents: a shared byte buffer plus its MIME type.
#[derive(Clone)]
pub(crate) struct BlobPayload {
    /// Underlying bytes, shared across `slice()` results via `Arc`.
    pub(crate) bytes: Arc<[u8]>,
    /// Lower-cased MIME type, stripped of control characters per spec.
    pub(crate) type_: String,
}

// No JS GC nodes in this payload.
zuqe::gc_lite::unsafe_empty_gc_trace!(BlobPayload);

impl BlobPayload {
    pub(crate) fn size(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn type_(&self) -> &str {
        &self.type_
    }
}

/// Construct a `Blob` from already-resolved bytes + a MIME type.
/// Used by `Response.blob()` and `Blob.slice()`.
pub(crate) fn blob_from_bytes(
    ctx: &mut ScopedContext,
    bytes: Arc<[u8]>,
    type_: String,
) -> Result<JSValue, i32> {
    JSBlob::new_instance(ctx, JSValue::UNDEFINED, BlobPayload { bytes, type_ }).map(|b| b.into())
}

/// Read the shared byte buffer out of a JS `Blob` value, if it is one.
/// Returns `None` for anything that is not a `Blob` instance.
pub(crate) fn blob_bytes_of(val: &JSValue) -> Option<Arc<[u8]>> {
    JSBlob::payload_of(val).map(|p| p.bytes.clone())
}

/// Read the MIME type out of a JS `Blob` value, if it is one.
pub(crate) fn blob_type_of(val: &JSValue) -> Option<String> {
    JSBlob::payload_of(val).map(|p| p.type_.clone())
}

/// Normalize a type string per File API. The result is a parseable media type
/// in lower case, or the empty string when the input is not parseable.
///
/// File API: `new Blob(parts, {type})` ignores `type` (treating it as empty)
/// unless it is a *valid media type* — i.e. it parses as `type"/"subtype` with
/// non-empty `type` and `subtype` tokens made of token characters. Control
/// characters (0x00-0x1F, 0x7F) are stripped first; the remaining string is
/// then validated and lower-cased (WPT `scheme-blob.sub.any.js`:
/// `Blob([], {type:"invalid"})` must yield type `""`, not `"invalid"`).
fn normalize_type(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !(*c as u32 <= 0x1F || *c as u32 == 0x7F))
        .collect();

    // A valid media type is `<token>/<token>`: a single '/', each side a
    // non-empty token (RFC 7230 token = alpha/digit or `!#$%&'*+-.^_`|~`).
    fn is_token(s: &str) -> bool {
        !s.is_empty()
            && s.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(
                        c,
                        '!' | '#'
                            | '$'
                            | '%'
                            | '&'
                            | '\''
                            | '*'
                            | '+'
                            | '-'
                            | '.'
                            | '^'
                            | '_'
                            | '`'
                            | '|'
                            | '~'
                    )
            })
    }

    // File API: the type is kept when it "can be parsed as a MIME type", i.e.
    // the MIME parsing algorithm succeeds — parameters are allowed, so the
    // type/subtype part before the first ';' must be `token/token` and the rest
    // must be a valid `;`-separated parameter list (WPT
    // `response-init-contenttype`: `Blob([], {type:"a/b; c=d"})` keeps its type).
    fn valid_params(s: &str) -> bool {
        fn trim(s: &str) -> &str {
            s.trim_matches(|c: char| c == ' ' || c == '\t')
        }
        let s = trim(s);
        if s.is_empty() {
            return true;
        }
        if !s.starts_with(';') {
            return false;
        }
        s.split(';').skip(1).all(|p| {
            let p = trim(p);
            match p.split_once('=') {
                Some((name, value)) => is_token(trim(name)) && is_token(trim(value)),
                None => false,
            }
        })
    }

    let head = cleaned.split(';').next().unwrap_or_default();
    if let Some((ty, sub)) = head.split_once('/')
        && is_token(ty.trim())
        && is_token(sub.trim())
        && valid_params(&cleaned[head.len()..])
    {
        return cleaned.to_ascii_lowercase();
    }

    String::new()
}

/// Extract bytes from a single BlobPart (String / ArrayBufferView / ArrayBuffer
/// / Blob) into an owned `Vec<u8>` for concatenation.
fn part_to_bytes(ctx: &mut ScopedContext, part: &JSValue) -> Result<Vec<u8>, i32> {
    // Blob part: reuse its existing bytes.
    if let Some(bytes) = blob_bytes_of(part) {
        return Ok(bytes.to_vec());
    }
    // TypedArray / ArrayBuffer view.
    if let Ok(mut ta) = TypedArray::try_from(*part) {
        return Ok(ta.with_bytes_mut(|b| b.to_vec()));
    }
    // String part: UTF-8 encode (spec uses UTF-8 for Blob strings).
    let s = part.to_string(ctx)?;
    Ok(s.content().encode_utf8(false).as_bytes().to_vec())
}

fn js_blob_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let new_target = cc.this();
    // Collect BlobParts into an owned list of JS values. The spec accepts an
    // array-like (sequence) of parts; we iterate it like any JS sequence.
    let parts: Vec<JSValue> = if cc.length() > 0 {
        let arg = cc.arg(0);
        if arg.is_array(ctx)? {
            let len = arg
                .get_property_str(ctx, "length")?
                .to_number(ctx)?
                .to_i32() as usize;
            let mut out = Vec::with_capacity(len);
            for i in 0..len {
                out.push(arg.get_property_str(ctx, &i.to_string())?);
            }
            out
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // Collect bytes from all parts.
    let mut buf: Vec<u8> = Vec::new();
    for part in &parts {
        buf.extend_from_slice(&part_to_bytes(ctx, part)?);
    }

    // Resolve the `type` and `endings` options.
    let mut type_ = String::new();
    if cc.length() > 1 {
        let opts = cc.arg(1);
        if !opts.is_undefined_or_null() {
            // `endings`: must be "transparent" or "native" (case-sensitive enum).
            // Invalid values throw TypeError. On the Web platform `native` is
            // equivalent to `transparent` (no newline translation), so the value
            // only affects validation here.
            let e = opts.get_property_str(ctx, "endings")?;
            if !e.is_undefined_or_null() {
                match e.to_string(ctx)?.content().encode_utf8(false).as_ref() {
                    "transparent" | "native" => {}
                    _ => return Err(ctx.throw_type_error("Invalid `endings` option")),
                }
            }

            let t = opts.get_property_str(ctx, "type")?;
            if !t.is_undefined_or_null() {
                let s = t.to_string(ctx)?;
                type_ = normalize_type(&s.content().encode_utf8(false));
            }
        }
    }

    let payload = BlobPayload {
        bytes: buf.into(),
        type_,
    };
    JSBlob::new_instance(ctx, new_target, payload).map(|b| b.into())
}

fn js_blob_get_size(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSBlob::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("Blob.prototype.size called on non-Blob"))?;
    Ok(JSValue::from(p.size() as i64))
}

fn js_blob_get_type(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSBlob::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("Blob.prototype.type called on non-Blob"))?;
    let s = ctx.create_string_from_utf8(p.type_().as_bytes().to_vec())?;
    Ok(JSValue::make_string(s))
}

/// Clamp and resolve slice start/end per spec: relative-to-length handling,
/// NaN -> 0, and clamping into [0, length].
fn resolve_slice_range(start: f64, end: f64, len: usize) -> (usize, usize) {
    let len_f = len as f64;
    let s = if start.is_nan() {
        0.0
    } else if start < 0.0 {
        (len_f + start).max(0.0)
    } else {
        start.min(len_f)
    };
    let e = if end.is_nan() {
        len_f
    } else if end < 0.0 {
        (len_f + end).max(0.0)
    } else {
        end.min(len_f)
    };
    let (s, e) = (s as usize, e as usize);
    (s.min(e), e) // ensure s <= e
}

fn js_blob_slice(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let payload = JSBlob::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("Blob.prototype.slice called on non-Blob"))?;
    let len = payload.size();

    let start = if cc.length() > 0 {
        cc.arg(0).to_number(ctx)?.to_f64()
    } else {
        0.0
    };
    let end = if cc.length() > 1 {
        cc.arg(1).to_number(ctx)?.to_f64()
    } else {
        len as f64
    };
    let (s, e) = resolve_slice_range(start, end, len);

    // Slice shares the underlying buffer via Rc (no copy of untouched bytes).
    let sliced: Arc<[u8]> = Arc::from(&payload.bytes()[s..e]);

    // `contentType` option.
    let mut type_ = payload.type_().to_string();
    if cc.length() > 2 {
        let ct = cc.arg(2);
        if !ct.is_undefined_or_null() {
            let s = ct.to_string(ctx)?;
            type_ = normalize_type(&s.content().encode_utf8(false));
        }
    }

    blob_from_bytes(ctx, sliced, type_)
}

/// Build an async consumer (`arrayBuffer`/`text`/`bytes`) on the byte buffer.
fn js_blob_consume(ctx: &mut ScopedContext, cc: CallContext, as_type: BlobConsumeKind) -> JSResult {
    let this = cc.this();
    let bytes: Arc<[u8]> = JSBlob::payload_of(&this)
        .map(|p| p.bytes.clone())
        .ok_or_else(|| ctx.throw_type_error("Blob consumer called on non-Blob"))?;

    let (promise, tx) =
        Promise::create_with_channel::<Result<(), String>>(ctx, move |cx, _| -> JSResult {
            let buf: Vec<u8> = bytes.to_vec();
            match as_type {
                // `arrayBuffer()` returns a real ArrayBuffer; `bytes()` a Uint8Array.
                BlobConsumeKind::ArrayBuffer => ArrayBuffer::from_bytes(
                    cx,
                    JSValue::UNDEFINED,
                    buf.into_boxed_slice(),
                    null_mut(),
                )
                .map(JSValue::from),
                BlobConsumeKind::Bytes => {
                    TypedArray::create_from_vec_u8(cx, buf).map(JSValue::from)
                }
                BlobConsumeKind::Text => {
                    let s = String::from_utf8_lossy(&buf);
                    cx.create_string_from_utf8(s.as_bytes().to_vec())
                        .map(JSValue::make_string)
                }
            }
        })?;

    let _ = tx.send(Ok(()));
    Ok(promise.into())
}

enum BlobConsumeKind {
    ArrayBuffer,
    Text,
    Bytes,
}

fn js_blob_array_buffer(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    js_blob_consume(ctx, cc, BlobConsumeKind::ArrayBuffer)
}

fn js_blob_text(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    js_blob_consume(ctx, cc, BlobConsumeKind::Text)
}

fn js_blob_bytes(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    js_blob_consume(ctx, cc, BlobConsumeKind::Bytes)
}

fn js_blob_stream(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let bytes: Arc<[u8]> = JSBlob::payload_of(&this)
        .map(|p| p.bytes.clone())
        .ok_or_else(|| ctx.throw_type_error("Blob.prototype.stream called on non-Blob"))?;
    Ok(JSValue::from(JSReadableStream::from_bytes(
        ctx,
        bytes.to_vec(),
    )?))
}

const BLOB_PROTO: &[FieldDef] = &[
    FieldDef::GETSET_ENUM("size", Some(js_blob_get_size), None, 0),
    FieldDef::GETSET_ENUM("type", Some(js_blob_get_type), None, 0),
    FieldDef::FUNC_ENUM("slice", 3, js_blob_slice, 0),
    FieldDef::FUNC_ENUM("arrayBuffer", 0, js_blob_array_buffer, 0),
    FieldDef::FUNC_ENUM("text", 0, js_blob_text, 0),
    FieldDef::FUNC_ENUM("bytes", 0, js_blob_bytes, 0),
    FieldDef::FUNC_ENUM("stream", 0, js_blob_stream, 0),
    FieldDef::STR("[Symbol.toStringTag]", "Blob", zuqe::JS_PROP_CONFIGURABLE),
];

def_native_object!(
    "Blob",
    JSBlob,
    BlobPayload,
    BLOB_PROTO,
    Some(ClassCtorDef::new(js_blob_constructor, 2, true).expose_to_global())
);
