// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WHATWG Encoding Standard — TextDecoder implementation.
//!
//! Supports UTF-8, UTF-16LE, UTF-16BE, and ISO-8859-1 with streaming decode
//! and BOM handling per spec.

use std::cell::{Cell, RefCell};

use zuqe::{
    CallContext, ClassCtorDef, FieldDef, JSResult, JSValue, Object, ScopedContext,
    def_native_object,
};

/// Supported encodings for TextDecoder
#[derive(Clone, Copy, PartialEq)]
enum Encoding {
    Utf8,
    Utf16Le,
    Utf16Be,
    Iso8859_1,
}

impl Encoding {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "utf-8" | "utf8" => Some(Encoding::Utf8),
            "utf-16le" | "utf16le" => Some(Encoding::Utf16Le),
            "utf-16be" | "utf16be" => Some(Encoding::Utf16Be),
            "iso-8859-1" | "iso8859-1" | "latin1" => Some(Encoding::Iso8859_1),
            _ => None,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Encoding::Utf8 => "utf-8",
            Encoding::Utf16Le => "utf-16le",
            Encoding::Utf16Be => "utf-16be",
            Encoding::Iso8859_1 => "iso-8859-1",
        }
    }
}

// ---------------------------------------------------------------------------
// TextDecoder opaque payload: stores all state in Rust memory
// ---------------------------------------------------------------------------

// No JS GC nodes in this payload (only plain Rust state).
pub(crate) struct TextDecoderPayload {
    encoding: Encoding,
    fatal: bool,
    ignore_bom: bool,
    bom_handled: Cell<bool>,
    pending: RefCell<Vec<u8>>,
}

zuqe::gc_lite::unsafe_empty_gc_trace!(TextDecoderPayload);

fn get_decoder<'a>(
    ctx: &mut ScopedContext,
    val: &'a JSValue,
) -> Result<&'a TextDecoderPayload, i32> {
    JSTextDecoder::payload_of(val)
        .ok_or_else(|| ctx.throw_internal_error("not a TextDecoder instance"))
}

fn js_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let new_target = cc.this();

    // Parse encoding
    let encoding = if cc.length() > 0 {
        let enc_str = cc.arg(0).to_string(ctx)?;
        let enc_name = enc_str.content().encode_utf8(false).to_string();
        Encoding::from_str(&enc_name)
            .ok_or_else(|| ctx.throw_range_error(&format!("Unsupported encoding: {}", enc_name)))?
    } else {
        Encoding::Utf8
    };

    // Parse constructor options: { fatal?, ignoreBOM? }
    let mut fatal = false;
    let mut ignore_bom = false;
    if cc.length() > 1 {
        let arg1 = cc.arg(1);
        match arg1.as_object() {
            Some(opts) => {
                let fatal_val = opts.get_property_str(ctx, "fatal")?;
                if !fatal_val.is_undefined() {
                    fatal = fatal_val.to_bool()?;
                }
                let ignore_bom_val = opts.get_property_str(ctx, "ignoreBOM")?;
                if !ignore_bom_val.is_undefined() {
                    ignore_bom = ignore_bom_val.to_bool()?;
                }
            }
            None => {
                return Err(ctx.throw_type_error("Options must be an object"));
            }
        }
    }

    JSTextDecoder::new_instance(
        ctx,
        new_target,
        TextDecoderPayload {
            encoding,
            fatal,
            ignore_bom,
            bom_handled: Cell::new(false),
            pending: RefCell::new(Vec::new()),
        },
    )
    .map(JSValue::from)
}

// ---------------------------------------------------------------------------
// UTF-8 streaming decoder
//
// Returns (decoded_string, pending_bytes).  When `stream` is true and the
// input ends in the middle of a multi-byte sequence, the partial bytes are
// returned as pending and decoding stops early.  When `stream` is false,
// incomplete trailing sequences are treated as errors.
// ---------------------------------------------------------------------------

fn decode_utf8(bytes: &[u8], fatal: bool, stream: bool) -> Result<(String, Vec<u8>), String> {
    let mut out = String::new();
    let mut i = 0;
    let len = bytes.len();

    while i < len {
        let b = bytes[i];

        // Determine expected sequence length and min code point
        let (seq_len, min_cp) = if b < 0x80 {
            (1, 0u32)
        } else if (0xC2..=0xDF).contains(&b) {
            (2, 0x80)
        } else if (0xE0..=0xEF).contains(&b) {
            (3, 0x800)
        } else if (0xF0..=0xF4).contains(&b) {
            (4, 0x10000)
        } else {
            // Stray continuation byte (0x80-0xBF), overlong lead (0xC0-0xC1),
            // or invalid lead (0xF5-0xFF)
            if fatal {
                return Err("Invalid UTF-8 sequence: unexpected byte".into());
            }
            out.push('\u{FFFD}');
            i += 1;
            continue;
        };

        // Check if the full sequence fits in the available bytes
        if seq_len > 1 && i + seq_len > len {
            if stream {
                // Save incomplete trailing bytes for the next chunk
                return Ok((out, bytes[i..].to_vec()));
            } else {
                // Flush mode: incomplete sequence is an error
                if fatal {
                    return Err("Incomplete UTF-8 sequence on flush".into());
                }
                out.push('\u{FFFD}');
                i += 1;
                continue;
            }
        }

        // Decode the multi-byte sequence
        let mut cp = if seq_len == 1 {
            // Single-byte: 0xxxxxxx, data is the full 7 bits
            b as u32
        } else {
            // Multi-byte lead byte: bits depend on sequence length
            (b & (0x7F >> seq_len)) as u32
        };
        let mut valid = seq_len == 1; // single-byte is always valid
        if seq_len > 1 {
            valid = true;
            for j in 1..seq_len {
                let cb = bytes[i + j];
                if cb & 0xC0 != 0x80 {
                    valid = false;
                    break;
                }
                cp = (cp << 6) | (cb & 0x3F) as u32;
            }
        }

        if !valid || cp < min_cp || (0xD800..=0xDFFF).contains(&cp) || cp > 0x10FFFF {
            if fatal {
                return Err("Invalid UTF-8 sequence".into());
            }
            out.push('\u{FFFD}');
            i += 1;
        } else {
            // SAFETY: validated above
            out.push(unsafe { char::from_u32_unchecked(cp) });
            i += seq_len;
        }
    }

    Ok((out, Vec::new()))
}

// ---------------------------------------------------------------------------
// UTF-16 streaming decoder (both LE and BE)
// ---------------------------------------------------------------------------

fn decode_utf16(
    bytes: &[u8],
    le: bool,
    fatal: bool,
    stream: bool,
) -> Result<(String, Vec<u8>), String> {
    let odd = bytes.len() % 2;

    // Determine how many whole code units we have
    let complete_len = if odd == 0 {
        bytes.len()
    } else if stream {
        bytes.len() - 1 // save the trailing byte as pending
    } else {
        bytes.len() // flush: include the odd byte, will error
    };

    let mut out = String::new();
    let mut i = 0;
    while i + 1 < complete_len {
        let cu = if le {
            u16::from_le_bytes([bytes[i], bytes[i + 1]])
        } else {
            u16::from_be_bytes([bytes[i], bytes[i + 1]])
        };

        match char::from_u32(cu as u32) {
            Some(c) => {
                out.push(c);
                i += 2;
            }
            None => {
                if fatal {
                    return Err("Invalid UTF-16 code unit".into());
                }
                out.push('\u{FFFD}');
                i += 2;
            }
        }
    }

    // Handle trailing odd byte in flush mode
    if odd != 0 && !stream && fatal {
        return Err("Incomplete UTF-16 data on flush".into());
    }
    if odd != 0 && !stream {
        out.push('\u{FFFD}');
    }

    let pending = if odd != 0 && stream {
        vec![bytes[bytes.len() - 1]]
    } else {
        Vec::new()
    };

    Ok((out, pending))
}

/// Internal: decode &[u8] with BOM handling, returns (string, pending)
fn process_decoded(
    decoder: &TextDecoderPayload,
    data: &[u8],
    call_fatal: bool,
    stream: bool,
) -> Result<(String, Vec<u8>), String> {
    // BOM stripping: only on the first decode() call; uses slice offset, no copy.
    let bom_handled = decoder.bom_handled.get();

    let slice = if !bom_handled && !decoder.ignore_bom && data.len() >= 2 {
        let bom_len = match decoder.encoding {
            Encoding::Utf8 => {
                if data.len() >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
                    Some(3)
                } else {
                    None
                }
            }
            Encoding::Utf16Le | Encoding::Iso8859_1 => {
                if data[0] == 0xFF && data[1] == 0xFE {
                    Some(2)
                } else {
                    None
                }
            }
            Encoding::Utf16Be => {
                if data[0] == 0xFE && data[1] == 0xFF {
                    Some(2)
                } else {
                    None
                }
            }
        };
        match bom_len {
            Some(n) => &data[n..],
            None => data,
        }
    } else {
        data
    };
    decoder.bom_handled.set(true);

    match decoder.encoding {
        Encoding::Utf8 => decode_utf8(slice, call_fatal, stream),
        Encoding::Utf16Le => decode_utf16(slice, true, call_fatal, stream),
        Encoding::Utf16Be => decode_utf16(slice, false, call_fatal, stream),
        Encoding::Iso8859_1 => Ok((
            slice.iter().map(|&b| b as char).collect::<String>(),
            Vec::new(),
        )),
    }
}

fn js_text_decoder_decode(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let decoder = get_decoder(ctx, &this)?;

    // Parse options first (no borrow on decoder internals needed here).
    let mut stream = false;
    let mut call_fatal = decoder.fatal;

    // Extract input as &[u8] (zero-copy) and process inline.
    // We keep the match arm as the outer scope so the &[u8] borrow stays valid.
    let mut ob: Option<Object> = None;
    let input_slice = if cc.length() == 0 {
        &[]
    } else {
        if cc.length() > 1
            && let Some(opts) = cc.arg(1).as_object()
        {
            let v = opts.get_property_str(ctx, "stream")?;
            if !v.is_undefined() {
                stream = v.to_bool()?;
            }

            let v = opts.get_property_str(ctx, "fatal")?;
            if !v.is_undefined() {
                call_fatal = v.to_bool()?;
            }
        }

        let a = cc.arg(0);
        if a.is_string() {
            return Ok(a);
        }

        if let Some(o) = a.as_object() {
            ob.replace(o);

            let p = ob.as_ref().unwrap();
            if let Some(ab) = p.payload_array_buffer() {
                ab.bytes() // &[u8] borrowing from the JS object
            } else if let Some(ta) = p.payload_typed_array() {
                ta.bytes()
            } else {
                return Err(ctx.throw_type_error("Input must be an ArrayBuffer or TypedArray"));
            }
        } else {
            return Err(ctx.throw_type_error("Input must be TypedArray, ArrayBuffer or Object"));
        }
    };

    let pending_old = std::mem::take(&mut *decoder.pending.borrow_mut());

    let (result, pending_new) = if pending_old.is_empty() {
        // Fast path: no pending bytes → pass &[u8] directly, zero allocation.
        process_decoded(decoder, input_slice, call_fatal, stream)
            .map_err(|e| ctx.throw_type_error(&e))?
    } else {
        // Slow path:  has pending  → merge into Vec (pending already allocated).
        let mut combined = pending_old;
        combined.extend_from_slice(input_slice);
        process_decoded(decoder, &combined, call_fatal, stream)
            .map_err(|e| ctx.throw_type_error(&e))?
    };

    if stream {
        *decoder.pending.borrow_mut() = pending_new;
    }

    ctx.create_string_from_utf8(result.into_bytes())
        .map(JSValue::make_string)
        .map_err(|_| ctx.throw_internal_error("Failed to create output string"))
}

// ---------------------------------------------------------------------------
// Getters
// ---------------------------------------------------------------------------

fn js_text_decoder_encoding_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let decoder = get_decoder(ctx, &this)?;
    ctx.create_string_from_utf8(decoder.encoding.label().as_bytes().to_vec())
        .map(JSValue::make_string)
}

fn js_text_decoder_fatal_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let decoder = get_decoder(ctx, &this)?;
    Ok(JSValue::from(decoder.fatal))
}

fn js_text_decoder_ignore_bom_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let decoder = get_decoder(ctx, &this)?;
    Ok(JSValue::from(decoder.ignore_bom))
}

// ---------------------------------------------------------------------------
// Class registration
// ---------------------------------------------------------------------------

const CLASS_TEXT_DECODER_PROTO: &[FieldDef] = &[
    FieldDef::GETSET_ENUM("encoding", Some(js_text_decoder_encoding_getter), None, 0),
    FieldDef::GETSET_ENUM("fatal", Some(js_text_decoder_fatal_getter), None, 0),
    FieldDef::GETSET_ENUM(
        "ignoreBOM",
        Some(js_text_decoder_ignore_bom_getter),
        None,
        0,
    ),
    FieldDef::FUNC_ENUM("decode", 2, js_text_decoder_decode, 0),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "TextDecoder",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "TextDecoder",
    JSTextDecoder,
    TextDecoderPayload,
    CLASS_TEXT_DECODER_PROTO,
    Some(ClassCtorDef::new(js_constructor, 2, true).expose_to_global())
);
