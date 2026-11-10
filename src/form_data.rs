// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WHATWG `FormData` (https://xhr.spec.whatwg.org/#interface-formdata).
//!
//! An entry list of (name, value) pairs where a value is either a string or a
//! `Blob`. Order is insertion order (unlike `Headers`, the list is never
//! sorted), and duplicate names are allowed — so the storage is a plain `Vec`.
//!
//! `Blob` values are stored as JS values rather than raw bytes so that entry
//! identity is preserved (`fd.get(n) === blob` per spec) and the object stays
//! reachable; that makes the payload a GC root (see `on_payload_gc`).

use std::cell::RefCell;

use zuqe::{
    Array, Atom, CallContext, ClassCtorDef, FieldDef, GcBind, JS_CLASS_ITERATOR, JS_PROP_C_W_E,
    JSIteratorKindEnum, JSResult, JSValue, Object, ScopedContext, WriteBarrier, WriteBarrierVec,
    def_native_object,
    gc_lite::GcTrace,
};

use crate::blob::{blob_bytes_of, blob_from_bytes, blob_type_of};

/// A single entry value: a string, or a `Blob`/`File` kept as a JS value.
#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
enum EntryValue {
    Str(String),
    /// A `Blob` value plus the filename it was appended under. The spec stores
    /// the filename on the entry, not on the blob, so `append(n, blob, fname)`
    /// does not mutate the blob itself.
    Blob {
        value: WriteBarrier<JSValue>,
        filename: String,
    },
}

/// Transient read copies (`get`/`getAll`/`forEach`/iteration snapshots out of
/// the borrow): the copy is never stored back into the payload, so unwrapping
/// the guard is safe. `WriteBarrier` itself is deliberately not `Clone`.
impl Clone for EntryValue {
    fn clone(&self) -> Self {
        match self {
            EntryValue::Str(s) => EntryValue::Str(s.clone()),
            EntryValue::Blob { value, filename } => EntryValue::Blob {
                value: WriteBarrier::new(value.get()),
                filename: filename.clone(),
            },
        }
    }
}

/// One entry: a local element type for `WriteBarrierVec` — the tuple
/// `(String, EntryValue)` is foreign, so it cannot `impl GcBind` (E0117).
#[derive(Clone, GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
struct FormDataEntry {
    name: String,
    value: EntryValue,
}

impl GcBind for FormDataEntry {
    fn bind_node(&self, ctx: &ScopedContext, owner: std::ptr::NonNull<zuqe::gc_lite::GcHead>) {
        // Only a `Blob` JS value is a GC leaf; `String` is not.
        if let EntryValue::Blob { value, .. } = &self.value {
            GcBind::bind_node(&value.get(), ctx, owner);
        }
    }
}

/// Entry list, in insertion order. Duplicate names are allowed.
#[derive(Default, GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct FormDataPayload {
    entries: RefCell<WriteBarrierVec<FormDataEntry>>,
}

fn get_fd<'a>(ctx: &mut ScopedContext, val: &'a JSValue) -> Result<&'a FormDataPayload, i32> {
    JSFormData::payload_of(val).ok_or_else(|| ctx.throw_type_error("not a FormData instance"))
}

// ---------------------------------------------------------------------------
// Entry construction (spec: "create an entry")
// ---------------------------------------------------------------------------

/// Default filename the spec assigns to a `Blob` value that is appended
/// without an explicit filename.
const DEFAULT_BLOB_FILENAME: &str = "blob";

/// Build an entry value from a JS argument. Per spec, a value that is not a
/// `Blob` is stringified; a `Blob` keeps its identity and gets a filename.
///
/// `filename_arg` is the optional third argument of `append`/`set`. Passing an
/// explicit filename for a non-`Blob` value is ignored (the value is still a
/// string entry), matching the WebIDL overload resolution.
fn make_entry(
    ctx: &mut ScopedContext,
    value: JSValue,
    filename_arg: Option<JSValue>,
) -> Result<EntryValue, i32> {
    if blob_bytes_of(&value).is_none() {
        let s = value.to_string(ctx)?;
        return Ok(EntryValue::Str(s.content().encode_utf8(false).to_string()));
    }

    // A `Blob` entry: the filename defaults to "blob" unless one is supplied.
    let filename = match filename_arg {
        Some(f) if !f.is_undefined() => {
            let s = f.to_string(ctx)?;
            s.content().encode_utf8(false).to_string()
        }
        _ => DEFAULT_BLOB_FILENAME.to_string(),
    };
    Ok(EntryValue::Blob {
        // No owner here: the FormData already exists, so bind_node records the barrier on push.
        value: WriteBarrier::new(value),
        filename,
    })
}

/// Convert an entry back to the JS value `get()`/iteration should expose.
fn entry_to_js(ctx: &mut ScopedContext, entry: &EntryValue) -> JSResult {
    match entry {
        EntryValue::Str(s) => ctx
            .create_string_from_utf8(s.clone().into_bytes())
            .map(JSValue::make_string),
        EntryValue::Blob { value, .. } => Ok(value.get()),
    }
}

/// Read argument 0 as the entry name (stringified per WebIDL `USVString`).
fn arg_name(ctx: &mut ScopedContext, cc: &CallContext) -> Result<String, i32> {
    let s = cc.arg(0).to_string(ctx)?;
    Ok(s.content().encode_utf8(false).to_string())
}

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

fn js_fd_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    // The `form` / `submitter` arguments are DOM-only; with no DOM there is
    // nothing to prefill, so a fresh FormData is always empty.
    JSFormData::new_instance(ctx, cc.this(), FormDataPayload::default()).map(|o| o.into())
}

fn js_fd_append(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() < 2 {
        return Err(ctx.throw_type_error("append requires 2 arguments"));
    }
    let this = cc.this();
    let name = arg_name(ctx, &cc)?;
    let filename = (cc.length() > 2).then(|| cc.arg(2));
    let entry = make_entry(ctx, cc.arg(1), filename)?;
    let owner = this;
    // Push records the barrier in the entry's guard slot (FormData may be old).
    let fd = get_fd(ctx, &this)?;
    fd.entries
        .borrow_mut()
        .push(ctx, owner, FormDataEntry { name, value: entry });
    Ok(JSValue::UNDEFINED)
}

fn js_fd_delete(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() < 1 {
        return Err(ctx.throw_type_error("delete requires 1 argument"));
    }
    let this = cc.this();
    let name = arg_name(ctx, &cc)?;
    get_fd(ctx, &this)?
        .entries
        .borrow_mut()
        .retain(|e| e.name != name);
    Ok(JSValue::UNDEFINED)
}

fn js_fd_get(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() < 1 {
        return Err(ctx.throw_type_error("get requires 1 argument"));
    }
    let this = cc.this();
    let name = arg_name(ctx, &cc)?;
    // Clone the matched entry so the borrow ends before `entry_to_js` runs
    // (which may allocate and therefore trigger GC / re-entrancy).
    let found = get_fd(ctx, &this)?
        .entries
        .borrow()
        .iter()
        .find(|e| e.name == name)
        .map(|e| e.value.clone());
    match found {
        Some(v) => entry_to_js(ctx, &v),
        None => Ok(JSValue::NULL),
    }
}

fn js_fd_get_all(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() < 1 {
        return Err(ctx.throw_type_error("getAll requires 1 argument"));
    }
    let this = cc.this();
    let name = arg_name(ctx, &cc)?;
    let found: Vec<EntryValue> = get_fd(ctx, &this)?
        .entries
        .borrow()
        .iter()
        .filter(|e| e.name == name)
        .map(|e| e.value.clone())
        .collect();
    let values = found
        .iter()
        .map(|v| entry_to_js(ctx, v))
        .collect::<Result<Vec<_>, _>>()?;
    Array::from_values(ctx, values).map(JSValue::from)
}

fn js_fd_has(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() < 1 {
        return Err(ctx.throw_type_error("has requires 1 argument"));
    }
    let this = cc.this();
    let name = arg_name(ctx, &cc)?;
    let has = get_fd(ctx, &this)?
        .entries
        .borrow()
        .iter()
        .any(|e| e.name == name);
    Ok(JSValue::from(has))
}

/// `set()` replaces the *first* matching entry in place and drops the rest,
/// preserving the original position (spec: "replace the first such entry").
fn js_fd_set(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() < 2 {
        return Err(ctx.throw_type_error("set requires 2 arguments"));
    }
    let this = cc.this();
    let name = arg_name(ctx, &cc)?;
    let filename = (cc.length() > 2).then(|| cc.arg(2));
    let entry = make_entry(ctx, cc.arg(1), filename)?;
    let owner = this;

    let fd = get_fd(ctx, &this)?;
    let mut entries = fd.entries.borrow_mut();
    // Pushes below record the barrier in the entry's guard slot.
    match entries.iter().position(|e| e.name == name) {
        Some(idx) => {
            // `WriteBarrierVec` has no element-set: pull the first match and the
            // whole tail out, push the replacement (it lands exactly at `idx`),
            // then re-push the tail in order, dropping later duplicates.
            entries.remove(idx); // the old first match is replaced below
            let tail: Vec<_> = (idx..entries.len())
                .map(|_| entries.remove(idx))
                .filter(|e| e.name != name)
                .collect();
            entries.push(ctx, owner, FormDataEntry { name, value: entry });
            for e in tail {
                entries.push(ctx, owner, e);
            }
        }
        None => entries.push(ctx, owner, FormDataEntry { name, value: entry }),
    }
    Ok(JSValue::UNDEFINED)
}

fn js_fd_for_each(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() == 0 {
        return Err(ctx.throw_type_error("forEach requires a callback"));
    }
    let this = cc.this();
    let cb = cc.arg(0).ensure_callable(ctx)?;
    let this_arg = if cc.length() > 1 {
        cc.arg(1)
    } else {
        JSValue::UNDEFINED
    };
    // Snapshot up front so callback mutations cannot invalidate the borrow.
    let pairs: Vec<FormDataEntry> = get_fd(ctx, &this)?.entries.borrow().to_vec();
    for FormDataEntry { name, value: entry } in pairs {
        let value = entry_to_js(ctx, &entry)?;
        let key = JSValue::make_string(ctx.create_string_from_utf8(name.into_bytes())?);
        cb.call(ctx, this_arg, &[value, key, this])?;
    }
    Ok(JSValue::UNDEFINED)
}

// ---------------------------------------------------------------------------
// Iterator
// ---------------------------------------------------------------------------

/// Live iterator over a `FormData` entry list, holding an advancing index into
/// the shared list (mirrors the `Headers` iterator, but the list is unsorted).
#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub struct FormDataIter {
    pub obj: Object,
    pub index: u32,
    #[gc(skip)]
    pub kind: JSIteratorKindEnum,
}

impl FormDataIter {
    pub fn new(obj: Object, kind: JSIteratorKindEnum) -> Self {
        FormDataIter {
            obj,
            index: 0,
            kind,
        }
    }
}

/// Build a `{value, done}` iterator result object.
fn make_iter_result(ctx: &mut ScopedContext, value: JSValue, done: bool) -> JSResult {
    let mut obj = ctx.create_base_object()?;
    obj.define_property_value(ctx, Atom::CONST_value, value, JS_PROP_C_W_E)?;
    obj.define_property_value(ctx, Atom::CONST_done, JSValue::from(done), JS_PROP_C_W_E)?;
    Ok(obj.into())
}

fn js_fd_iterator_self(_ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    Ok(cc.this())
}

fn js_fd_iterator_ctor(_ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    Ok(JSValue::UNDEFINED)
}

fn js_fd_iterator_next(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let obj = this.as_object().ok_or(-1)?;
    let mut wrapper = FormDataIterator(obj);
    let it = FormDataIterator::payload_mut(&mut wrapper).ok_or(-1)?;
    let idx = it.index as usize;
    let kind = it.kind;
    let obj_val = JSValue::from(it.obj);

    let entries = &JSFormData::payload_of(&obj_val).ok_or(-1)?.entries;
    let len = entries.borrow().len();
    if idx >= len {
        // Park the index at the end so later calls stay done.
        it.index = len as u32;
        return make_iter_result(ctx, JSValue::UNDEFINED, true);
    }
    let FormDataEntry { name, value: entry } = entries.borrow().get(idx).ok_or(-1)?.clone();
    it.index = (idx + 1) as u32;

    match kind {
        JSIteratorKindEnum::JS_ITERATOR_KIND_KEY => {
            let k = JSValue::make_string(ctx.create_string_from_utf8(name.into_bytes())?);
            make_iter_result(ctx, k, false)
        }
        JSIteratorKindEnum::JS_ITERATOR_KIND_VALUE => {
            let v = entry_to_js(ctx, &entry)?;
            make_iter_result(ctx, v, false)
        }
        JSIteratorKindEnum::JS_ITERATOR_KIND_KEY_AND_VALUE => {
            let k = JSValue::make_string(ctx.create_string_from_utf8(name.into_bytes())?);
            let v = entry_to_js(ctx, &entry)?;
            let pair = Array::from_values(ctx, vec![k, v])?;
            make_iter_result(ctx, pair.into(), false)
        }
    }
}

const FORM_DATA_ITER_PROTO: &[FieldDef] = &[
    // `next` must be enumerable for WPT's `checkIteratorProperties`.
    FieldDef::FUNC_ENUM("next", 0, js_fd_iterator_next, 0),
    FieldDef::FUNC("[Symbol.iterator]", 0, js_fd_iterator_self, 0),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "FormData Iterator",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "FormData Iterator",
    FormDataIterator,
    FormDataIter,
    FORM_DATA_ITER_PROTO,
    Some(ClassCtorDef::new(js_fd_iterator_ctor, 0, false)),
    extends: || JS_CLASS_ITERATOR
);

fn create_fd_iterator(
    ctx: &mut ScopedContext,
    fd_val: JSValue,
    kind: JSIteratorKindEnum,
) -> JSResult {
    // Validate the receiver before building an iterator over it.
    get_fd(ctx, &fd_val)?;
    let obj = fd_val.as_object().ok_or(-1)?;
    let inst =
        FormDataIterator::new_instance(ctx, JSValue::UNDEFINED, FormDataIter::new(obj, kind))?;
    Ok(inst.into())
}

fn js_fd_keys(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    create_fd_iterator(ctx, cc.this(), JSIteratorKindEnum::JS_ITERATOR_KIND_KEY)
}

fn js_fd_values(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    create_fd_iterator(ctx, cc.this(), JSIteratorKindEnum::JS_ITERATOR_KIND_VALUE)
}

fn js_fd_entries(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    create_fd_iterator(
        ctx,
        cc.this(),
        JSIteratorKindEnum::JS_ITERATOR_KIND_KEY_AND_VALUE,
    )
}

// ---------------------------------------------------------------------------
// Body serialization (multipart/form-data)
// ---------------------------------------------------------------------------

/// Fixed multipart boundary. The spec only requires that the boundary not
/// appear in the payload; a constant keeps serialization deterministic (and
/// testable) since we do not escape occurrences in content.
// Boundary is restricted to lowercase letters + digits so that, e.g., a
// caller-supplied body whose bytes have been case-folded (WPT
// fetch/api/body/formdata.any.js lowercases the whole body) still matches the
// `boundary` parameter declared in the Content-Type header.
const MULTIPART_BOUNDARY: &str = "----aikeformboundary7ma4ywxktrzu0gw";

/// `Content-Type` a `FormData` body contributes when used as a `BodyInit`.
///
/// An empty `FormData` still carries the multipart content type so that the
/// (empty) body remains parseable back into an empty `FormData`; only its byte
/// payload is empty.
pub(crate) fn form_data_content_type(val: &JSValue) -> Option<String> {
    JSFormData::payload_of(val)
        .map(|_| format!("multipart/form-data; boundary={MULTIPART_BOUNDARY}"))
}

/// Escape a field/file name for a `Content-Disposition` header per the
/// "multipart/form-data encoding algorithm" (escape CR, LF and `"`).
fn escape_disposition(name: &str) -> String {
    name.replace('\r', "%0D")
        .replace('\n', "%0A")
        .replace('"', "%22")
}

/// Serialize a `FormData` into a `multipart/form-data` byte body matching
/// `form_data_content_type`'s boundary. Returns `None` for non-FormData values.
///
/// An empty `FormData` (empty entry list) produces an empty body: a trailing
/// boundary alone (`--boundary--\r\n`) would be non-empty text when the body is
/// consumed as text, but the Fetch tests expect an empty `FormData` to yield an
/// empty string. The multipart `Content-Type` is still set (see
/// `form_data_content_type`), so the body remains parseable back into an empty
/// `FormData`.
pub(crate) fn form_data_to_bytes(val: &JSValue) -> Option<Vec<u8>> {
    let fd = JSFormData::payload_of(val)?;
    let entries = fd.entries.borrow();
    let mut out = Vec::new();

    if entries.is_empty() {
        return Some(out);
    }

    for e in entries.iter() {
        out.extend_from_slice(format!("--{MULTIPART_BOUNDARY}\r\n").as_bytes());
        match &e.value {
            EntryValue::Str(s) => {
                out.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{}\"\r\n\r\n",
                        escape_disposition(&e.name)
                    )
                    .as_bytes(),
                );
                out.extend_from_slice(s.as_bytes());
            }
            EntryValue::Blob { value, filename } => {
                let value = value.get();
                let ctype = blob_type_of(&value).filter(|t| !t.is_empty());
                out.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\nContent-Type: {}\r\n\r\n",
                        escape_disposition(&e.name),
                        escape_disposition(filename),
                        ctype.as_deref().unwrap_or("application/octet-stream")
                    )
                    .as_bytes(),
                );
                if let Some(bytes) = blob_bytes_of(&value) {
                    out.extend_from_slice(&bytes);
                }
            }
        }
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("--{MULTIPART_BOUNDARY}--\r\n").as_bytes());
    Some(out)
}

/// Parse a `multipart/form-data` body into a new `FormData`, used by
/// `Response.formData()` / `Request.formData()`. `boundary` comes from the
/// `Content-Type` header. Returns `None` when the body is malformed.
pub(crate) fn form_data_from_multipart(
    ctx: &mut ScopedContext,
    body: &[u8],
    boundary: &str,
) -> Result<Option<JSValue>, i32> {
    let delim = format!("--{boundary}");
    let mut entries: Vec<FormDataEntry> = Vec::new();

    // An empty body with a multipart content type (e.g. an empty `FormData`)
    // parses to an empty `FormData`, not a parse error.
    if body.is_empty() {
        let inst = JSFormData::new_instance(
            ctx,
            JSValue::UNDEFINED,
            FormDataPayload {
                entries: RefCell::new(WriteBarrierVec::from_vec(entries)),
            },
        )?;
        return Ok(Some(inst.into()));
    }

    // Split on the boundary delimiter; the first chunk is the preamble and the
    // last one is the closing "--" epilogue, both ignored.
    let parts = split_on(body, delim.as_bytes());
    // A well-formed multipart body contains at least the closing delimiter.
    // A non-empty body without one is malformed (WPT expects TypeError).
    if parts.len() < 2 {
        return Ok(None);
    }
    for part in parts.iter().skip(1) {
        // A closing delimiter ends the message.
        if part.starts_with(b"--") {
            break;
        }
        // Each part starts with CRLF after the delimiter, then headers,
        // a blank line, the content, and a trailing CRLF before the next one.
        let part = part.strip_prefix(b"\r\n").unwrap_or(part);
        let Some(sep) = find_sub(part, b"\r\n\r\n") else {
            return Ok(None);
        };
        let (head, rest) = part.split_at(sep);
        let content = &rest[4..];
        let content = content.strip_suffix(b"\r\n").unwrap_or(content);

        let head = String::from_utf8_lossy(head);
        let mut name = None;
        let mut filename = None;
        let mut ctype = String::new();
        for line in head.split("\r\n") {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            match key.trim().to_ascii_lowercase().as_str() {
                "content-disposition" => {
                    name = param_value(value, "name");
                    filename = param_value(value, "filename");
                }
                "content-type" => ctype = value.trim().to_string(),
                _ => {}
            }
        }
        let Some(name) = name else {
            return Ok(None);
        };

        let entry = match filename {
            Some(filename) => EntryValue::Blob {
                value: WriteBarrier::new(blob_from_bytes(ctx, content.into(), ctype)?),
                filename,
            },
            None => EntryValue::Str(String::from_utf8_lossy(content).into_owned()),
        };
        entries.push(FormDataEntry { name, value: entry });
    }

    let inst = JSFormData::new_instance(
        ctx,
        JSValue::UNDEFINED,
        FormDataPayload {
            entries: RefCell::new(WriteBarrierVec::from_vec(entries)),
        },
    )?;
    Ok(Some(inst.into()))
}

/// Parse a body into a `FormData` according to `content_type`, implementing
/// the Fetch "consume body as FormData" steps. Returns `None` when the type is
/// unsupported or the payload is malformed (the caller throws `TypeError`).
pub(crate) fn form_data_parse(
    ctx: &mut ScopedContext,
    body: &[u8],
    content_type: &str,
) -> Result<Option<JSValue>, i32> {
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    match mime.as_str() {
        "multipart/form-data" => {
            let boundary = match param_unquoted(content_type, "boundary") {
                Some(b) => b,
                // When the `boundary` parameter is absent (e.g. the body was
                // round-tripped through a `Blob`, whose MIME type keeps only the
                // essence), recover it from the body's first `--{boundary}` line.
                None => match boundary_from_body(body) {
                    Some(b) => b,
                    None => return Ok(None),
                },
            };
            form_data_from_multipart(ctx, body, &boundary)
        }
        "application/x-www-form-urlencoded" => {
            let text = String::from_utf8_lossy(body);
            let entries = urlencoded_entries(&text);
            let inst = JSFormData::new_instance(
                ctx,
                JSValue::UNDEFINED,
                FormDataPayload {
                    entries: RefCell::new(WriteBarrierVec::from_vec(entries)),
                },
            )?;
            Ok(Some(inst.into()))
        }
        _ => Ok(None),
    }
}

/// Decode `application/x-www-form-urlencoded` text into string entries.
fn urlencoded_entries(text: &str) -> Vec<FormDataEntry> {
    text.split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            FormDataEntry {
                name: percent_decode_plus(k),
                value: EntryValue::Str(percent_decode_plus(v)),
            }
        })
        .collect()
}

/// Percent-decode a urlencoded component, treating `+` as a space.
fn percent_decode_plus(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 2;
                    }
                    // Invalid escape: keep the '%' literally.
                    Err(_) => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Recover the multipart boundary from the body's first delimiter line when
/// the `Content-Type` lacks an explicit `boundary` parameter. A delimiter line
/// is `--{boundary}\r\n` (an optional leading CRLF preamble is skipped).
fn boundary_from_body(body: &[u8]) -> Option<String> {
    // Skip an optional leading CRLF (multipart preamble).
    let body = body.strip_prefix(b"\r\n").unwrap_or(body);
    let line_end = find_sub(body, b"\r\n")?;
    let line = &body[..line_end];
    let line = line.strip_prefix(b"--")?;
    if line.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(line).into_owned())
}

/// Extract a header parameter that may or may not be quoted
/// (e.g. `boundary=abc` and `boundary="abc"` are both valid).
fn param_unquoted(header: &str, key: &str) -> Option<String> {
    header.split(';').skip(1).find_map(|part| {
        let (k, v) = part.split_once('=')?;
        (k.trim().eq_ignore_ascii_case(key)).then(|| v.trim().trim_matches('"').to_string())
    })
}

/// Extract a quoted `key="value"` parameter from a header value.
fn param_value(header: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = header.find(&needle)? + needle.len();
    let end = start + header[start..].find('"')?;
    Some(header[start..end].to_string())
}

/// Find the first occurrence of `needle` in `hay`.
fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Split `hay` on every occurrence of `sep` (like `str::split`).
fn split_on<'a>(hay: &'a [u8], sep: &[u8]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut rest = hay;
    while let Some(pos) = find_sub(rest, sep) {
        out.push(&rest[..pos]);
        rest = &rest[pos + sep.len()..];
    }
    out.push(rest);
    out
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

const FORM_DATA_PROTO: &[FieldDef] = &[
    FieldDef::FUNC_ENUM("append", 2, js_fd_append, 0),
    FieldDef::FUNC_ENUM("delete", 1, js_fd_delete, 0),
    FieldDef::FUNC_ENUM("get", 1, js_fd_get, 0),
    FieldDef::FUNC_ENUM("getAll", 1, js_fd_get_all, 0),
    FieldDef::FUNC_ENUM("has", 1, js_fd_has, 0),
    FieldDef::FUNC_ENUM("set", 2, js_fd_set, 0),
    FieldDef::FUNC_ENUM("forEach", 1, js_fd_for_each, 0),
    FieldDef::FUNC_ENUM("keys", 0, js_fd_keys, 0),
    FieldDef::FUNC_ENUM("values", 0, js_fd_values, 0),
    FieldDef::FUNC_ENUM("entries", 0, js_fd_entries, 0),
    // WebIDL §3.7.9: `%Symbol.iterator%` is the *same function object* as
    // `entries`, but is created with `DefineMethodProperty(..., false)` so it
    // stays non-enumerable (unlike `entries`).
    FieldDef::ALIAS("[Symbol.iterator]", "entries"),
    // WebIDL class string (`Object.prototype.toString` -> "[object FormData]").
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "FormData",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "FormData",
    JSFormData,
    FormDataPayload,
    FORM_DATA_PROTO,
    Some(ClassCtorDef::new(js_fd_constructor, 0, true).expose_to_global())
);
