// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

use std::{cell::RefCell, rc::Rc};

use zuqe::{
    Array, Atom, CallContext, ClassCtorDef, FieldDef, JS_CLASS_ITERATOR, JS_PROP_C_W_E,
    JSIteratorKindEnum, JSResult, JSValue, Object, ScopedContext, def_native_object,
    gc_lite::GcTrace,
};

/// Case-insensitive header storage. Names keep their original casing; lookups
/// are case-insensitive per the Fetch/HTTP spec.
///
/// `Set-Cookie` values are kept in the same list (as separate, non-merged
/// entries) because they MUST NOT be comma-joined per the Fetch/HTTP spec.
///
/// The list is kept **sorted by lowercased header name** at all times (stable
/// sort: repeated `Set-Cookie` values keep their insertion order). This matches
/// the WHATWG Headers iteration/serialization order, and lets the live iterator
/// walk a single sorted `Vec` with a plain advancing index — deletions shift
/// later entries left (skipping one), appends at the sorted position either
/// re-yield a shifted entry or get reached at the end.
#[derive(Clone, Default)]
pub(crate) struct HeaderList {
    list: Vec<(String, String)>,
    /// Original casing of the first `append`/`set` for each lowercased name.
    /// The Fetch spec stores lowercase names, but browsers send the casing the
    /// author used on the wire (WPT `request-headers-case`).
    wire_names: std::collections::HashMap<String, String>,
}

impl HeaderList {
    pub(crate) fn new() -> Self {
        HeaderList {
            list: Vec::new(),
            wire_names: std::collections::HashMap::new(),
        }
    }

    pub(crate) fn from_vec(v: Vec<(String, String)>) -> Self {
        let mut h = HeaderList::new();
        for (name, value) in v {
            h.append(&name, &value);
        }
        h
    }

    pub(crate) fn len(&self) -> usize {
        self.list.len()
    }

    /// Clone the entry at `i` (used by the live iterator).
    pub(crate) fn get_at(&self, i: usize) -> (String, String) {
        self.list[i].clone()
    }

    /// First index at which a new entry with `name` should be inserted to keep
    /// the list sorted by lowercased name. For duplicate names (e.g. repeated
    /// `Set-Cookie`), this lands *after* the existing same-name block, so the
    /// duplicates stay contiguous and insertion-ordered.
    fn sorted_insert_index(&self, name: &str) -> usize {
        let lower = name.to_lowercase();
        self.list
            .iter()
            .position(|(k, _)| k.to_lowercase() > lower)
            .unwrap_or(self.list.len())
    }

    /// Append a value, combining with any existing same-name (case-insensitive)
    /// header as a comma-separated list. `Set-Cookie` is an exception — values
    /// are stored individually (never comma-merged) and kept sorted in place.
    pub(crate) fn append(&mut self, name: &str, value: &str) {
        // Header names are normalized to lowercase on storage (Fetch spec).
        let key = name.to_lowercase();
        self.wire_names
            .entry(key.clone())
            .or_insert_with(|| name.to_string());
        let value = normalize_header_value(value).to_string();
        if let Some(pos) = self.list.iter().position(|(k, _)| *k == key) {
            if key == "set-cookie" {
                // `Set-Cookie` never comma-merges; insert a new separate entry
                // right after the existing `Set-Cookie` block.
                self.list
                    .insert(self.sorted_insert_index(&key), (key, value));
            } else {
                self.list[pos].1.push_str(", ");
                self.list[pos].1.push_str(&value);
            }
        } else {
            let idx = self.sorted_insert_index(&key);
            self.list.insert(idx, (key, value));
        }
    }

    /// Set a value, replacing any existing same-name header.
    /// For `Set-Cookie`, replaces all existing values with a single entry.
    pub(crate) fn set(&mut self, name: &str, value: &str) {
        let key = name.to_lowercase();
        let lower = key.clone();
        self.wire_names.insert(key.clone(), name.to_string());
        let value = normalize_header_value(value).to_string();
        self.list.retain(|(k, _)| *k != lower);
        let idx = self.sorted_insert_index(&key);
        self.list.insert(idx, (key, value));
    }

    pub(crate) fn delete(&mut self, name: &str) {
        let lower = name.to_lowercase();
        self.wire_names.remove(&lower);
        self.list.retain(|(k, _)| k.to_lowercase() != lower);
    }

    /// Original casing for a stored (lowercased) header name, if one was
    /// recorded. Used only when serializing onto the wire.
    pub(crate) fn wire_name(&self, lower: &str) -> Option<&String> {
        self.wire_names.get(lower)
    }

    /// Filter entries per the Fetch spec's request-header guard:
    /// - normal request: drop forbidden request-header names;
    /// - `no-cors` request: keep only CORS-safelisted request headers.
    ///
    /// Used by the `Request` constructor to filter headers given via init or an
    /// input Request (WPT request-headers).
    pub(crate) fn filter_for_request_mode(&mut self, no_cors: bool) {
        self.list.retain(|(name, value)| {
            if no_cors {
                is_cors_safelisted(name, value)
            } else {
                !is_forbidden_request_header(name, value)
            }
        });
    }

    pub(crate) fn get(&self, name: &str) -> Option<String> {
        let lower = name.to_lowercase();
        let values: Vec<&str> = self
            .list
            .iter()
            .filter(|(k, _)| lower.eq(k))
            .map(|(_, v)| v.as_str())
            .collect();

        if values.is_empty() {
            return None;
        }
        // Comma-join all values (this also gives `Set-Cookie` its combined
        // form, per the Fetch spec `get()` semantics).
        Some(values.join(", "))
    }

    pub(crate) fn has(&self, name: &str) -> bool {
        if name.eq_ignore_ascii_case("set-cookie") {
            return self
                .list
                .iter()
                .any(|(k, _)| k.to_lowercase() == "set-cookie");
        }
        let lower = name.to_lowercase();
        self.list.iter().any(|(k, _)| k.to_lowercase() == lower)
    }

    /// Entries as exposed to JS: sorted by lowercased name. The list is already
    /// kept sorted, so this is a straight clone.
    pub(crate) fn entries(&self) -> Vec<(String, String)> {
        self.list.clone()
    }

    /// Get all values for a given header name (case-insensitive).
    pub(crate) fn get_all(&self, name: &str) -> Vec<String> {
        let lower = name.to_lowercase();
        self.list
            .iter()
            .filter(|(k, _)| k.to_lowercase() == lower)
            .map(|(_, v)| v.clone())
            .collect()
    }

    pub(crate) fn to_vec(&self) -> Vec<(String, String)> {
        self.list.clone()
    }
}

/// WHATWG valid header name = 1+ `tchar` (token chars).
fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            matches!(b,
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9'
            | b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*'
            | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~')
        })
}

/// WHATWG valid header value at the *Headers* layer: the value must be a
/// sequence of code points whose code units are all ≤ U+00FF (i.e. it can be
/// represented as a byte sequence). Code points above U+00FF (e.g. "\uFFFF")
/// are rejected here.
fn is_valid_header_value(value: &str) -> bool {
    value.chars().all(|c| (c as u32) <= 0xFF)
}

/// WHATWG "normalize a header value": strip leading/trailing HTTP whitespace
/// (only SP, TAB, CR, LF — *not* arbitrary Unicode whitespace like `str::trim`).
/// This is the Fetch normalization applied both at Headers storage time and
/// again when values hit the wire; other C0 controls are left intact (the
/// transport/fetch layer rejects the forbidden NUL/LF/CR ones).
pub(super) fn normalize_header_value(value: &str) -> &str {
    value.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'))
}

fn check_header_name(ctx: &mut ScopedContext, name: &str) -> JSResult {
    if !is_valid_header_name(name) {
        return Err(ctx.throw_type_error(&format!("Invalid header name: {}", name)));
    }
    Ok(JSValue::UNDEFINED)
}

fn check_header_value(ctx: &mut ScopedContext, value: &str) -> JSResult {
    // A value is normalized (leading/trailing HTTP whitespace stripped) before
    // it is validated; NUL/LF/CR anywhere in the *normalized* value are a
    // TypeError (WPT header-values: only 0x00, 0x0A, 0x0D are forbidden, all
    // other bytes 0x01..0xFF are valid).
    let norm = normalize_header_value(value);
    if norm.contains('\u{0000}') || norm.contains('\u{000a}') || norm.contains('\u{000d}') {
        return Err(ctx.throw_type_error("Invalid header value"));
    }
    if !is_valid_header_value(norm) {
        return Err(ctx.throw_type_error("Invalid header value"));
    }
    Ok(JSValue::UNDEFINED)
}

/// Validate a header list per the Fetch spec before a `Request`/`fetch` is
/// built. Must be called on the JS thread so failures reject with a `TypeError`
/// (not an async transport error):
/// - header names must be valid `tchar` sequences;
/// - header values must not contain NUL/LF/CR (RFC 7230 / Fetch) after
///   leading/trailing HTTP whitespace is stripped (the engine sends the value
///   literally, so control chars other than those three are left to the
///   transport layer).
pub(crate) fn validate_header_list_for_fetch(
    ctx: &mut ScopedContext,
    list: &HeaderList,
) -> JSResult {
    for (name, value) in &list.list {
        check_header_name(ctx, name)?;
        let norm = normalize_header_value(value);
        if norm.contains('\u{0000}') || norm.contains('\u{000a}') || norm.contains('\u{000d}') {
            return Err(ctx.throw_type_error(&format!(
                "Invalid header value: {} contains forbidden character",
                name
            )));
        }
        if !is_valid_header_value(norm) {
            return Err(ctx.throw_type_error("Invalid header value"));
        }
    }
    Ok(JSValue::UNDEFINED)
}

/// `Set-Cookie` values are normalized then validated at *storage* time: a value
/// containing a NUL/LF/CR (the only bytes forbidden in a cookie-pair) must throw
/// a `TypeError` immediately (WPT `header-setcookie` expects this on
/// construction, `append`, and `set`).
fn check_set_cookie_value(ctx: &mut ScopedContext, value: &str) -> JSResult {
    let norm = normalize_header_value(value);
    if norm.contains('\u{0000}') || norm.contains('\u{000a}') || norm.contains('\u{000d}') {
        return Err(ctx.throw_type_error("Invalid Set-Cookie value: contains forbidden character"));
    }
    Ok(JSValue::UNDEFINED)
}

/// Fetch spec "headers guard": controls whether/how mutation is allowed.
/// The `request` guard only adds forbidden-header filtering, which we do not
/// enforce, so it is not represented here.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Guard {
    None,
    /// Headers of an opaque/error `Response`: any mutation throws `TypeError`.
    Immutable,
    /// Headers of a normal `Response`: mutable, but forbidden response headers
    /// (`Set-Cookie`, `Set-Cookie2`) are silently dropped.
    Response,
    /// Headers of a `mode: "no-cors"` `Request`: mutations that are not
    /// CORS-safelisted are silently ignored (no error).
    RequestNoCors,
    /// Headers of a normal `Request`: mutable, but forbidden request-header
    /// names (`Host`, `Connection`, `Accept-Encoding`, ...) are silently
    /// dropped.
    Request,
}

/// WHATWG "forbidden request-header name": cannot be set through a Request's
/// headers object, silently dropped under the `request` guard.
fn is_forbidden_request_header_name(name: &str) -> bool {
    const FORBIDDEN: &[&str] = &[
        "accept-charset",
        "accept-encoding",
        "access-control-request-headers",
        "access-control-request-method",
        "connection",
        "content-length",
        "cookie",
        "cookie2",
        "date",
        "dnt",
        "expect",
        "host",
        "keep-alive",
        "origin",
        "referer",
        "set-cookie",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "via",
    ];
    let lower = name.to_lowercase();
    if FORBIDDEN.contains(&lower.as_str()) {
        return true;
    }
    if lower.starts_with("proxy-") || lower.starts_with("sec-") {
        return true;
    }
    // The conditional method-override headers are only forbidden when their
    // value resolves to a forbidden method; that check needs the value, so it
    // is done in the set/append path.
    false
}

/// WHATWG "forbidden request-header name" including the conditional
/// method-override headers (`x-http-method`, `x-http-method-override`,
/// `x-method-override`), which are forbidden when their value resolves to a
/// forbidden method (`CONNECT`/`TRACE`/`TRACK`, byte-case-insensitive, after
/// "get, decode, and split").
fn is_forbidden_request_header(name: &str, value: &str) -> bool {
    if is_forbidden_request_header_name(name) {
        return true;
    }
    let lower = name.to_lowercase();
    if matches!(
        lower.as_str(),
        "x-http-method" | "x-http-method-override" | "x-method-override"
    ) {
        return split_method_override(value).iter().any(|m| {
            matches!(
                m.to_ascii_lowercase().as_str(),
                "connect" | "trace" | "track"
            )
        });
    }
    false
}

/// "Get, decode, and split" for a header value: split on commas, keeping quoted
/// strings intact and trimming each item.
fn split_method_override(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut temp = String::new();
    let mut in_quote = false;
    for c in value.chars() {
        if c == '"' {
            in_quote = !in_quote;
            temp.push(c);
            continue;
        }
        if c == ',' && !in_quote {
            out.push(temp.trim().to_string());
            temp.clear();
            continue;
        }
        temp.push(c);
    }
    out.push(temp.trim().to_string());
    out
}

/// WHATWG "CORS-safelisted request-header". Only these may be set on a
/// `no-cors` request; everything else is dropped.
pub(crate) fn is_cors_safelisted(name: &str, value: &str) -> bool {
    // Values over 128 bytes are never safelisted, whatever the name.
    if value.len() > 128 {
        return false;
    }
    let lower = name.to_lowercase();
    match lower.as_str() {
        "accept" => !value.bytes().any(is_cors_unsafe_byte),
        "accept-language" | "content-language" => value.bytes().all(|b| {
            matches!(b, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
                | b' ' | b'*' | b',' | b'-' | b'.' | b';' | b'=')
        }),
        "content-type" => {
            if value.bytes().any(is_cors_unsafe_byte) {
                return false;
            }
            // Essence (type/subtype without parameters) must be one of three.
            let essence = value.split(';').next().unwrap_or("").trim().to_lowercase();
            matches!(
                essence.as_str(),
                "application/x-www-form-urlencoded" | "multipart/form-data" | "text/plain"
            )
        }
        _ => false,
    }
}

/// WHATWG "CORS-unsafe request-header byte".
fn is_cors_unsafe_byte(b: u8) -> bool {
    b < 0x20 && b != b'\t'
        || matches!(
            b,
            b'"' | b'('
                | b')'
                | b':'
                | b'<'
                | b'>'
                | b'?'
                | b'@'
                | b'['
                | b'\\'
                | b']'
                | b'{'
                | b'}'
                | 0x7F
        )
}

// No JS GC nodes in this payload.
#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct HeadersPayload {
    /// Shared header storage. A `Request`/`Response` and its exposed `Headers`
    /// object reference the same `Rc`, so mutations through either are visible
    /// to both (per the Fetch spec, `request.headers` is the live header set).
    #[gc(skip)]
    pub(crate) list: Rc<RefCell<HeaderList>>,
    #[gc(skip)]
    pub(crate) guard: Guard,
}

impl HeadersPayload {
    /// A mutable, standalone header set (`new Headers()`).
    pub(crate) fn new(list: HeaderList) -> Self {
        HeadersPayload {
            list: Rc::new(RefCell::new(list)),
            guard: Guard::None,
        }
    }

    /// Wrap an existing shared header list. `Request.headers` / `Response.headers`
    /// reference the payload's live `Rc`, so mutations through the exposed
    /// `Headers` object are visible to body consumers (Fetch spec [SameObject]).
    pub(crate) fn from_shared(list: Rc<RefCell<HeaderList>>, guard: Guard) -> Self {
        HeadersPayload { list, guard }
    }
}

/// WHATWG "forbidden response-header name": cannot be set through a Response's
/// headers, silently ignored under the `response` guard.
fn is_forbidden_response_header(name: &str) -> bool {
    let lower = name.to_lowercase();
    matches!(lower.as_str(), "set-cookie" | "set-cookie2")
}

/// Reject mutation on an immutable (response) header set, per the Fetch spec.
fn check_mutable(ctx: &mut ScopedContext, guard: Guard) -> JSResult {
    if guard == Guard::Immutable {
        return Err(ctx.throw_type_error("Headers are immutable"));
    }
    Ok(JSValue::UNDEFINED)
}

fn get_headers<'a>(ctx: &mut ScopedContext, val: &'a JSValue) -> Result<&'a HeadersPayload, i32> {
    JSHeaders::payload_of(val).ok_or_else(|| ctx.throw_type_error("not a Headers instance"))
}

fn get_headers_mut<'a>(
    ctx: &mut ScopedContext,
    val: &'a mut JSValue,
) -> Result<&'a mut HeadersPayload, i32> {
    JSHeaders::payload_mut_of(val).ok_or_else(|| ctx.throw_type_error("not a Headers instance"))
}

/// Build a `HeaderList` from a JS init. WebIDL `HeadersInit` is one of:
/// - `undefined` / omitted → empty list;
/// - `null` → type error;
/// - any value exposing `[Symbol.iterator]` → a *sequence* of `[name, value]`
///   pairs (this also covers `Headers` instances and monkeypatched iterators);
/// - any other object → a *record* (own enumerable string/integer keys).
pub(crate) fn header_list_from_js(
    ctx: &mut ScopedContext,
    val: &mut JSValue,
) -> Result<HeaderList, i32> {
    let mut list = HeaderList::new();
    // An omitted/`undefined` init means "no headers".
    if val.is_undefined() {
        return Ok(list);
    }
    if val.is_null() {
        return Err(ctx.throw_type_error("Headers init must not be null"));
    }
    let Some(mut obj) = val.as_object() else {
        return Err(ctx.throw_type_error(
            "Headers init must be a record, a sequence of name/value pairs, a Headers object, or undefined",
        ));
    };

    // Sequence path: anything with a callable [Symbol.iterator].
    let iter_method = obj.get_property(ctx, Atom::CONST_Symbol_iterator)?;
    if iter_method.is_callable() {
        let iter_fn = iter_method.ensure_callable(ctx)?;
        let iterator = iter_fn.call(ctx, obj.into(), &[])?;
        loop {
            let next_fn = iterator.get_property_str(ctx, "next")?;
            if !next_fn.is_callable() {
                return Err(ctx.throw_type_error("Header init iterator has no next()"));
            }
            let next = next_fn.ensure_callable(ctx)?;
            let result = next.call(ctx, iterator, &[])?;
            if result.get_property_str(ctx, "done")?.to_bool()? {
                break;
            }
            let pair = result.get_property_str(ctx, "value")?;
            if !pair.is_array(ctx)? {
                return Err(ctx.throw_type_error("Each header entry must be a [name, value] pair"));
            }
            // A header entry must be a `[name, value]` tuple of exactly two
            // items. Fewer (e.g. `["name"]`) or more (e.g. `["a", "b", "c"]`)
            // elements are rejected per the Fetch spec (WPT headers-errors).
            let pair_len = pair
                .get_property_str(ctx, "length")?
                .to_number(ctx)?
                .to_i32();
            if pair_len != 2 {
                return Err(ctx.throw_type_error(
                    "Each header entry must be a [name, value] pair of exactly two elements",
                ));
            }
            let name = pair
                .get_property_str(ctx, "0")?
                .to_string(ctx)?
                .content()
                .encode_utf8(false)
                .to_string();
            let value_v = pair.get_property_str(ctx, "1")?;
            // Sequence values are coerced to ByteString like record values
            // (null/undefined/numbers become "null"/"undefined"/"1"); they are
            // not rejected.
            let value = value_v
                .to_string(ctx)?
                .content()
                .encode_utf8(false)
                .to_string();
            check_header_name(ctx, &name)?;
            check_header_value(ctx, &value)?;
            if name.eq_ignore_ascii_case("set-cookie") {
                check_set_cookie_value(ctx, &value)?;
            }
            list.append(&name, &value);
        }
        return Ok(list);
    }

    // Record path — mirrors the WHATWG `es-to-record` algorithm exactly:
    //   4. [[OwnPropertyKeys]]  → `ownKeys` trap   (get_own_property_names)
    //   5. for each key:
    //     5.1 [[GetOwnProperty]] → `getOwnPropertyDescriptor` trap (get_own_property)
    //         if absent or non-enumerable → skip
    //         convert key to ByteString (header name): a Symbol key cannot be
    //         converted → TypeError; an invalid name → TypeError
    //     5.2 [[Get]]            → `get` trap (get_property)
    //         convert value to ByteString: invalid value → TypeError
    // We include Symbol keys in the enumeration (JS_GPN_SYMBOL_MASK) so that the
    // spec's mandatory Symbol→ByteString conversion failure is observed, and we
    // deliberately omit JS_GPN_ENUM_ONLY so the engine doesn't call
    // `getOwnPropertyDescriptor` a second time (which would double-fire the trap).
    let pks =
        obj.get_own_property_names(ctx, zuqe::JS_GPN_STR_OR_INT_MASK | zuqe::JS_GPN_SYMBOL_MASK)?;
    for pk in pks.iter() {
        // [[GetOwnProperty]] — the `getOwnPropertyDescriptor` trap (step 5.1).
        let Some(desc) = obj.get_own_property(ctx, pk.atom)? else {
            continue;
        };
        if desc.flags & zuqe::JS_PROP_ENUMERABLE == 0 {
            continue; // skip non-enumerable own properties
        }
        // Convert the *key* to a ByteString (header name) before the [[Get]].
        // A Symbol key cannot be stringified → TypeError (per es-to-record).
        let key_atom_val = pk.atom.to_value(ctx)?;
        if key_atom_val.is_symbol() {
            return Err(ctx.throw_type_error("Header name must not be a symbol"));
        }
        let key = key_atom_val
            .to_string(ctx)?
            .content()
            .encode_utf8(false)
            .to_string();
        check_header_name(ctx, &key)?;
        // [[Get]] — the `get` trap (step 5.2).
        let value_v = obj.get_property(ctx, pk.atom)?;
        // Record values are coerced to ByteString; `null`/`undefined`/`1` become
        // "null"/"undefined"/"1" rather than being skipped.
        let value = value_v
            .to_string(ctx)?
            .content()
            .encode_utf8(false)
            .to_string();
        check_header_value(ctx, &value)?;
        if key.eq_ignore_ascii_case("set-cookie") {
            check_set_cookie_value(ctx, &value)?;
        }
        list.append(&key, &value);
    }
    Ok(list)
}

fn js_headers_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let new_target = cc.this();
    let list = if cc.length() > 0 {
        let mut arg0 = cc.arg(0);
        header_list_from_js(ctx, &mut arg0)?
    } else {
        HeaderList::new()
    };
    JSHeaders::new_instance(ctx, new_target, HeadersPayload::new(list)).map(JSValue::from)
}

fn js_headers_append(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut this = cc.this();
    let guard = get_headers(ctx, &this)?.guard;
    check_mutable(ctx, guard)?;
    let h = get_headers_mut(ctx, &mut this)?;
    let name = cc
        .arg(0)
        .to_string(ctx)?
        .content()
        .encode_utf8(false)
        .to_string();
    let value = cc
        .arg(1)
        .to_string(ctx)?
        .content()
        .encode_utf8(false)
        .to_string();
    check_header_name(ctx, &name)?;
    check_header_value(ctx, &value)?;
    // `Set-Cookie` values are validated at storage time (NUL/LF/CR are rejected).
    if name.eq_ignore_ascii_case("set-cookie") {
        check_set_cookie_value(ctx, &value)?;
    }
    // response guard: forbidden response headers are silently dropped.
    if guard == Guard::Response && is_forbidden_response_header(&name) {
        return Ok(JSValue::UNDEFINED);
    }
    // request guard: forbidden request-header names are silently dropped.
    if guard == Guard::Request && is_forbidden_request_header(&name, &value) {
        return Ok(JSValue::UNDEFINED);
    }
    // no-cors guard: the safelist test applies to the *combined* value that
    // append would produce, not just the new one.
    if guard == Guard::RequestNoCors {
        let combined = match h.list.borrow().get(&name) {
            Some(existing) => format!("{existing}, {value}"),
            None => value.to_string(),
        };
        if !is_cors_safelisted(&name, &combined) {
            return Ok(JSValue::UNDEFINED);
        }
    }
    h.list.borrow_mut().append(&name, &value);
    Ok(JSValue::UNDEFINED)
}

fn js_headers_delete(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut this = cc.this();
    let guard = get_headers(ctx, &this)?.guard;
    check_mutable(ctx, guard)?;
    let h = get_headers_mut(ctx, &mut this)?;
    let name = cc
        .arg(0)
        .to_string(ctx)?
        .content()
        .encode_utf8(false)
        .to_string();
    check_header_name(ctx, &name)?;
    // response guard: forbidden response headers cannot be removed either.
    if guard == Guard::Response && is_forbidden_response_header(&name) {
        return Ok(JSValue::UNDEFINED);
    }
    // request guard: forbidden request-header names cannot be removed either.
    if guard == Guard::Request && is_forbidden_request_header_name(&name) {
        return Ok(JSValue::UNDEFINED);
    }
    h.list.borrow_mut().delete(&name);
    Ok(JSValue::UNDEFINED)
}

fn js_headers_get(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let h = get_headers(ctx, &this)?;

    let name = cc
        .arg(0)
        .to_string(ctx)?
        .content()
        .encode_utf8(false)
        .to_string();
    check_header_name(ctx, &name)?;

    match h.list.borrow().get(&name) {
        Some(v) => ctx
            .create_string_from_utf8(v.into_bytes())
            .map(JSValue::make_string),
        None => Ok(JSValue::NULL),
    }
}

fn js_headers_has(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let h = get_headers(ctx, &this)?;
    let name = cc
        .arg(0)
        .to_string(ctx)?
        .content()
        .encode_utf8(false)
        .to_string();
    check_header_name(ctx, &name)?;
    Ok(JSValue::from(h.list.borrow().has(&name)))
}

fn js_headers_set(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut this = cc.this();
    let guard = get_headers(ctx, &this)?.guard;
    check_mutable(ctx, guard)?;
    let h = get_headers_mut(ctx, &mut this)?;
    let name = cc
        .arg(0)
        .to_string(ctx)?
        .content()
        .encode_utf8(false)
        .to_string();
    let value = cc
        .arg(1)
        .to_string(ctx)?
        .content()
        .encode_utf8(false)
        .to_string();
    check_header_name(ctx, &name)?;
    check_header_value(ctx, &value)?;
    // `Set-Cookie` values are validated at storage time (NUL/LF/CR are rejected).
    if name.eq_ignore_ascii_case("set-cookie") {
        check_set_cookie_value(ctx, &value)?;
    }
    // response guard: forbidden response headers are silently dropped.
    if guard == Guard::Response && is_forbidden_response_header(&name) {
        return Ok(JSValue::UNDEFINED);
    }
    // request guard: forbidden request-header names are silently dropped.
    if guard == Guard::Request && is_forbidden_request_header(&name, &value) {
        return Ok(JSValue::UNDEFINED);
    }
    // no-cors guard: drop writes that are not CORS-safelisted.
    if guard == Guard::RequestNoCors && !is_cors_safelisted(&name, &value) {
        return Ok(JSValue::UNDEFINED);
    }
    h.list.borrow_mut().set(&name, &value);
    Ok(JSValue::UNDEFINED)
}

/// `keys()`/`values()`/`entries()` must return an iterator, not an array.
/// Live iterator over a `Headers` object's header list. Behaves like the
/// WHATWG header-list iterator: it holds a *live index* into the header list
/// (which is kept sorted). Each `next()` yields `list[index]` and advances the
/// index. Because the underlying list is shared and mutable, deletions shift
/// subsequent entries left (so one gets skipped) and insertions at the sorted
/// position may shift entries right (re-yielded) or append at the end
/// (reached) — matching the Fetch spec's iteration semantics.
#[derive(Debug, GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub struct HeaderListIter {
    pub obj: Object,
    pub index: u32,
    #[gc(skip)]
    pub kind: JSIteratorKindEnum,
}
impl HeaderListIter {
    pub fn new(obj: Object, kind: JSIteratorKindEnum) -> Self {
        HeaderListIter {
            obj,
            index: 0,
            kind,
        }
    }
}

const HEADER_ITER_PROTO: &[FieldDef] = &[
    // `next` must be enumerable (WPT `checkIteratorProperties` requires a writable
    // + configurable + enumerable `next`). We expose it as a normal method that
    // returns a `{value, done}` record; the engine's generic iteration path
    // (apply_next NotParsed) reads `.value`/`.done` from the result.
    FieldDef::FUNC_ENUM("next", 0, js_headers_iterator_next, 0),
    FieldDef::FUNC("[Symbol.iterator]", 0, js_headers_iterator_self, 0),
    // WebIDL: an iterator prototype object's class string is
    // `<interface> Iterator`.
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "Headers Iterator",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

fn js_headers_iterator_self(_: &mut ScopedContext, cc: CallContext) -> JSResult {
    Ok(cc.this())
}

fn js_headers_iterator_ctor(_: &mut ScopedContext, _cc: CallContext) -> JSResult {
    Ok(JSValue::UNDEFINED)
}

def_native_object!(
    "Headers Iterator",
    HeaderListIterator,
    HeaderListIter,
    HEADER_ITER_PROTO,
    Some(ClassCtorDef::new(js_headers_iterator_ctor, 0, false)),
    extends: || JS_CLASS_ITERATOR
);

/// Build a `{value, done}` iterator result object.
fn make_iter_result(ctx: &mut ScopedContext, value: JSValue, done: bool) -> JSResult {
    let mut obj = ctx.create_base_object()?;
    obj.define_property_value(ctx, Atom::CONST_value, value, JS_PROP_C_W_E)?;
    obj.define_property_value(ctx, Atom::CONST_done, JSValue::from(done), JS_PROP_C_W_E)?;
    Ok(obj.into())
}

fn js_headers_iterator_next(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let obj = this.as_object().ok_or(-1)?;
    let mut wrapper = HeaderListIterator(obj);
    let it = HeaderListIterator::payload_mut(&mut wrapper).ok_or(-1)?;
    let idx = it.index as usize;
    let kind = it.kind;
    let obj_val = JSValue::from(it.obj);
    let list = JSHeaders::payload_of(&obj_val).ok_or(-1)?.list.borrow();
    if idx >= list.len() {
        // Advance the live index past the end so subsequent calls stay done.
        it.index = list.len() as u32;
        return make_iter_result(ctx, JSValue::UNDEFINED, true);
    }

    let (name, value) = list.get_at(idx);
    let name_js = JSValue::make_string(ctx.create_string_from_utf8(name.into_bytes())?);
    let value_js = JSValue::make_string(ctx.create_string_from_utf8(value.into_bytes())?);

    // Advance the live index. Mutations/deletions to the underlying list between
    // calls are reflected automatically: deletions shift entries left (skipping
    // one), insertions at the sorted position may shift entries right (re-yield)
    // or append at the end (reached).
    it.index = (idx + 1) as u32;

    // Return the `{value, done}` record per the standard iterator protocol.
    match kind {
        JSIteratorKindEnum::JS_ITERATOR_KIND_KEY => make_iter_result(ctx, name_js, false),
        JSIteratorKindEnum::JS_ITERATOR_KIND_VALUE => make_iter_result(ctx, value_js, false),
        JSIteratorKindEnum::JS_ITERATOR_KIND_KEY_AND_VALUE => {
            let pair = Array::from_values(ctx, vec![name_js, value_js])?;
            make_iter_result(ctx, pair.into(), false)
        }
    }
}

fn create_headers_iterator(
    ctx: &mut ScopedContext,
    headers_val: JSValue,
    kind: JSIteratorKindEnum,
) -> JSResult {
    let obj = headers_val.as_object().ok_or(-1)?;
    let inst =
        HeaderListIterator::new_instance(ctx, JSValue::UNDEFINED, HeaderListIter::new(obj, kind))?;
    Ok(inst.into())
}

fn js_headers_keys(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    create_headers_iterator(ctx, this, JSIteratorKindEnum::JS_ITERATOR_KIND_KEY)
}

fn js_headers_values(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    create_headers_iterator(ctx, this, JSIteratorKindEnum::JS_ITERATOR_KIND_VALUE)
}

fn js_headers_entries(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    create_headers_iterator(
        ctx,
        this,
        JSIteratorKindEnum::JS_ITERATOR_KIND_KEY_AND_VALUE,
    )
}

fn js_headers_for_each(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let h = get_headers(ctx, &this)?;
    if cc.length() == 0 {
        return Err(ctx.throw_type_error("forEach requires a callback"));
    }
    let cb = cc.arg(0).ensure_callable(ctx)?;
    let this_arg = if cc.length() > 1 {
        cc.arg(1)
    } else {
        JSValue::UNDEFINED
    };
    // Snapshot the (name, value) pairs up front; deletions during iteration
    // simply skip the removed pair.
    let pairs: Vec<(String, String)> = h.list.borrow().list.clone();
    for (k, v) in pairs {
        let k_js = ctx.create_string_from_utf8(k.as_bytes().to_vec())?;
        let v_js = ctx.create_string_from_utf8(v.as_bytes().to_vec())?;
        cb.call(
            ctx,
            this_arg,
            &[JSValue::make_string(v_js), JSValue::make_string(k_js), this],
        )?;
    }
    Ok(JSValue::UNDEFINED)
}

/// `getSetCookie()` — returns all `Set-Cookie` header values as an array.
fn js_headers_get_set_cookie(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let h = get_headers(ctx, &this)?;
    let cookies: Vec<JSValue> = h
        .list
        .borrow()
        .get_all("set-cookie")
        .into_iter()
        .map(|v| {
            ctx.create_string_from_utf8(v.into_bytes())
                .map(JSValue::make_string)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Array::from_values(ctx, cookies).map(JSValue::from)
}

// `[Symbol.iterator]` is an alias of `entries` (see `HEADERS_PROTO`), so no
// dedicated handler is needed here.

const HEADERS_PROTO: &[FieldDef] = &[
    FieldDef::FUNC_ENUM("append", 2, js_headers_append, 0),
    FieldDef::FUNC_ENUM("delete", 1, js_headers_delete, 0),
    FieldDef::FUNC_ENUM("get", 1, js_headers_get, 0),
    FieldDef::FUNC_ENUM("has", 1, js_headers_has, 0),
    FieldDef::FUNC_ENUM("set", 2, js_headers_set, 0),
    FieldDef::FUNC_ENUM("forEach", 1, js_headers_for_each, 0),
    FieldDef::FUNC_ENUM("keys", 0, js_headers_keys, 0),
    FieldDef::FUNC_ENUM("values", 0, js_headers_values, 0),
    FieldDef::FUNC_ENUM("entries", 0, js_headers_entries, 0),
    FieldDef::FUNC_ENUM("getSetCookie", 0, js_headers_get_set_cookie, 0),
    // WebIDL §3.7.9: `%Symbol.iterator%` must be the *same function object* as
    // `entries`. Note the asymmetry there: `entries` is created with
    // `CreateDataPropertyOrThrow` (enumerable: true) while `%Symbol.iterator%`
    // is `DefineMethodProperty(..., false)` (enumerable: false), so this uses
    // the plain non-enumerable `ALIAS`.
    FieldDef::ALIAS("[Symbol.iterator]", "entries"),
    // WebIDL: an interface prototype object's class string is the interface's
    // qualified name (`Object.prototype.toString` → "[object Headers]").
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "Headers",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "Headers",
    JSHeaders,
    HeadersPayload,
    HEADERS_PROTO,
    Some(ClassCtorDef::new(js_headers_constructor, 0, true).expose_to_global())
);
