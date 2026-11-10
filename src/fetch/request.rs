// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

use std::{cell::RefCell, rc::Rc};

use zuqe::{
    CallContext, ClassCtorDef, Exception, FieldDef, JSResult, JSValue, NativeObject, Object,
    ScopedContext, WriteBarrier,
    builtins::promise::Promise,
    def_native_object,
    gc_lite::{GcTrace, GcTraceCtx},
};

use crate::{
    abort::{JSAbortSignal, make_default_signal, signal_attach_follower},
    fetch::{
        body::{
            BODY_AS_ARRAY_BUFFER, BODY_AS_BLOB, BODY_AS_BYTES, BODY_AS_FORM_DATA, BODY_AS_JSON,
            BODY_AS_TEXT, BodySource, blob_type_from_header, body_content_type, body_to_bytes,
            drain_body,
        },
        headers::{
            Guard, HeaderList, HeadersPayload, JSHeaders, header_list_from_js,
            validate_header_list_for_fetch,
        },
    },
    stream::JSReadableStream,
};

#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct RequestPayload {
    #[gc(skip)]
    pub(crate) method: String,
    #[gc(skip)]
    pub(crate) url: String,
    #[gc(skip)]
    pub(crate) headers: Rc<RefCell<HeaderList>>,
    #[gc(skip)]
    pub(crate) destination: String,
    #[gc(skip)]
    pub(crate) referrer: String,
    #[gc(skip)]
    pub(crate) referrer_policy: String,
    #[gc(skip)]
    pub(crate) mode: String,
    #[gc(skip)]
    pub(crate) credentials: String,
    #[gc(skip)]
    pub(crate) cache: String,
    #[gc(skip)]
    pub(crate) redirect: String,
    #[gc(skip)]
    pub(crate) integrity: String,
    #[gc(skip)]
    pub(crate) keepalive: bool,
    /// Request `duplex` mode. Defaults to `"half"`; `new Request(stream)` without
    /// `duplex: "half"` is rejected at construction.
    #[gc(skip)]
    pub(crate) duplex: String,
    #[gc(skip)]
    pub(crate) is_reload_navigation: bool,
    #[gc(skip)]
    pub(crate) is_history_navigation: bool,
    pub(crate) signal: Option<JSValue>,
    /// Cached `Headers` object returned by the `headers` getter ([SameObject]).
    pub(crate) headers_obj: WriteBarrier<Option<JSValue>>,
    #[gc(skip)]
    pub(crate) synthetic_body: Option<Vec<u8>>,
    /// A `ReadableStream` body, kept unread until the request is sent.
    pub(crate) stream_body: Option<JSValue>,
    /// Cached body `ReadableStream` returned by the `body` getter; stays the
    /// same object across accesses and after consumption (disturbed).
    pub(crate) cached_body: WriteBarrier<Option<JSReadableStream>>,
    #[gc(skip)]
    pub(crate) body_consumed: bool,
}

pub(crate) fn get_request_payload_mut<'a>(
    ctx: &mut ScopedContext,
    val: &'a mut JSValue,
) -> Result<&'a mut RequestPayload, i32> {
    JSRequest::payload_mut_of(val).ok_or_else(|| ctx.throw_type_error("not a Request instance"))
}

fn get_request_payload<'a>(
    ctx: &mut ScopedContext,
    val: &'a JSValue,
) -> Result<&'a RequestPayload, i32> {
    JSRequest::payload_of(val).ok_or_else(|| ctx.throw_type_error("not a Request instance"))
}

/// HTTP token byte, per RFC 7230 tchar: `!#$%&'*+-.^_`|~` plus alphanumerics.
fn is_http_token(c: char) -> bool {
    matches!(c,
        '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~'
        | '0'..='9' | 'A'..='Z' | 'a'..='z')
}

/// WHATWG forbidden methods: CONNECT, TRACE, TRACK (byte-case-insensitive).
fn is_forbidden_method(method: &str) -> bool {
    matches!(
        method.to_ascii_lowercase().as_str(),
        "connect" | "trace" | "track"
    )
}

/// Throw a TypeError and return it as a rejected promise: body-use methods
/// must reject rather than throw synchronously (Fetch spec). Shared by the
/// Request/Response body consumers.
pub(super) fn reject_type_error_as_promise(ctx: &mut ScopedContext, msg: &str) -> JSResult {
    let _ = ctx.throw_type_error(msg);
    let reason = match ctx.take_exception() {
        Exception::Error(v) => v,
        // Non-Error exceptions (OOM, interrupt) must stay fatal.
        other => {
            ctx.throw(other);
            return Err(-1);
        }
    };
    Promise::from_reject_value(ctx, reason).map(JSValue::from)
}

/// Fetch spec "ensure method": the method must be a valid HTTP token, and not a
/// forbidden method. Returns `Err` (TypeError) on violation.
pub(crate) fn check_request_method(ctx: &mut ScopedContext, method: &str) -> Result<(), i32> {
    if is_forbidden_method(method) {
        return Err(ctx.throw_type_error(&format!("method {method} is forbidden")));
    }
    if !method.chars().all(is_http_token) {
        return Err(ctx.throw_type_error(&format!("invalid method {method}")));
    }
    Ok(())
}

/// Fetch spec "method normalize": uppercase the method if it is a
/// byte-case-insensitive match for one of DELETE, GET, HEAD, OPTIONS, POST, PUT.
/// Any other method (e.g. `patch`, custom verbs) is left as-is.
pub(crate) fn normalize_method(method: &str) -> String {
    match method.to_ascii_uppercase().as_str() {
        "DELETE" | "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" => method.to_ascii_uppercase(),
        _ => method.to_string(),
    }
}

/// Fetch spec "validate request URL": the URL must resolve to a valid `URL`
/// (absolute, or relative against the current document base), must not contain
/// credentials, and must not be `about:blank` or `about:srcdoc`. Returns `Err`
/// (TypeError) on violation.
fn check_request_url(ctx: &mut ScopedContext, url: &str) -> Result<(), i32> {
    if url == "about:blank" || url == "about:srcdoc" {
        return Ok(());
    }
    // Resolve relative URLs against the current module/document base, mirroring
    // how `fetch()` resolves relative specifiers. An absolute URL parses
    // directly; a relative one needs the base.
    let parsed = match url::Url::parse(url) {
        Ok(u) => Some(u),
        Err(_) => ctx
            .current_module_name()
            .and_then(|base| url::Url::parse(&base).ok())
            .and_then(|base| base.join(url).ok()),
    };
    let parsed = parsed.ok_or_else(|| ctx.throw_type_error(&format!("invalid URL: {url}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ctx.throw_type_error("URL contains credentials"));
    }
    Ok(())
}

/// Fetch spec allowed request credentials.
const VALID_CREDENTIALS: &[&str] = &["omit", "same-origin", "include"];
/// Fetch spec allowed request cache modes.
const VALID_CACHE: &[&str] = &[
    "default",
    "no-store",
    "reload",
    "no-cache",
    "force-cache",
    "only-if-cached",
];
/// Fetch spec allowed request redirect modes.
const VALID_REDIRECT: &[&str] = &["follow", "error", "manual"];
/// Fetch spec allowed request referrer policies.
const VALID_REFERRER_POLICY: &[&str] = &[
    "",
    "no-referrer",
    "no-referrer-when-downgrade",
    "same-origin",
    "origin",
    "strict-origin",
    "origin-when-cross-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
];
/// Fetch spec allowed request modes.
const VALID_MODE: &[&str] = &["same-origin", "no-cors", "cors", "navigate", "websocket"];
/// Fetch spec allowed request priorities (RequestInit.priority).
const VALID_PRIORITY: &[&str] = &["high", "low", "auto"];

/// Validate a `RequestInit` option string against its allowed set (per the Fetch
/// spec, invalid values throw `TypeError`). `request-error.js` WPT exercises the
/// `referrerPolicy`/`mode`/`credentials`/`cache`/`redirect` bad-value cases.
fn check_enum_option(
    ctx: &mut ScopedContext,
    name: &str,
    value: &str,
    allowed: &[&str],
) -> Result<(), i32> {
    if !allowed.contains(&value) {
        return Err(
            ctx.throw_type_error(&format!("invalid value '{value}' for RequestInit.{name}"))
        );
    }
    Ok(())
}

/// Fetch spec "request method + no-cors" rule: a `no-cors` request may only use
/// a CORS-safelisted method (`GET`, `HEAD`, `POST`); anything else throws.
fn is_cors_safelisted_method(method: &str) -> bool {
    matches!(
        method.to_ascii_lowercase().as_str(),
        "get" | "head" | "post"
    )
}

/// Whether a referrer value parses as a URL, absolutely or relative to any base
/// (the spec resolves it against the entry settings object's base URL).
/// Whether a referrer value parses as a URL, absolutely or relative to a base
/// (the spec resolves it against the entry settings object's base URL). The base
/// here is only a resolvability probe, so any hierarchical URL will do — an
/// opaque-path base like `about:blank` cannot resolve relative references.
fn is_parseable_referrer(referrer: &str) -> bool {
    url::Url::parse(referrer)
        .or_else(|_| url::Url::parse("https://example.invalid/").and_then(|b| b.join(referrer)))
        .is_ok()
}

/// Validate the request options that the Fetch spec rejects with a `TypeError`
/// (`method`, `mode`, `cache`, `credentials`, `redirect`, `referrerPolicy`,
/// `referrer`, `only-if-cached`/`same-origin`, `no-cors` method, `navigate` mode).
///
/// Shared by `new Request` and `fetch`: a string-`input` `fetch` call does not
/// build a `Request` object, so it must run this validation itself — WPT
/// `abort/general.any.js` "TypeError from request constructor takes priority"
/// requires a bad init to reject with `TypeError` *before* an already-aborted
/// signal surfaces an `AbortError`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_request_init_options(
    ctx: &mut ScopedContext,
    url_str: &str,
    method: &str,
    mode: &str,
    cache: &str,
    credentials: &str,
    redirect: &str,
    referrer: &str,
    referrer_policy: &str,
) -> Result<(), i32> {
    // Validate the request URL (WPT request-error: invalid URL, credentials).
    if !url_str.is_empty() {
        check_request_url(ctx, url_str)?;
    }
    // Validate the request method (WPT forbidden-method / request-error).
    check_request_method(ctx, method)?;
    // Validate the enum options (WPT request-error bad-option values).
    check_enum_option(ctx, "mode", mode, VALID_MODE)?;
    check_enum_option(ctx, "credentials", credentials, VALID_CREDENTIALS)?;
    check_enum_option(ctx, "cache", cache, VALID_CACHE)?;
    check_enum_option(ctx, "redirect", redirect, VALID_REDIRECT)?;
    check_enum_option(
        ctx,
        "referrerPolicy",
        referrer_policy,
        VALID_REFERRER_POLICY,
    )?;
    // Validate the referrer: must be `""`, `about:client`, `about:blank`, or
    // something parseable as a URL (WPT request-error "RequestInit's referrer is
    // invalid"). The spec parses the referrer *with* the entry settings object's
    // base URL, so a relative value like `myreferrer` is valid and resolves
    // against the document base — only a value that parses neither absolutely
    // nor relatively is a TypeError.
    if !matches!(referrer, "" | "about:client" | "about:blank") && !is_parseable_referrer(referrer)
    {
        return Err(ctx.throw_type_error("RequestInit.referrer is not a valid URL"));
    }
    // `only-if-cached` requires `mode: "same-origin"` (WPT request-error).
    if cache == "only-if-cached" && mode != "same-origin" {
        return Err(ctx.throw_type_error("cache mode 'only-if-cached' requires mode 'same-origin'"));
    }
    // `no-cors` mode forbids non-safelisted methods (WPT request-error).
    if mode == "no-cors" && !is_cors_safelisted_method(method) {
        return Err(ctx.throw_type_error("mode 'no-cors' may only use CORS-safelisted methods"));
    }
    // A `navigate` mode is never constructible (WPT request-error).
    if mode == "navigate" {
        return Err(ctx.throw_type_error("mode 'navigate' is not constructible"));
    }
    Ok(())
}

fn js_request_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let new_target = cc.this();
    let input = cc.arg(0);

    let mut url_str = String::new();
    let mut method = String::from("GET");
    let mut header_list = HeaderList::new();
    let mut synthetic_body: Option<Vec<u8>> = None;
    let mut stream_body: Option<JSValue> = None;
    let mut redirect = String::from("follow");
    let mut signal: Option<JSValue> = None;
    let mut integrity = String::new();
    // Track the effective `mode`/`cache`/`credentials`/`referrer`/`referrerPolicy`
    // and `duplex`/navigation flags so validation and defaults can be applied
    // after the input-Request and RequestInit layers are merged.
    let mut mode = String::from("cors");
    let mut cache = String::from("default");
    let mut credentials = String::from("same-origin");
    let mut referrer = String::from("about:client");
    let mut referrer_policy = String::new();
    let mut duplex: Option<String> = None;
    let mut keepalive = false;
    let mut is_reload_navigation = false;
    let mut is_history_navigation = false;
    // Whether RequestInit supplied a non-null `body` (overrides the input's).
    let mut init_body_provided = false;

    // Track an input `Request` so its body can be disturbed (marked used) after
    // all constructor validation has passed — a *failed* construction must not
    // disturb the input (WPT request-disturbed "construction failure should not
    // set bodyUsed").
    let mut input_is_request = false;
    let mut input_has_body = false;
    let mut input_body_consumed = false;

    // Inherit from a Request input.
    if let Some(p) = JSRequest::payload_of(&input) {
        input_is_request = true;
        input_has_body = p.synthetic_body.is_some() || p.stream_body.is_some();
        input_body_consumed = p.body_consumed;
        url_str = p.url.clone();
        method = p.method.clone();
        header_list = p.headers.borrow().clone();
        redirect = p.redirect.clone();
        signal = p.signal;
        synthetic_body = p.synthetic_body.clone();
        stream_body = p.stream_body;
        mode = p.mode.clone();
        cache = p.cache.clone();
        credentials = p.credentials.clone();
        referrer = p.referrer.clone();
        referrer_policy = p.referrer_policy.clone();
        integrity = p.integrity.clone();
        is_reload_navigation = p.is_reload_navigation;
        is_history_navigation = p.is_history_navigation;
    } else if !input.is_undefined_or_null() {
        let href = input.get_property_str(ctx, "href")?;
        if !href.is_undefined() {
            url_str = href
                .to_string(ctx)?
                .content()
                .encode_utf8(false)
                .to_string();
        } else {
            url_str = input
                .to_string(ctx)?
                .content()
                .encode_utf8(false)
                .to_string();
        }
    }

    // Apply RequestInit overrides.
    if cc.length() > 1 {
        let init = cc.arg(1);
        if let Some(o) = init.as_object() {
            // `window` is only ever allowed to be null (it is a forbidden
            // legacy option). Any other value throws (WPT request-error).
            let w = o.get_property_str(ctx, "window")?;
            if !w.is_undefined() && !w.is_null() {
                return Err(ctx.throw_type_error("RequestInit.window must be null"));
            }

            let m = o.get_property_str(ctx, "method")?;
            if !m.is_undefined() {
                let raw = m.to_string(ctx)?.content().encode_utf8(false).to_string();
                method = normalize_method(&raw);
            }
            let mut h = o.get_property_str(ctx, "headers")?;
            if !h.is_undefined_or_null() {
                header_list = header_list_from_js(ctx, &mut h)?;
            }
            // `duplex` must be read off the init dictionary whenever a body is
            // present, and read before `body` so a getter on it still fires.
            let d = o.get_property_str(ctx, "duplex")?;
            if !d.is_undefined() {
                duplex = Some(d.to_string(ctx)?.content().encode_utf8(false).to_string());
            }

            // Any non-`"half"` `duplex` value rejects the request, whatever the
            // body (or absence thereof) — WPT request-init-stream "duplex full"
            // cases, including `body: null`.
            if let Some(d) = duplex.as_deref()
                && d != "half"
            {
                return Err(ctx.throw_type_error("duplex must be 'half'"));
            }

            let b = o.get_property_str(ctx, "body")?;
            if !b.is_undefined_or_null() {
                init_body_provided = true;
                // The body source implies a default Content-Type unless the
                // caller already supplied one.
                if let Some(t) = body_content_type(&b)
                    && !header_list.has("content-type")
                {
                    header_list.set("Content-Type", &t);
                }

                let is_stream = JSReadableStream::payload_of(&b).is_some();
                // A body on a GET/HEAD request is a TypeError.
                if !is_stream && matches!(method.as_str(), "GET" | "HEAD") {
                    return Err(ctx.throw_type_error("GET/HEAD requests may not have a body"));
                }
                // A stream body requires `duplex: "half"` and must not already be
                // locked/disturbed (WPT request-init-stream).
                if is_stream {
                    let unusable = JSReadableStream::payload_of(&b)
                        .is_some_and(|sp| sp.disturbed || sp.reader.get().is_some());
                    if duplex.as_deref() != Some("half") {
                        return Err(ctx.throw_type_error(
                            "Request body is a ReadableStream but duplex is not 'half'",
                        ));
                    }
                    if unusable {
                        return Err(ctx.throw_type_error(
                            "Request body ReadableStream is locked or already disturbed",
                        ));
                    }
                    stream_body = Some(b);
                } else {
                    synthetic_body = Some(body_to_bytes(ctx, &b)?);
                }
            }

            let r = o.get_property_str(ctx, "redirect")?;
            if !r.is_undefined() {
                redirect = r.to_string(ctx)?.content().encode_utf8(false).to_string();
            }

            let s = o.get_property_str(ctx, "signal")?;
            if JSAbortSignal::from_value(s).is_some() {
                signal = Some(s);
            }

            let mut read_str = |o: Object, key: &str| -> Result<Option<String>, i32> {
                let v = o.get_property_str(ctx, key)?;
                if v.is_undefined() {
                    Ok(None)
                } else {
                    Ok(Some(
                        v.to_string(ctx)?.content().encode_utf8(false).to_string(),
                    ))
                }
            };
            if let Some(v) = read_str(o, "mode")? {
                mode = v;
            }
            if let Some(v) = read_str(o, "credentials")? {
                credentials = v;
            }
            if let Some(v) = read_str(o, "cache")? {
                cache = v;
            }
            if let Some(v) = read_str(o, "referrer")? {
                referrer = v;
            }
            if let Some(v) = read_str(o, "referrerPolicy")? {
                referrer_policy = v;
            }
            // SRI metadata string, echoed verbatim by `Request.integrity`.
            if let Some(v) = read_str(o, "integrity")? {
                integrity = v;
            }
            if let Some(v) = read_str(o, "priority")? {
                // Validate eagerly: any invalid RequestInit member value must
                // throw a TypeError (WPT request-init-priority).
                check_enum_option(ctx, "priority", &v, VALID_PRIORITY)?;
            }
            let rn = o.get_property_str(ctx, "isReloadNavigation")?;
            if !rn.is_undefined() {
                is_reload_navigation = rn.to_bool()?;
            }
            let hn = o.get_property_str(ctx, "isHistoryNavigation")?;
            if !hn.is_undefined() {
                is_history_navigation = hn.to_bool()?;
            }
            let kl = o.get_property_str(ctx, "keepalive")?;
            if !kl.is_undefined() {
                keepalive = kl.to_bool()?;
            }
        }
    }

    // A `keepalive: true` request cannot use a ReadableStream body (WPT
    // request-keepalive "keepalive flag with stream body").
    if keepalive && stream_body.is_some() {
        return Err(ctx.throw_type_error("keepalive requests cannot have a ReadableStream body"));
    }

    // Validate request URL + method + enum options (WPT request-error, and shared
    // with `fetch` so a string-input fetch also rejects bad init with TypeError).
    validate_request_init_options(
        ctx,
        &url_str,
        &method,
        &mode,
        &cache,
        &credentials,
        &redirect,
        &referrer,
        &referrer_policy,
    )?;
    // A GET/HEAD request may not carry a body — whether inherited from the input
    // Request or supplied via init (WPT request-disturbed "A get request may not
    // have body").
    if matches!(method.as_str(), "GET" | "HEAD")
        && (synthetic_body.is_some() || stream_body.is_some())
    {
        return Err(ctx.throw_type_error("GET/HEAD requests may not have a body"));
    }

    // Validate header names/values per the Fetch spec. Must run on the JS
    // thread so a violation throws a `TypeError` synchronously (WPT expects
    // `promise_rejects_js(t, TypeError, ...)`).
    validate_header_list_for_fetch(ctx, &header_list)?;

    // Filter headers per the request's final mode: forbidden request headers
    // are dropped for normal requests; only CORS-safelisted headers survive in
    // `no-cors` mode (WPT request-headers).
    header_list.filter_for_request_mode(mode == "no-cors");

    // Disturb the input Request's body per the Fetch spec: constructing a new
    // Request from an input with a body marks the input's body as used. A
    // request with a *replaced* body (init.body) disturbs the input too; a
    // request without a replacement body whose input is already disturbed
    // throws a TypeError (WPT request-disturbed).
    // The input Request's body is unusable if it was consumed OR its body
    // stream was locked/disturbed (e.g. `request.body.getReader()` was called,
    // WPT request-init-stream). In either case, without a replacement body the
    // new construction throws.
    let input_body_unusable = if input_is_request && !init_body_provided {
        let p = get_request_payload(ctx, &input)?;
        p.body_consumed
            || p.cached_body.get().is_some_and(|s| {
                s.payload()
                    .is_some_and(|sp| sp.disturbed || sp.reader.get().is_some())
            })
    } else {
        false
    };
    if input_body_unusable {
        return Err(ctx.throw_type_error(
            "Cannot construct a Request from a request whose body has already been used",
        ));
    }

    if input_is_request
        && input_has_body
        && !input_body_consumed
        && let Ok(p) = get_request_payload_mut(ctx, &mut input.clone())
    {
        p.body_consumed = true;
    }

    // WHATWG: `request.signal` is a fresh "follow" signal that follows the
    // supplied signal (`request.signal !== signal`), and is never the same
    // object. If no signal is supplied, create a default non-aborted signal so
    // that `request.signal` is always present.
    let signal = match signal {
        Some(parent) => {
            let child = make_default_signal(ctx)?;
            signal_attach_follower(ctx, &parent, &child);
            Some(child)
        }
        None => Some(make_default_signal(ctx)?),
    };

    let payload = RequestPayload {
        method,
        url: url_str,
        headers: Rc::new(RefCell::new(header_list)),
        destination: String::new(),
        referrer,
        referrer_policy,
        mode,
        credentials,
        cache,
        redirect,
        integrity,
        keepalive,
        duplex: duplex.unwrap_or_else(|| "half".to_string()),
        is_reload_navigation,
        is_history_navigation,
        signal,
        headers_obj: WriteBarrier::new(None),
        synthetic_body,
        stream_body,
        cached_body: WriteBarrier::new(None),
        body_consumed: false,
    };

    JSRequest::new_instance(ctx, new_target, payload).map(JSValue::from)
}

// --- getters ---

macro_rules! req_str_getter {
    ($name:ident, $field:ident) => {
        fn $name(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
            let this = cc.this();
            let p = get_request_payload(ctx, &this)?;
            ctx.create_string_from_utf8(p.$field.as_bytes().to_vec())
                .map(JSValue::make_string)
        }
    };
}

req_str_getter!(js_req_method, method);
req_str_getter!(js_req_url, url);
req_str_getter!(js_req_destination, destination);
req_str_getter!(js_req_referrer, referrer);
req_str_getter!(js_req_referrer_policy, referrer_policy);
req_str_getter!(js_req_mode, mode);
req_str_getter!(js_req_credentials, credentials);
req_str_getter!(js_req_cache, cache);
req_str_getter!(js_req_redirect, redirect);
req_str_getter!(js_req_integrity, integrity);

fn js_req_keepalive_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = get_request_payload(ctx, &this)?;
    Ok(JSValue::from(p.keepalive))
}

fn js_req_duplex_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = get_request_payload(ctx, &this)?;
    ctx.create_string_from_utf8(p.duplex.as_bytes().to_vec())
        .map(JSValue::make_string)
}

fn js_req_is_reload_navigation_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = get_request_payload(ctx, &this)?;
    Ok(JSValue::from(p.is_reload_navigation))
}

fn js_req_is_history_navigation_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = get_request_payload(ctx, &this)?;
    Ok(JSValue::from(p.is_history_navigation))
}

fn js_req_signal_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = get_request_payload(ctx, &this)?;
    Ok(p.signal.unwrap_or(JSValue::NULL))
}

fn js_req_headers_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    // [SameObject]: return the same Headers instance on every access.
    let mut this = cc.this();
    if let Some(h) = get_request_payload_mut(ctx, &mut this)?.headers_obj.get() {
        return Ok(h);
    }
    let (shared, guard) = {
        let p = get_request_payload(ctx, &this)?;
        // A Request's exposed Headers object uses the `request` guard (or
        // `request-no-cors` in no-cors mode), which silently drops forbidden
        // request-header names / non-CORS-safelisted writes.
        let guard = if p.mode == "no-cors" {
            Guard::RequestNoCors
        } else {
            Guard::Request
        };
        (p.headers.clone(), guard)
    };
    let payload = HeadersPayload::from_shared(shared, guard);
    let headers = JSHeaders::new_instance(ctx, JSValue::UNDEFINED, payload)?;
    let hv = headers.into();
    let owner = this;
    get_request_payload_mut(ctx, &mut this)?
        .headers_obj
        .set(ctx, owner, Some(hv));
    // The guard slot records the request→Headers barrier itself.
    Ok(hv)
}

fn js_req_body_used_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = get_request_payload(ctx, &this)?;
    Ok(JSValue::from(p.body_consumed))
}

fn js_req_body(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut this = cc.this();
    // Copy of the owner for the write barriers below: the payload borrows
    // `this` mutably, so the original cannot be read while they are live.
    let owner = this;

    // A stream body is exposed as-is: it is the very stream the caller passed
    // in, so `request.body` must hand back that same object.
    {
        let p = get_request_payload_mut(ctx, &mut this)?;
        if !p.body_consumed
            && let Some(s) = p.stream_body
        {
            return Ok(s);
        }
    }
    // Return the same cached stream instance on every access ([SameObject]).
    {
        let p = get_request_payload_mut(ctx, &mut this)?;
        if let Some(s) = p.cached_body.get() {
            return Ok(JSValue::from(s));
        }
    }

    // A *consumed* body still exposes a `body` that is a ReadableStream —
    // disturbed, so any read rejects (Fetch spec). A request that never had a
    // body exposes a null `body` (WPT request-disturbed "body's default value
    // is null").
    {
        let p = get_request_payload_mut(ctx, &mut this)?;
        if p.body_consumed {
            let mut s = JSReadableStream::from_bytes(ctx, Vec::new())?;
            // Lock the stream so a later getReader() throws (Fetch spec: a
            // consumed request body still exposes a disturbed ReadableStream).
            s.acquire_reader(ctx, false)?;
            p.cached_body.set(ctx, owner, Some(s));
            // The guard slot records the request→stream barrier itself.
            return Ok(JSValue::from(p.cached_body.get().expect("just set")));
        }
        // A request constructed without any body has a null body.
        if p.synthetic_body.is_none() && p.stream_body.is_none() {
            return Ok(JSValue::NULL);
        }
    }

    // First access of an unconsumed buffered body: build and cache the stream.
    // The synthetic bytes are *cloned* (not taken): accessing `request.body`
    // does not consume the body (bodyUsed stays false), so a later `blob()` /
    // `text()` must still find the source bytes.
    let stream = {
        let p = get_request_payload_mut(ctx, &mut this)?;
        if let Some(bytes) = p.synthetic_body.clone() {
            JSReadableStream::from_bytes(ctx, bytes)?
        } else {
            JSReadableStream::from_bytes(ctx, Vec::new())?
        }
    };
    get_request_payload_mut(ctx, &mut this)?
        .cached_body
        .set(ctx, owner, Some(stream));
    // The guard slot records the request→stream barrier itself.
    let p = get_request_payload_mut(ctx, &mut this)?;
    Ok(JSValue::from(p.cached_body.get().expect("just set")))
}

/// Body read methods for Request (bytes, text, json, arrayBuffer).
fn js_req_body_as(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let magic = cc.magic();
    let mut this = cc.this();

    // Spec (Fetch): an already-consumed body rejects with a `TypeError`
    // *before* any abort-signal check — WPT "Calling arrayBuffer() on an
    // aborted consumed nonempty request must reject with TypeError" expects
    // the consumed state to take priority over a(`AbortError`) abort reason.
    {
        let p = get_request_payload(ctx, &this)?;
        if p.body_consumed {
            return reject_type_error_as_promise(ctx, "body already consumed or unavailable");
        }
    }

    // A null-body request (e.g. `new Request(url)` with no init body) has no
    // synthetic/stream body and is never disturbed. `formData()` must reject on
    // a null body per the Fetch spec (e.g. WPT "Consume request's body as
    // formData with correct multipart type (error case)"), even when a multipart
    // `Content-Type` header is set without an actual body. We record this before
    // the source block turns it into an empty synthetic body.
    let is_null_body = {
        let p = get_request_payload(ctx, &this)?;
        !p.body_consumed && p.synthetic_body.is_none() && p.stream_body.is_none()
    };

    // A null-body request consumed as `formData()` must reject per the Fetch
    // spec when the `Content-Type` is multipart/form-data (which needs a closing
    // delimiter that an empty body lacks) — WPT "Consume request's body as
    // formData with correct multipart type (error case)". A null body with an
    // `application/x-www-form-urlencoded` type still parses (to an empty
    // FormData), so it is allowed through.
    if magic == BODY_AS_FORM_DATA && is_null_body {
        let p = get_request_payload(ctx, &this)?;
        let ct = p.headers.borrow().get("content-type").unwrap_or_default();
        if ct.to_ascii_lowercase().starts_with("multipart/form-data") {
            return reject_type_error_as_promise(ctx, "cannot parse null body as FormData");
        }
    }

    // NOTE: Unlike Response (whose body consumption is aborted by its signal),
    // a Request's body methods consume the *request* body and are NOT affected
    // by signal abort. An aborted-but-unconsumed request resolves normally; a
    // consumed request rejects with TypeError (handled above). See WPT
    // fetch/api/abort/request.any.js.

    let source = {
        let p = get_request_payload_mut(ctx, &mut this)?;
        if p.body_consumed {
            None
        } else if let Some(bytes) = p.synthetic_body.take() {
            p.body_consumed = true;
            Some(BodySource::Synthetic(bytes))
        } else if let Some(s) = p.stream_body.take() {
            // A stream body is drained on demand, like a buffered one.
            p.body_consumed = true;
            Some(BodySource::Stream(JSReadableStream::try_from(s)?))
        } else {
            // Null-body request (e.g. `new Request(url)` with no init body):
            // consumers resolve to the empty value, and the body stays unused
            // (bodyUsed remains false — a null body is never disturbed).
            Some(BodySource::Synthetic(Vec::new()))
        }
    };

    // Request.blob() sets the Blob's type to the request's *current*
    // Content-Type header (mutable via `headers.set`), with parameters
    // stripped. Computed before consuming the source below.
    let blob_type = match magic {
        BODY_AS_BLOB => {
            let p = get_request_payload(ctx, &this)?;
            blob_type_from_header(&p.headers.borrow())
        }
        // formData() needs the raw Content-Type: the multipart boundary lives
        // in the parameters that blob_type_from_header strips.
        BODY_AS_FORM_DATA => {
            let p = get_request_payload(ctx, &this)?;
            let ct = p.headers.borrow().get("content-type");
            ct.unwrap_or_default()
        }
        _ => String::new(),
    };

    // The request's `AbortSignal`, so a mid-read abort rejects with the signal's
    // reason rather than the cancellation's transport error.
    let signal = get_request_payload(ctx, &this).ok().and_then(|p| p.signal);

    match source {
        Some(source) => drain_body(ctx, source, magic, blob_type, signal),
        // Spec: these methods always return a promise; an already-consumed body
        // rejects it rather than throwing synchronously.
        None => reject_type_error_as_promise(ctx, "body already consumed or unavailable"),
    }
}

/// `textStream()` — returns a `ReadableStream` of UTF-8-decoded string chunks.
/// Consumes the body (sets `bodyUsed`); a null-body request yields an empty
/// stream without marking the body used, and an already-consumed or locked
/// body throws (WPT fetch/api/body/textstream.any.js expects a TypeError when
/// `request.body` is locked via `getReader()`).
fn js_req_text_stream(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    let mut this = _cc.this();
    let source = {
        let p = get_request_payload_mut(ctx, &mut this)?;
        if p.body_consumed {
            return Err(ctx.throw_type_error("body already consumed or locked"));
        }
        // A body exposed as a ReadableStream that is locked (or disturbed)
        // cannot be consumed again — `textStream()` must reject, just like
        // `blob()`/`text()` do (the shared `request_body_unusable` helper).
        if p.cached_body.get().is_some_and(|s| {
            s.payload()
                .is_some_and(|sp| sp.disturbed || sp.reader.get().is_some())
        }) {
            return Err(ctx.throw_type_error("body is locked"));
        }

        // Null-body request: empty stream, bodyUsed stays false, reusable.
        if p.synthetic_body.is_none() && p.stream_body.is_none() {
            None
        } else if let Some(bytes) = p.synthetic_body.take() {
            p.body_consumed = true;
            Some(BodySource::Synthetic(bytes))
        } else {
            p.body_consumed = true;
            let s = p.stream_body.take().expect("stream_body checked above");
            Some(BodySource::Stream(JSReadableStream::try_from(s)?))
        }
    };

    match source {
        Some(src) => Ok(JSValue::from(JSReadableStream::from_text_source(ctx, src)?)),
        None => Ok(JSValue::from(JSReadableStream::from_text_source(
            ctx,
            BodySource::Synthetic(Vec::new()),
        )?)),
    }
}

fn js_req_clone(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();

    let src = get_request_payload(ctx, &this)?;
    if src.body_consumed {
        return Err(ctx.throw_type_error("Cannot clone a Request whose body has already been used"));
    }

    // WHATWG: a cloned Request gets its own "follow" signal that tracks the
    // original. `clone.signal` must be a distinct object from `request.signal`,
    // and aborting the original controller must abort the clone's signal too.
    let signal = match src.signal {
        Some(parent) => {
            let child = make_default_signal(ctx)?;
            signal_attach_follower(ctx, &parent, &child);
            Some(child)
        }
        None => None,
    };

    let payload = RequestPayload {
        method: src.method.clone(),
        url: src.url.clone(),
        // A cloned request owns an independent header set, not the shared one.
        headers: Rc::new(RefCell::new(src.headers.borrow().clone())),
        destination: src.destination.clone(),
        referrer: src.referrer.clone(),
        referrer_policy: src.referrer_policy.clone(),
        mode: src.mode.clone(),
        credentials: src.credentials.clone(),
        cache: src.cache.clone(),
        redirect: src.redirect.clone(),
        integrity: src.integrity.clone(),
        keepalive: src.keepalive,
        duplex: src.duplex.clone(),
        is_reload_navigation: src.is_reload_navigation,
        is_history_navigation: src.is_history_navigation,
        signal,
        headers_obj: WriteBarrier::new(None),
        synthetic_body: src.synthetic_body.clone(),
        stream_body: src.stream_body,
        cached_body: WriteBarrier::new(None),
        body_consumed: false,
    };
    JSRequest::new_instance(ctx, this, payload).map(JSValue::from)
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

const REQUEST_PROTO: &[FieldDef] = &[
    FieldDef::GETSET_ENUM("method", Some(js_req_method), None, 0),
    FieldDef::GETSET_ENUM("url", Some(js_req_url), None, 0),
    FieldDef::GETSET_ENUM("destination", Some(js_req_destination), None, 0),
    FieldDef::GETSET_ENUM("referrer", Some(js_req_referrer), None, 0),
    FieldDef::GETSET_ENUM("referrerPolicy", Some(js_req_referrer_policy), None, 0),
    FieldDef::GETSET_ENUM("mode", Some(js_req_mode), None, 0),
    FieldDef::GETSET_ENUM("credentials", Some(js_req_credentials), None, 0),
    FieldDef::GETSET_ENUM("cache", Some(js_req_cache), None, 0),
    FieldDef::GETSET_ENUM("redirect", Some(js_req_redirect), None, 0),
    FieldDef::GETSET_ENUM("integrity", Some(js_req_integrity), None, 0),
    FieldDef::GETSET_ENUM("keepalive", Some(js_req_keepalive_getter), None, 0),
    FieldDef::GETSET_ENUM("signal", Some(js_req_signal_getter), None, 0),
    FieldDef::GETSET_ENUM("headers", Some(js_req_headers_getter), None, 0),
    FieldDef::GETSET_ENUM("bodyUsed", Some(js_req_body_used_getter), None, 0),
    FieldDef::GETSET_ENUM("duplex", Some(js_req_duplex_getter), None, 0),
    FieldDef::GETSET_ENUM(
        "isReloadNavigation",
        Some(js_req_is_reload_navigation_getter),
        None,
        0,
    ),
    FieldDef::GETSET_ENUM(
        "isHistoryNavigation",
        Some(js_req_is_history_navigation_getter),
        None,
        0,
    ),
    FieldDef::GETSET_ENUM("body", Some(js_req_body), None, 0),
    FieldDef::FUNC_ENUM("bytes", 0, js_req_body_as, BODY_AS_BYTES as i16),
    FieldDef::FUNC_ENUM(
        "arrayBuffer",
        0,
        js_req_body_as,
        BODY_AS_ARRAY_BUFFER as i16,
    ),
    FieldDef::FUNC_ENUM("text", 0, js_req_body_as, BODY_AS_TEXT as i16),
    FieldDef::FUNC_ENUM("json", 0, js_req_body_as, BODY_AS_JSON as i16),
    FieldDef::FUNC_ENUM("blob", 0, js_req_body_as, BODY_AS_BLOB as i16),
    FieldDef::FUNC_ENUM("formData", 0, js_req_body_as, BODY_AS_FORM_DATA as i16),
    FieldDef::FUNC_ENUM("textStream", 0, js_req_text_stream, 0),
    FieldDef::FUNC_ENUM("clone", 0, js_req_clone, 0),
    // WebIDL class string (`Object.prototype.toString` → "[object Request]").
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "Request",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "Request",
    JSRequest,
    RequestPayload,
    REQUEST_PROTO,
    // `call_as_func: false`: Request must be constructed with `new` (WPT
    // request-error "without new must throw").
    Some(ClassCtorDef::new(js_request_constructor, 1, false).expose_to_global())
);
