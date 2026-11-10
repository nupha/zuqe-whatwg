// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! HTTP response class.
//!
//! `Response` is the strict WHATWG class returned by `fetch()`. It exposes
//! the `Response` constructor, `error()` / `redirect()` / `json()` statics,
//! and the `Body` mixin. No aike extensions.

use std::{cell::RefCell, rc::Rc};

use zuqe::{
    CallContext, ClassCtorDef, FieldDef, JSResult, JSValue, ScopedContext, WriteBarrier,
    builtins::{json::JSON, promise::Promise},
    def_native_object,
    gc_lite::{GcTrace, GcTraceCtx},
};

use crate::{
    abort::signal_reason,
    fetch::{
        body::{
            BODY_AS_ARRAY_BUFFER, BODY_AS_BLOB, BODY_AS_BYTES, BODY_AS_FORM_DATA, BODY_AS_JSON,
            BODY_AS_TEXT, BodySource, blob_type_from_header, body_content_type, body_to_bytes,
            drain_body,
        },
        headers::{Guard, HeaderList, HeadersPayload, JSHeaders, header_list_from_js},
        request::reject_type_error_as_promise,
        transport::TransportResponse,
    },
    stream::JSReadableStream,
};

/// WHATWG `Response.type` (closed set of values this runtime produces).
/// `Error` / `OpaqueRedirect` / `Opaque` force `body` to null per spec.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum RespType {
    Basic,
    Cors,
    Default,
    Error,
    OpaqueRedirect,
    Opaque,
}

impl RespType {
    /// Spec string exposed via the `type` getter.
    fn as_str(self) -> &'static str {
        match self {
            RespType::Basic => "basic",
            RespType::Cors => "cors",
            RespType::Default => "default",
            RespType::Error => "error",
            RespType::OpaqueRedirect => "opaqueredirect",
            RespType::Opaque => "opaque",
        }
    }
}

pub(crate) struct ResponsePayload {
    /// Open network response for lazy body streaming (None once taken).
    resp: Option<reqwest::Response>,
    /// Transient holder for the body channel while it is being consumed.
    /// Each item is `Ok(bytes)` for a chunk or `Err(msg)` on a network failure.
    body_rx: Option<zuqe::WakeReceiver<Result<Vec<u8>, String>>>,
    /// Whether the body has begun consumption (enforces single-use).
    body_consumed: bool,

    /// Cached `ReadableStream` returned by `response.body` (same instance each
    /// access; locked once the body is consumed).
    pub(crate) cached_body: WriteBarrier<Option<JSReadableStream>>,
    /// Fixed body bytes for constructed (synthetic) responses.
    pub(crate) synthetic_body: Option<Vec<u8>>,

    /// `ReadableStream` passed to `new Response(stream)`; drained on consumption.
    ctor_stream: WriteBarrier<Option<JSReadableStream>>,

    /// WHATWG `Response.type`; see [`RespType`].
    resp_type: RespType,

    pub(crate) url: String,
    redirected: bool,
    pub(crate) status: u16,
    pub(crate) status_text: String,
    content_type: String,
    /// Shared live header list. The exposed `Headers` object references the
    /// same `Rc`, so user mutations via `response.headers.set()` are visible to
    /// body consumers (e.g. `blob()` type derivation).
    pub(crate) headers: Rc<RefCell<HeaderList>>,
    /// Cached `Headers` object returned by the `headers` getter ([SameObject]).
    headers_obj: WriteBarrier<Option<JSValue>>,
    /// Guard applied to the exposed `Headers`. Responses built by `fetch()` (or
    /// `Response.error()`) are immutable; ones built by user code use the
    /// "response" guard, which is mutable but drops forbidden response headers.
    headers_guard: Guard,
    content_length: Option<u64>,
    /// Negotiated HTTP version ("1.1", "2", …); empty for synthetic responses.
    http_version: &'static str,
    /// Abort signal tied to this response's fetch. When aborted mid-body, the
    /// body `ReadableStream` errors with the signal's reason (WHATWG Fetch: an
    /// abort rejects the in-flight `Response.body` reader). Kept alive for GC.
    signal: Option<JSValue>,
}

impl Default for ResponsePayload {
    fn default() -> Self {
        Self {
            resp: None,
            body_rx: None,
            body_consumed: false,
            cached_body: WriteBarrier::new(None),
            synthetic_body: None,
            ctor_stream: WriteBarrier::new(None),
            resp_type: RespType::Default,
            url: String::new(),
            redirected: false,
            status: 0,
            status_text: String::new(),
            content_type: String::new(),
            headers: Rc::new(RefCell::new(HeaderList::new())),
            headers_obj: WriteBarrier::new(None),
            headers_guard: Guard::Immutable,
            content_length: None,
            http_version: "",
            signal: None,
        }
    }
}

impl ResponsePayload {
    /// Keep JS-visible stream handles alive across GC while the body is held.
    fn gc_trace(&self, gcx: &mut GcTraceCtx) {
        if let Some(s) = self.cached_body.get() {
            s.trace(gcx);
        }
        if let Some(s) = self.ctor_stream.get() {
            JSValue::from(s).trace(gcx);
        }
        if let Some(h) = self.headers_obj.get() {
            h.trace(gcx);
        }
        if let Some(ref s) = self.signal {
            s.trace(gcx);
        }
    }

    /// The relevant body stream: the constructor-supplied stream (if present)
    /// over the lazily-cached `.body` stream. Borrows `self`.
    fn underlying_stream(&self) -> Option<JSReadableStream> {
        self.ctor_stream.get().or(self.cached_body.get())
    }

    /// Per fetch spec: `bodyUsed` is true once the body has been consumed OR
    /// its underlying stream is disturbed (read/cancelled). A merely-locked
    /// stream (getReader only) does NOT disturb.
    fn body_disturbed(&self) -> bool {
        self.underlying_stream()
            .is_some_and(|s| s.payload().is_some_and(|sp| sp.disturbed))
    }

    /// Whether the body cannot be re-consumed: already consumed, or its
    /// underlying stream is disturbed/locked by a previous reader.
    fn body_unusable(&self) -> bool {
        self.body_consumed
            || self.underlying_stream().is_some_and(|s| {
                s.payload()
                    .is_some_and(|sp| sp.disturbed || sp.reader.get().is_some())
            })
    }

    /// Start body streaming (lazily) and return a `BodySource`.
    /// Returns `None` if the body was already consumed or is unavailable.
    fn ensure_cached_body(&mut self, ctx: &mut ScopedContext) -> Option<BodySource> {
        if self.body_consumed {
            return None;
        }

        if let Some(resp) = self.resp.take() {
            let (tx, rx) = ctx.make_local_channel::<Result<Vec<u8>, String>>();
            self.body_rx = Some(rx);

            tokio::spawn(async move {
                use futures_util::StreamExt;

                let mut stream = resp.bytes_stream();

                while let Some(chunk) = stream.next().await {
                    match chunk {
                        Ok(bytes) => {
                            if tx.send(Ok(bytes.to_vec())).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            // An https body delimited by connection close: rustls
                            // rejects the missing `close_notify` with
                            // `UnexpectedEof`, which is this body's end, not a
                            // failure (see `is_tls_eof`).
                            if crate::fetch::body::is_tls_eof(&e) {
                                break;
                            }
                            // Signal the consumer that the body stream failed:
                            // the reader's read() promise must reject (TypeError).
                            // Carry the cause chain: the top-level reqwest
                            // message ("error decoding response body") hides the
                            // underlying hyper/io/TLS reason, which is exactly
                            // what is needed to tell a truncated body from a
                            // missing TLS `close_notify`.
                            let mut msg = format!("{e}");
                            let mut src = std::error::Error::source(&e);
                            while let Some(s) = src {
                                msg.push_str(&format!("; caused by: {s}"));
                                src = s.source();
                            }
                            let _ = tx.send(Err(msg));
                            break;
                        }
                    }
                }
            });
            Some(BodySource::Channel(self.body_rx.clone().unwrap()))
        } else if let Some(bytes) = self.synthetic_body.clone() {
            Some(BodySource::Synthetic(bytes))
        } else {
            self.ctor_stream.get().map(BodySource::Stream)
        }
    }
}

// Custom trace: traces GC-visible stream/header/signal handles; the payload holds
// non-GcTrace network/channel types (`reqwest::Response`, `WakeReceiver`) and
// shared header storage that are not traced as JS graph edges here.
impl GcTrace for ResponsePayload {
    fn trace(&self, gcx: &mut GcTraceCtx) {
        self.gc_trace(gcx);
    }
}

fn get_response_payload_mut<'a>(
    ctx: &mut ScopedContext,
    val: &'a mut JSValue,
) -> Result<&'a mut ResponsePayload, i32> {
    JSResponse::payload_mut_of(val)
        .ok_or_else(|| ctx.throw_type_error("not an http response object"))
}

fn get_response_payload<'a>(
    ctx: &mut ScopedContext,
    val: &'a JSValue,
) -> Result<&'a ResponsePayload, i32> {
    JSResponse::payload_of(val).ok_or_else(|| ctx.throw_type_error("not an http response object"))
}

/// Build an opaque-redirect `Response` (used for `redirect: "manual"`).
pub(crate) fn build_opaque_redirect_response(ctx: &mut ScopedContext, url: &str) -> JSResult {
    JSResponse::new_instance(
        ctx,
        JSValue::UNDEFINED,
        ResponsePayload {
            body_consumed: true,
            resp_type: RespType::OpaqueRedirect,
            url: url.to_string(),
            ..Default::default()
        },
    )
    .map(JSValue::from)
}

/// CORS-safelisted response headers exposed on an opaque filtered response
/// (Fetch spec §5.1.1). Non-safelisted headers (e.g. x-is-filtered) are dropped.
const CORS_SAFELISTED_HEADERS: &[&str] = &[
    "cache-control",
    "content-language",
    "content-length",
    "content-type",
    "expires",
    "last-modified",
    "pragma",
];

/// Build an opaque `Response` (used for a cross-origin `no-cors` fetch).
///
/// Per Fetch spec, an opaque response has `type="opaque"`, `status=0`,
/// `statusText=""`, `url=""`, a null body, and a header list filtered down to
/// the CORS-safelisted set. The real network body is dropped (`resp: None`).
pub(crate) fn build_opaque_response(ctx: &mut ScopedContext, tr: TransportResponse) -> JSResult {
    let headers: Vec<(String, String)> = tr
        .headers
        .into_iter()
        .filter(|(k, _)| {
            CORS_SAFELISTED_HEADERS
                .iter()
                .any(|h| h.eq_ignore_ascii_case(k))
        })
        .collect();
    let headers = Rc::new(RefCell::new(HeaderList::from_vec(headers)));

    JSResponse::new_instance(
        ctx,
        JSValue::UNDEFINED,
        ResponsePayload {
            body_consumed: true,
            resp_type: RespType::Opaque,
            headers,
            ..Default::default()
        },
    )
    .map(JSValue::from)
}

/// Build the shared payload from a [`TransportResponse`].
fn transport_payload(
    tr: TransportResponse,
    resp_type: RespType,
    url: &str,
    redirected: bool,
    signal: Option<JSValue>,
) -> ResponsePayload {
    ResponsePayload {
        resp: tr.resp,
        synthetic_body: tr.synthetic_body,
        resp_type,
        url: url.to_string(),
        redirected,
        status: tr.status,
        status_text: tr.status_text,
        content_type: tr.content_type,
        headers: Rc::new(RefCell::new(HeaderList::from_vec(tr.headers))),
        // Came off the network: headers are immutable.
        content_length: tr.content_length,
        http_version: tr.http_version,
        signal,
        ..Default::default()
    }
}

/// Build a plain WHATWG `Response` from a [`TransportResponse`] (fetch path).
pub(crate) fn build_response_from_transport(
    ctx: &mut ScopedContext,
    tr: TransportResponse,
    resp_type: RespType,
    url: &str,
    redirected: bool,
    signal: Option<JSValue>,
) -> JSResult {
    // An opaque response drops the real status/url/body and filters headers to
    // the CORS-safelisted set (Fetch spec §5.1.1).
    if resp_type == RespType::Opaque {
        return build_opaque_response(ctx, tr);
    }
    let payload = transport_payload(tr, resp_type, url, redirected, signal);
    JSResponse::new_instance(ctx, JSValue::UNDEFINED, payload).map(JSValue::from)
}

// ---------------------------------------------------------------------------
// Constructor: new Response(body?, init?)
// ---------------------------------------------------------------------------

fn js_response_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let new_target = cc.this();

    let mut synthetic: Option<Vec<u8>> = None;
    let mut ctor_stream: Option<JSReadableStream> = None;
    let mut status = 200u16;
    let mut status_text = String::new();
    let mut header_list = HeaderList::new();

    // Content-Type extracted from the body itself; an explicit `init.headers`
    // entry wins over it, so it is only applied after parsing init below.
    let mut ctor_content_type: Option<String> = None;

    // Init is parsed before the body so that an invalid status rejects even
    // when the body itself would also be invalid.
    if cc.length() > 1 {
        let init = cc.arg(1);
        if let Some(o) = init.as_object() {
            let s = o.get_property_str(ctx, "status")?;
            if !s.is_undefined() {
                let n = s.to_number(ctx)?.to_i32();
                if !(200..=599).contains(&n) {
                    return Err(ctx
                        .throw_range_error("Failed to construct 'Response': invalid status code"));
                }
                status = n as u16;
            }
            let st = o.get_property_str(ctx, "statusText")?;
            if !st.is_undefined() {
                let text = st.to_string(ctx)?.content().encode_utf8(false).to_string();
                // reason-phrase = *( HTAB / SP / VCHAR ), extended to the whole
                // Latin-1 range (0x80-0xFF) per the fetch spec's ByteString
                // statusText. 0x7F (DEL) and control chars (<= 0x1F) stay invalid.
                if !text.chars().all(|c| {
                    c == '\t'
                        || (' '..='\u{7E}').contains(&c)
                        || (c as u32) >= 0x80 && (c as u32) <= 0xFF
                }) {
                    return Err(
                        ctx.throw_type_error("Failed to construct 'Response': invalid status text")
                    );
                }
                status_text = text;
            }
            let mut h = o.get_property_str(ctx, "headers")?;
            if !h.is_undefined_or_null() {
                header_list = header_list_from_js(ctx, &mut h)?;
            }
        }
    }

    if cc.length() > 0 {
        let body_arg = cc.arg(0);
        if !body_arg.is_undefined_or_null() {
            // 204/205/304 are null-body statuses and cannot carry a body.
            if matches!(status, 204 | 205 | 304) {
                return Err(ctx.throw_type_error(
                    "Failed to construct 'Response': response with null body status cannot have body",
                ));
            }
            // A ReadableStream body must stay a stream; stringifying it would
            // silently produce "[object ReadableStream]".
            match JSReadableStream::try_from(body_arg) {
                Ok(s) => {
                    // A locked or already-read stream cannot become a body.
                    if s.payload()
                        .is_some_and(|p| p.reader.get().is_some() || p.disturbed)
                    {
                        return Err(ctx.throw_type_error(
                            "Failed to construct 'Response': body stream is locked or disturbed",
                        ));
                    }
                    ctor_stream = Some(s)
                }
                Err(_) => {
                    ctor_content_type = body_content_type(&body_arg);
                    synthetic = Some(body_to_bytes(ctx, &body_arg)?);
                }
            }
        }
    }
    if let Some(ct) = ctor_content_type
        && !header_list.has("content-type")
    {
        header_list.set("Content-Type", &ct);
    }

    JSResponse::new_instance(
        ctx,
        new_target,
        ResponsePayload {
            synthetic_body: synthetic,
            ctor_stream: WriteBarrier::new(ctor_stream),
            resp_type: RespType::Default,
            status,
            status_text,
            content_type: String::new(),
            headers: Rc::new(RefCell::new(header_list)),
            headers_guard: Guard::Response,
            ..Default::default()
        },
    )
    .map(JSValue::from)
}

// ---------------------------------------------------------------------------
// Statics: Response.error() / Response.redirect() / Response.json()
// ---------------------------------------------------------------------------

fn js_response_static_error(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    JSResponse::new_instance(
        ctx,
        JSValue::UNDEFINED,
        ResponsePayload {
            body_consumed: true,
            resp_type: RespType::Error,
            ..Default::default()
        },
    )
    .map(JSValue::from)
}

fn js_response_static_redirect(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() < 1 {
        return Err(ctx.throw_type_error("Response.redirect requires a url"));
    }
    let url = cc
        .arg(0)
        .to_string(ctx)?
        .content()
        .encode_utf8(false)
        .to_string();

    // Per WHATWG fetch, redirect() parses the url against the current base URL
    // and only throws TypeError when that fails. A relative url like "/" is
    // valid whenever a base exists, so resolve it the way fetch() does.
    let url = match url::Url::parse(&url) {
        Ok(u) => u,
        Err(_) => ctx
            .current_module_name()
            .and_then(|base| url::Url::parse(&base).ok())
            .and_then(|base| base.join(&url).ok())
            .ok_or_else(|| {
                ctx.throw_type_error("Failed to execute 'Response.redirect': invalid url")
            })?,
    }
    .to_string();

    let status = if cc.length() > 1 {
        let s = cc.arg(1).to_number(ctx)?.to_i32();
        if ![301, 302, 303, 307, 308].contains(&s) {
            return Err(
                ctx.throw_range_error("Response.redirect status must be 301, 302, 303, 307 or 308")
            );
        }
        s as u16
    } else {
        302
    };

    let mut list = HeaderList::new();
    list.set("Location", &url);

    JSResponse::new_instance(
        ctx,
        JSValue::UNDEFINED,
        ResponsePayload {
            // A redirect response has a *null* body, not a consumed one:
            // `.body` must be null and consumers resolve to the empty value.
            resp_type: RespType::Default,
            status,
            headers: Rc::new(RefCell::new(list)),
            headers_guard: Guard::Response,
            ..Default::default()
        },
    )
    .map(JSValue::from)
}

/// `Response.json(data, init?)` — creates a JSON response.
fn js_response_static_json(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut status = 200u16;
    let mut status_text = String::new();
    let mut header_list = HeaderList::new();

    if cc.length() > 1
        && let Some(o) = cc.arg(1).as_object()
    {
        let s = o.get_property_str(ctx, "status")?;
        if !s.is_undefined() {
            let n = s.to_number(ctx)?.to_i32();
            if !(200..=599).contains(&n) {
                return Err(ctx.throw_range_error("Response.json: invalid status code"));
            }
            // Response.json always has a body, so null-body statuses are invalid.
            if matches!(n, 204 | 205 | 304) {
                return Err(ctx.throw_type_error(
                    "Response.json: response with null body status cannot have body",
                ));
            }
            status = n as u16;
        }

        let st = o.get_property_str(ctx, "statusText")?;
        if !st.is_undefined() {
            status_text = st.to_string(ctx)?.content().encode_utf8(false).to_string();
        }

        let mut h = o.get_property_str(ctx, "headers")?;
        if !h.is_undefined_or_null() {
            header_list = header_list_from_js(ctx, &mut h)?;
        }
    }

    // Use the engine's JSON.stringify so spec behavior is inherited: it throws
    // on circular structures, propagates errors from getters/toJSON, and
    // escapes lone surrogates as \uXXXX.
    let json_val = JSON::stringify(ctx, cc.arg(0), JSValue::UNDEFINED, JSValue::UNDEFINED)?;
    // stringify returns undefined for non-encodable input (symbol, function);
    // Response.json requires a body, so that is a TypeError.
    let Some(s) = json_val.as_string(false) else {
        return Err(ctx.throw_type_error("Response.json: data is not JSON-serializable"));
    };
    let json_str = s.content().encode_utf8(false).to_string();

    if !header_list.has("content-type") {
        header_list.set("Content-Type", "application/json");
    }

    let body = json_str.into_bytes();
    JSResponse::new_instance(
        ctx,
        JSValue::UNDEFINED,
        ResponsePayload {
            synthetic_body: Some(body),
            resp_type: RespType::Default,
            status,
            status_text,
            content_type: "application/json".to_string(),
            headers: Rc::new(RefCell::new(header_list)),
            headers_guard: Guard::Response,
            ..Default::default()
        },
    )
    .map(JSValue::from)
}

// ---------------------------------------------------------------------------
// Spec property getters
// ---------------------------------------------------------------------------

const RESPONSE_GET_TYPE: i16 = 0;
const RESPONSE_GET_URL: i16 = 1;
const RESPONSE_GET_REDIRECTED: i16 = 2;
const RESPONSE_GET_STATUS: i16 = 3;
const RESPONSE_GET_OK: i16 = 4;
const RESPONSE_GET_STATUS_TEXT: i16 = 5;
const RESPONSE_GET_HEADERS: i16 = 8;
const RESPONSE_GET_BODY_USED: i16 = 9;

fn js_response_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let kind = cc.magic() as i16;
    let this = cc.this();
    let p = get_response_payload(ctx, &this)?;

    match kind {
        RESPONSE_GET_TYPE => ctx
            .create_string_from_utf8(p.resp_type.as_str().as_bytes().to_vec())
            .map(JSValue::make_string),
        RESPONSE_GET_URL => ctx
            .create_string_from_utf8(p.url.as_bytes().to_vec())
            .map(JSValue::make_string),
        RESPONSE_GET_REDIRECTED => Ok(JSValue::from(p.redirected)),
        RESPONSE_GET_STATUS => Ok(JSValue::from(p.status as i32)),
        RESPONSE_GET_OK => Ok(JSValue::from(p.status >= 200 && p.status < 300)),
        RESPONSE_GET_STATUS_TEXT => ctx
            .create_string_from_utf8(p.status_text.as_bytes().to_vec())
            .map(JSValue::make_string),
        RESPONSE_GET_HEADERS => {
            // [SameObject]: return the same Headers instance on every access.
            let mut this = cc.this();
            if let Some(h) = get_response_payload_mut(ctx, &mut this)?.headers_obj.get() {
                return Ok(h);
            }
            let (shared, guard) = {
                let p = get_response_payload(ctx, &this)?;
                (p.headers.clone(), p.headers_guard)
            };
            // Share the payload's live header list so mutations through the
            // exposed `Headers` object propagate back to body consumers.
            let payload = HeadersPayload::from_shared(shared, guard);
            let headers = JSHeaders::new_instance(ctx, JSValue::UNDEFINED, payload)?;
            let hv = headers.into();
            let owner = this;
            get_response_payload_mut(ctx, &mut this)?
                .headers_obj
                .set(ctx, owner, Some(hv));
            // The guard slot records the response→Headers barrier itself.
            Ok(hv)
        }
        RESPONSE_GET_BODY_USED => {
            // Per fetch spec, bodyUsed is true if the body has been consumed OR
            // its underlying stream is disturbed. For a Response built from a
            // ReadableStream, reading the *original* stream directly (via its
            // own reader) must also mark bodyUsed.
            Ok(JSValue::from(p.body_consumed || p.body_disturbed()))
        }
        _ => Err(ctx.throw_type_error("unknown Response getter")),
    }
}

fn js_response_body(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut this = cc.this();
    // Captured before `this` is mutably borrowed for the payload.
    let owner = this;

    // error / opaqueredirect / opaque have no body per spec.
    if matches!(
        get_response_payload_mut(ctx, &mut this)?.resp_type,
        RespType::Error | RespType::OpaqueRedirect | RespType::Opaque
    ) {
        return Ok(JSValue::NULL);
    }

    // Return the same cached stream instance on every access.
    if let Some(s) = get_response_payload(ctx, &this)?.cached_body.get() {
        return Ok(JSValue::from(s));
    }

    // A response constructed without a body has a null body per spec. This is
    // distinct from a consumed body, which stays non-null but disturbed.
    {
        let p = get_response_payload(ctx, &this)?;
        if !p.body_consumed
            && p.resp.is_none()
            && p.synthetic_body.is_none()
            && p.ctor_stream.get().is_none()
        {
            return Ok(JSValue::NULL);
        }
    }

    // First access (or access after consumption): build/disturb and cache.
    let stream = if get_response_payload_mut(ctx, &mut this)?.body_consumed {
        // A consumed body stays non-null but its getReader() must reject:
        // build an empty stream and lock it.
        let mut s = JSReadableStream::from_bytes(ctx, Vec::new())?;
        s.acquire_reader(ctx, false)?;
        s
    } else {
        // A constructor-supplied stream IS the body — expose it directly.
        if let Some(s) = get_response_payload_mut(ctx, &mut this)?.ctor_stream.get() {
            get_response_payload_mut(ctx, &mut this)?
                .cached_body
                .set(ctx, owner, Some(s));
            // The guard slot records the response→stream barrier itself.
            return Ok(JSValue::from(s));
        }
        let source = {
            let p = get_response_payload_mut(ctx, &mut this)?;
            if p.resp.is_some() || p.synthetic_body.is_some() {
                p.ensure_cached_body(ctx)
            } else {
                None
            }
        };
        match source {
            Some(BodySource::Channel(rx)) => {
                let signal = get_response_payload(ctx, &this)?.signal;
                JSReadableStream::from_channel(ctx, rx, signal)?
            }
            Some(BodySource::Synthetic(bytes)) => JSReadableStream::from_bytes(ctx, bytes)?,
            // Handled above by the ctor_stream early return.
            Some(BodySource::Stream(s)) => s,
            None => {
                // No source: body stays non-null but getReader() must reject.
                let mut s = JSReadableStream::from_bytes(ctx, Vec::new())?;
                s.acquire_reader(ctx, false)?;
                s
            }
        }
    };

    get_response_payload_mut(ctx, &mut this)?
        .cached_body
        .set(ctx, owner, Some(stream));
    // The guard slot records the response→stream barrier itself.
    Ok(JSValue::from(stream))
}

fn js_response_body_as(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let magic = cc.magic();
    let mut this = cc.this();

    let source = {
        let p = get_response_payload_mut(ctx, &mut this)?;

        // Spec (Fetch): consuming a body whose signal is already aborted must
        // reject with the signal's reason (e.g. an "AbortError"), not resolve.
        if let Some(sig) = p.signal.as_ref()
            && let Some(reason) = signal_reason(sig)
        {
            return Promise::from_reject_value(ctx, reason).map(JSValue::from);
        }

        // Spec: consuming a body whose stream is already disturbed or locked
        // must reject with TypeError. The stream may be the constructor-supplied
        // one or the cached `.body` stream handed out earlier.
        let unusable = p.body_unusable();

        // An opaque / error / opaque-redirect response has a null body per the
        // Fetch spec: `text()`/etc. resolve to the empty value rather than
        // rejecting. These set `body_consumed: true` at construction, so they
        // would otherwise trip the "unusable" rejection below.
        let null_body_type = matches!(
            p.resp_type,
            RespType::Error | RespType::OpaqueRedirect | RespType::Opaque
        );

        if null_body_type {
            p.body_consumed = true;
            Some(BodySource::Synthetic(Vec::new()))
        } else if unusable {
            None
        } else if p.resp.is_none()
            && p.synthetic_body.is_none()
            && p.ctor_stream.get().is_none()
            && p.cached_body.get().is_none()
        {
            // Null-body response (204/205/304, HEAD, or a synthetic response
            // built without a body that was never accessed as a stream):
            // consumers resolve to the empty value rather than rejecting.
            // `bodyUsed` is `body != null && body.stream.disturbed`, so a null
            // body stays undisturbed and repeated consumption keeps working.
            //
            // `cached_body` must be checked as well: the `.body` getter calls
            // ensure_cached_body(), which takes `resp` and moves the body into
            // the cached stream. Without it a network response whose `.body`
            // was merely touched would be misread as null-body and consumers
            // would resolve to "" instead of the real bytes.
            Some(BodySource::Synthetic(Vec::new()))
        } else {
            let src = if p.cached_body.get().is_some() && !p.body_consumed {
                // The `.body` getter already built the unique ReadableStream.
                // Per WHATWG fetch, body getters and consumers (text()/json()/
                // bytes()) must share that one stream; re-running
                // ensure_cached_body() would take the already-drained `resp`
                // and lose the body. Reuse the cached stream instance instead.
                p.cached_body.take().map(BodySource::Stream)
            } else {
                p.ensure_cached_body(ctx)
            };

            // Mark body as consumed only when consuming via text/json/bytes/etc.,
            // NOT via the .body getter (js_response_body).
            if src.is_some() {
                p.body_consumed = true;
                // Lock the cached .body stream (if any) so its getReader()
                // throws. Skip the constructor-supplied stream: drain_body
                // acquires that reader itself.
                let is_own_stream = matches!(
                    (p.cached_body.get(), p.ctor_stream.get()),
                    (Some(a), Some(b)) if a == b
                );
                if let Some(mut s) = p.cached_body.get()
                    && !is_own_stream
                {
                    // This closure returns a tuple (can't `?`); on a live
                    // cached body the lock won't fail, but if it does, drop
                    // the error rather than failing the consumer.
                    if s.acquire_reader(ctx, false).is_err() {
                        let exc = ctx.take_exception();
                        #[cfg(debug_assertions)]
                        crate::helpers::print_exc(ctx, exc);
                    }
                }
            }

            src
        }
    };

    // A null-body response (204/205/304/HEAD, or a synthetic response built
    // without a body that was never accessed as a stream) consumed as
    // `formData()` must reject per the Fetch spec when the `Content-Type` is
    // multipart/form-data — WPT "Consume response's body as formData with
    // correct multipart type (error case)". An `application/x-www-form-urlencoded`
    // null body still parses (to an empty FormData) and is allowed through.
    let is_null_body = {
        let p = JSResponse::payload_of(&this);
        matches!(p, Some(p) if p.resp.is_none()
            && p.synthetic_body.is_none()
            && p.ctor_stream.get().is_none()
            && p.cached_body.get().is_none()
            && !matches!(p.resp_type, RespType::Error | RespType::OpaqueRedirect | RespType::Opaque))
    };
    if magic == BODY_AS_FORM_DATA && is_null_body {
        let p = JSResponse::payload_of(&this);
        let ct = p
            .map(|p| p.headers.borrow().get("content-type").unwrap_or_default())
            .unwrap_or_default();
        if ct.to_ascii_lowercase().starts_with("multipart/form-data") {
            return reject_type_error_as_promise(ctx, "cannot parse null body as FormData");
        }
    }

    // Response.blob() sets the Blob's type to the response's *current*
    // Content-Type header (which the user may have mutated via `headers.set`),
    // with any parameters (e.g. charset) stripped. Resolve it once before
    // borrowing `source`, since the payload borrow below lives in a nested scope.
    let blob_type = {
        let p = JSResponse::payload_of(&this);
        match p {
            // formData() needs the *raw* Content-Type: the multipart boundary
            // lives in the parameters that blob_type_from_header strips.
            Some(p) if magic == BODY_AS_FORM_DATA => {
                p.headers.borrow().get("content-type").unwrap_or_default()
            }
            Some(p) => blob_type_from_header(&p.headers.borrow()),
            None => String::new(),
        }
    };

    // The owning request's `AbortSignal`, so a mid-read abort rejects with the
    // signal's reason rather than the cancellation's transport error.
    let signal = JSResponse::payload_of(&this).and_then(|p| p.signal);

    match source {
        Some(source) => drain_body(ctx, source, magic, blob_type, signal),
        // Spec: these methods always return a promise; a disturbed/locked or
        // already-consumed body rejects it rather than throwing synchronously.
        None => reject_type_error_as_promise(ctx, "body already consumed or unavailable"),
    }
}

/// `textStream()` — returns a `ReadableStream` of UTF-8-decoded string chunks.
/// Consumes the body (sets `bodyUsed`); a null-body response yields an empty
/// stream without marking the body used; a consumed or locked body throws.
fn js_response_text_stream(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    let mut this = _cc.this();
    let source = {
        let p = get_response_payload_mut(ctx, &mut this)?;
        // Consumed or locked body: textStream throws TypeError.
        if p.body_unusable() {
            return Err(ctx.throw_type_error("body already consumed or locked"));
        }
        // Null-body response (never had a body): empty stream, bodyUsed stays
        // false, callable repeatedly.
        if p.resp.is_none() && p.synthetic_body.is_none() && p.ctor_stream.get().is_none() {
            None
        } else {
            let src = if p.cached_body.get().is_some() && !p.body_consumed {
                p.cached_body.take().map(BodySource::Stream)
            } else {
                p.ensure_cached_body(ctx)
            };
            p.body_consumed = true;
            Some(src)
        }
    };
    match source {
        Some(Some(src)) => Ok(JSValue::from(JSReadableStream::from_text_source(ctx, src)?)),
        Some(None) => Err(ctx.throw_internal_error("failed to obtain body")),
        None => Ok(JSValue::from(JSReadableStream::from_text_source(
            ctx,
            BodySource::Synthetic(Vec::new()),
        )?)),
    }
}

fn js_response_clone(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut this = cc.this();
    // Captured before `this` is mutably borrowed for the payload.
    let owner = this;
    // A body cannot be copied, so the spec tees it: this response keeps one
    // branch and the clone gets the other. The source stream is materialized
    // here (constructor stream, network channel, or synthetic buffer) because
    // only one of the two responses may own it.
    let branches: Option<[JSReadableStream; 2]> = {
        let p = get_response_payload_mut(ctx, &mut this)?;
        if p.body_consumed {
            return Err(
                ctx.throw_type_error("Cannot clone a Response whose body has already been used")
            );
        }
        let source: Option<JSReadableStream> = if let Some(cs) = p.ctor_stream.get() {
            Some(cs)
        } else if p.resp.is_some() || p.synthetic_body.is_some() {
            match p.ensure_cached_body(ctx) {
                Some(BodySource::Channel(rx)) => {
                    Some(JSReadableStream::from_channel(ctx, rx, None)?)
                }
                Some(BodySource::Synthetic(bytes)) => {
                    Some(JSReadableStream::from_bytes(ctx, bytes)?)
                }
                Some(BodySource::Stream(s)) => Some(s),
                None => {
                    return Err(ctx.throw_type_error("Cannot clone a Response with no body source"));
                }
            }
        } else {
            // A null-body response clones to a null body.
            None
        };

        if let Some(mut stream) = source {
            let mut reader = stream.acquire_reader(ctx, false)?;
            let b = reader.tee(ctx)?;
            // The tee owns the source now, so this response must not also build
            // a body from the underlying response/buffer.
            p.ctor_stream.set(ctx, owner, Some(b[0]));
            p.resp = None;
            p.synthetic_body = None;
            p.body_rx = None;
            let _ = p.cached_body.take();
            // The guard slot records the response→tee branch barrier itself.
            Some(b)
        } else {
            None
        }
    };

    let src = get_response_payload_mut(ctx, &mut this)?;
    let payload = ResponsePayload {
        resp: None,
        body_rx: None,
        body_consumed: false,
        cached_body: WriteBarrier::new(None),
        synthetic_body: None,
        ctor_stream: WriteBarrier::new(branches.map(|b| b[1])),
        resp_type: src.resp_type,
        url: src.url.clone(),
        redirected: src.redirected,
        status: src.status,
        status_text: src.status_text.clone(),
        content_type: src.content_type.clone(),
        // A cloned response owns an independent header set, not the shared one.
        headers: Rc::new(RefCell::new(src.headers.borrow().clone())),
        headers_obj: WriteBarrier::new(None),
        headers_guard: src.headers_guard,
        content_length: src.content_length,
        http_version: src.http_version,
        signal: src.signal,
    };
    JSResponse::new_instance(ctx, cc.this(), payload).map(JSValue::from)
}

// Strict WHATWG prototype — no aike extensions.
const RESPONSE_PROTO: &[FieldDef] = &[
    FieldDef::GETSET_ENUM("type", Some(js_response_getter), None, RESPONSE_GET_TYPE),
    FieldDef::GETSET_ENUM("url", Some(js_response_getter), None, RESPONSE_GET_URL),
    FieldDef::GETSET_ENUM(
        "redirected",
        Some(js_response_getter),
        None,
        RESPONSE_GET_REDIRECTED,
    ),
    FieldDef::GETSET_ENUM(
        "status",
        Some(js_response_getter),
        None,
        RESPONSE_GET_STATUS,
    ),
    FieldDef::GETSET_ENUM("ok", Some(js_response_getter), None, RESPONSE_GET_OK),
    FieldDef::GETSET_ENUM(
        "statusText",
        Some(js_response_getter),
        None,
        RESPONSE_GET_STATUS_TEXT,
    ),
    FieldDef::GETSET_ENUM(
        "headers",
        Some(js_response_getter),
        None,
        RESPONSE_GET_HEADERS,
    ),
    FieldDef::GETSET_ENUM(
        "bodyUsed",
        Some(js_response_getter),
        None,
        RESPONSE_GET_BODY_USED,
    ),
    FieldDef::GETSET_ENUM("body", Some(js_response_body), None, 0),
    FieldDef::FUNC_ENUM("bytes", 0, js_response_body_as, BODY_AS_BYTES as i16),
    FieldDef::FUNC_ENUM("text", 0, js_response_body_as, BODY_AS_TEXT as i16),
    FieldDef::FUNC_ENUM("json", 0, js_response_body_as, BODY_AS_JSON as i16),
    FieldDef::FUNC_ENUM(
        "arrayBuffer",
        0,
        js_response_body_as,
        BODY_AS_ARRAY_BUFFER as i16,
    ),
    FieldDef::FUNC_ENUM("blob", 0, js_response_body_as, BODY_AS_BLOB as i16),
    FieldDef::FUNC_ENUM("formData", 0, js_response_body_as, BODY_AS_FORM_DATA as i16),
    FieldDef::FUNC_ENUM("textStream", 0, js_response_text_stream, 0),
    FieldDef::FUNC_ENUM("clone", 0, js_response_clone, 0),
    // WebIDL class string (`Object.prototype.toString` → "[object Response]").
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "Response",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

const RESPONSE_STATIC_ENTRIES: &[FieldDef] = &[
    FieldDef::FUNC_ENUM("error", 0, js_response_static_error, 0),
    FieldDef::FUNC_ENUM("redirect", 2, js_response_static_redirect, 0),
    FieldDef::FUNC_ENUM("json", 2, js_response_static_json, 0),
];

def_native_object!(
    "Response",
    JSResponse,
    ResponsePayload,
    RESPONSE_PROTO,
    Some(
        // WebIDL: `constructor(optional BodyInit? body = null, optional
        // ResponseInit init = {})` — no required argument, so `.length` is 0.
        ClassCtorDef::new(js_response_constructor, 0, true)
            .entries(RESPONSE_STATIC_ENTRIES)
            .expose_to_global()
    )
);
