// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

use std::{cell::RefCell, rc::Rc, time::Duration};

use zuqe::{
    CallContext, Callback, Exception, JSResult, JSValue, JobState, NativeObject, Object,
    ScopedContext,
    builtins::promise::{Promise, PromiseResultSlot},
};

use crate::fetch::{
    body::{BODY_TIMEOUT, body_content_type, body_to_bytes},
    headers::{HeaderList, JSHeaders, header_list_from_js, validate_header_list_for_fetch},
    request::{
        JSRequest, get_request_payload_mut, normalize_method, validate_request_init_options,
    },
    response::{
        JSResponse, RespType, build_opaque_redirect_response, build_response_from_transport,
    },
    transport::{
        ReferrerCtx, TransportError, TransportRequest, TransportResponse, perform_request_retrying,
        throw_transport_error,
    },
};

// The HTTP response cache, compiled in only with the `fetch_cache` feature;
// every read/write below is gated the same way.
#[cfg(feature = "fetch_cache")]
use crate::fetch::cache as http_cache;

use crate::{
    abort::{JSAbortSignal, signal_is_aborted, signal_notify, signal_reason},
    aike::AikeRuntimeState,
    dom::make_dom_exception,
    stream::JSReadableStream,
};

use super::{
    cors::{
        PreflightCtx, append_fetch_metadata_headers, check_allow_origin, corp_violation,
        cors_check, cors_filter_response_headers, is_cross_origin, join_request_headers,
        make_before_hop_hook, needs_preflight, preflight_request_headers, same_origin_violation,
        serialized_origin, should_append_origin,
    },
    integrity::check_integrity,
    origin::resolve_client_origin,
    referrer::compute_request_referrer,
};

/// Error type carried through the fetch result slot.
enum FetchError {
    /// Aborted via `AbortSignal` (or pre-aborted signal).
    Abort,
    /// Any other failure (network, redirect, timeout, ...).
    Other(TransportError),
}

/// `fetch(input, init)` → `Promise<Response>`
///
/// Per the Fetch spec `fetch()` never throws synchronously: request-construction
/// failures (bad URL, invalid header, ...) must surface as a rejected promise.
/// `fetch_impl` does the real work and may throw; here we catch a pending
/// exception and convert it into a rejection.
pub(crate) fn js_fetch(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    match fetch_impl(ctx, cc) {
        Ok(v) => Ok(v),
        Err(e) => {
            // Turn the in-flight exception into a rejected promise.
            let Exception::Error(reason) = ctx.take_exception() else {
                // Nothing retrievable (e.g. stack overflow): propagate as-is.
                return Err(e);
            };
            let (mut promise, _funcs) = Promise::create(ctx)?;
            promise.reject(ctx, reason);
            Ok(promise.into())
        }
    }
}

fn fetch_impl(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let input = cc.arg(0);
    let init = if cc.length() > 1 {
        cc.arg(1)
    } else {
        JSValue::UNDEFINED
    };

    let mut url_str = String::new();
    let mut method = String::from("GET");
    let mut header_list = HeaderList::new();
    let mut body_bytes: Option<Vec<u8>> = None;
    // A `ReadableStream` body, held until it can be pumped to bytes below.
    let mut stream_body: Option<JSValue> = None;
    let mut redirect = String::from("follow");
    // No total cap by default (browsers impose none); `timeout` opts in.
    let mut timeout: Option<Duration> = None;

    // RequestInit fields used for client config.
    let mut credentials = String::from("same-origin");
    let mut referrer = String::from("about:client");
    let mut referrer_policy = String::from("");
    let mut integrity = String::new();
    // Fetch spec default request mode is "cors"; "no-cors" produces an opaque
    // response for cross-origin fetches.
    let mut mode = String::from("cors");
    let mut signal_val: Option<JSValue> = None;
    // Fetch spec request `cache` mode: default | no-store | reload | no-cache |
    // force-cache | only-if-cached. Drives HTTP cache reuse/revalidation.
    let mut cache_mode = String::from("default");

    // Inherit from a Request input.
    if let Some(p) = JSRequest::payload_of(&input) {
        url_str = p.url.clone();
        method = p.method.clone();
        header_list = p.headers.borrow().clone();
        redirect = p.redirect.clone();
        signal_val = p.signal;
        body_bytes = p.synthetic_body.clone();
        // Consuming an input Request's body marks it used (Fetch spec):
        // subsequent body methods on it must reject with TypeError. A null-body
        // request stays unconsumed (bodyUsed remains false), matching WPT's
        // "aborted consumed empty request" cases.
        let input_has_body = p.synthetic_body.is_some() || p.stream_body.is_some();
        credentials = p.credentials.clone();
        referrer = p.referrer.clone();
        mode = p.mode.clone();
        cache_mode = p.cache.clone();
        if input_has_body && let Ok(p) = get_request_payload_mut(ctx, &mut input.clone()) {
            p.body_consumed = true;
        }
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
    // Fetch spec: the request URL is serialized "with the exclude fragment
    // flag set" — the fragment is never sent and never appears in
    // `response.url`. Parsing also normalizes the URL (e.g. an empty path
    // becomes "/"). Leave unparsable URLs alone so the transport reports them.
    if let Ok(mut u) = url::Url::parse(&url_str) {
        u.set_fragment(None);
        url_str = u.to_string();
    } else if let Some(base) = ctx.current_module_name() {
        // Relative specifier: resolve against the current module's base URL
        // (the value behind `import.meta.url`, set by `aike.evalModule`),
        // mirroring Node/Bun semantics. `None` when not inside a script/module
        // frame, in which case the specifier stays as-is.
        if let Ok(base_u) = url::Url::parse(&base)
            && let Ok(joined) = base_u.join(&url_str)
        {
            let mut u = joined;
            u.set_fragment(None);
            url_str = u.to_string();
        }
    }

    // Apply RequestInit overrides.
    if let Some(o) = init.as_object() {
        // `window` may only be null (forbidden legacy option). Any other
        // value throws a TypeError, and it must take priority over an
        // already-aborted signal (WPT "TypeError from request constructor
        // takes priority"). Mirrors `js_request_constructor`.
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
        // `duplex` must be read whenever a body is present: the spec reads
        // it off the init dictionary, and a stream body requires it to be
        // "half". Read it before `body` so a throwing getter still fires.
        let duplex = o.get_property_str(ctx, "duplex")?;
        let duplex = match duplex.is_undefined() {
            true => None,
            false => Some(
                duplex
                    .to_string(ctx)?
                    .content()
                    .encode_utf8(false)
                    .to_string(),
            ),
        };

        let b = o.get_property_str(ctx, "body")?;
        if !b.is_undefined_or_null() {
            // Fetch spec: a GET/HEAD request must not carry a body.
            if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") {
                return Err(ctx.throw_type_error("Request with GET/HEAD method cannot have body"));
            }

            // The body source implies a default Content-Type unless the
            // caller already supplied one.
            if let Some(t) = body_content_type(&b)
                && !header_list.has("content-type")
            {
                header_list.set("Content-Type", &t);
            }

            match JSReadableStream::payload_of(&b).is_some() {
                // A stream body is only allowed with `duplex: "half"`;
                // omitting it is a TypeError so that code written against
                // full-duplex semantics fails loudly instead of silently
                // buffering.
                true if duplex.as_deref() != Some("half") => {
                    return Err(ctx.throw_type_error(
                        "Request body is a ReadableStream but duplex is not 'half'",
                    ));
                }
                true => stream_body = Some(b),
                false => body_bytes = Some(body_to_bytes(ctx, &b)?),
            }
        }

        let r = o.get_property_str(ctx, "redirect")?;
        if !r.is_undefined() {
            redirect = r.to_string(ctx)?.content().encode_utf8(false).to_string();
        }

        // Per Fetch spec, an *explicit* `signal: null` in the init clears any
        // signal inherited from the input Request; an absent `signal` key
        // leaves the inherited signal in place.
        let s = o.get_property_str(ctx, "signal")?;
        if s.is_undefined() {
            // Key absent: keep the inherited signal.
        } else if s.is_null() {
            signal_val = None;
        } else if JSAbortSignal::from_value(s).is_some() {
            signal_val = Some(s);
        }

        let t = o.get_property_str(ctx, "timeout")?;
        if !t.is_undefined() {
            let secs = t.to_number(ctx)?.to_f64();
            if secs > 0.0 {
                timeout = Some(Duration::from_secs_f64(secs));
            }
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
        if let Some(v) = read_str(o, "credentials")? {
            credentials = v;
        }
        if let Some(v) = read_str(o, "referrer")? {
            referrer = v;
        }
        if let Some(v) = read_str(o, "referrerPolicy")? {
            referrer_policy = v;
        }
        if let Some(v) = read_str(o, "integrity")? {
            integrity = v;
        }
        if let Some(v) = read_str(o, "mode")? {
            mode = v;
        }
        if let Some(v) = read_str(o, "cache")? {
            cache_mode = v;
        }
        // Validate `priority` eagerly: an invalid RequestInit member value
        // must reject the fetch with a TypeError (WPT request-init-priority).
        // The valid set is `high` | `low` | `auto`; `high`/`low` are accepted
        // as hints and otherwise ignored, `auto` is the effective default.
        if let Some(v) = read_str(o, "priority")? {
            const VALID: &[&str] = &["high", "low", "auto"];
            if !VALID.contains(&v.as_str()) {
                return Err(
                    ctx.throw_type_error(&format!("invalid value '{v}' for RequestInit.priority"))
                );
            }
        }
    }

    // Browser-security semantics are a compile-time decision: with the
    // `fetch_cors_cookie` feature both are always enforced (WPT builds);
    // without it both compile out and fetch is a plain HTTP client. There is
    // no runtime switch.
    #[cfg(feature = "fetch_cors_cookie")]
    let (fetch_cors, fetch_cookie) = (true, true);
    #[cfg(not(feature = "fetch_cors_cookie"))]
    let (fetch_cors, fetch_cookie) = (false, false);

    let notify = signal_val.as_ref().and_then(signal_notify);
    let already_aborted = signal_val.as_ref().is_some_and(signal_is_aborted);
    // When the signal is (already) aborted the fetch must reject with the
    // signal's `reason` (e.g. a DOMException "AbortError"), matching the Fetch
    // spec and WPT's `promise_rejects_exactly`/`promise_rejects_dom`.
    let abort_reason = signal_val
        .as_ref()
        .and_then(signal_reason)
        .unwrap_or_else(|| {
            make_dom_exception(ctx, "AbortError", "The operation was aborted.")
                .unwrap_or(JSValue::UNDEFINED)
        });

    // Client origin/URL for same-origin checks (used by the cache
    // short-circuit and the response handler below). In a browser this is the
    // document's origin; resolved from the `self.location` shim / WPT runner
    // globals. Server builds (`fetch_cors_cookie` off) have no location concept
    // and get a null origin.
    let (mut client_origin, mut client_url) = resolve_client_origin(ctx);

    // Without the feature there is no client-origin concept: fetch behaves
    // like a plain HTTP client (no CORS taint, no same-origin referrer).
    if !(fetch_cors || fetch_cookie) {
        client_origin = None;
        client_url = None;
    }
    // No client origin → `same-origin` cookie scoping cannot be evaluated;
    // treat it like `include` so cookies still flow.
    if client_origin.is_none() && credentials == "same-origin" {
        credentials = String::from("include");
    }


    // CORS tainting: a cross-origin request in `cors` mode. These require
    // origin/ACAO handling and (for non-safelisted requests) a preflight.
    // Computed up front so the response callback (created below) can reference
    // it and the async side can run the preflight.
    let cors_tainted =
        fetch_cors && mode == "cors" && is_cross_origin(client_origin.as_deref(), &url_str);
    // Whether `Access-Control-Allow-Credentials` must be present (fetch
    // `credentials: "include"`).
    let credentials_include = credentials == "include";

    // HTTP cache (§ Fetch HTTP-cache). The request's `cache` mode decides
    // whether we serve straight from cache, revalidate, or always hit network:
    //   default      fresh hit → serve cache; stale hit → revalidate
    //   no-store     always network, never read/write cache
    //   reload       always network (force re-fetch), then re-store
    //   no-cache     always revalidate via conditional headers
    //   force-cache  serve cache hit regardless of freshness; else network
    //   only-if-cached  serve cache hit; a miss is a network error
    // The short-circuit below runs before the network request is issued, so a
    // fresh hit (or `force-cache`) never touches the transport.

    // Is this request cacheable at all (GET, no body)? Every cache read below is
    // compiled in only with the `fetch_cache` feature; without it each request
    // goes to the network and the `cache` option has no effect.
    #[cfg(feature = "fetch_cache")]
    let cacheable =
        method.eq_ignore_ascii_case("GET") && body_bytes.is_none() && stream_body.is_none();

    // A request carrying any conditional header (`If-None-Match`,
    // `If-Modified-Since`, `If-Unmodified-Since`, `If-Match`, `If-Range`) is
    // treated as `no-store`: it bypasses the cache (WPT
    // request-cache-default-conditional).
    // The request's header list as the cache sees it (pre-transport): it drives
    // the lookups below and selects the stored `Vary` variant on both store and
    // revalidation, so all three must use the same list.
    #[cfg(feature = "fetch_cache")]
    let cache_req_headers = header_list.to_vec();
    #[cfg(feature = "fetch_cache")]
    let has_conditional = cacheable && http_cache::caller_supplied_validator(&cache_req_headers);
    // Without the feature there is no cache, so no caller header can be a
    // "conditional" one as far as this layer is concerned.
    #[cfg(not(feature = "fetch_cache"))]
    let has_conditional = false;

    // Serve-from-cache hit for the modes that can return without a network call.
    #[cfg(feature = "fetch_cache")]
    let cache_hit = if cacheable && !has_conditional {
        match cache_mode.as_str() {
            "default" => {
                http_cache::lookup_full(&method, &url_str, &cache_req_headers).filter(|h| h.fresh)
            }
            "force-cache" | "only-if-cached" => {
                http_cache::lookup_full(&method, &url_str, &cache_req_headers)
            }
            _ => None,
        }
    } else {
        None
    };

    // RFC 5861: with `default` caching, a stale entry carrying
    // `stale-while-revalidate` may be served as-is; the network request below
    // doubles as its revalidation (the transport stores the fresh response).
    #[cfg(feature = "fetch_cache")]
    let swr_hit = if cacheable && !has_conditional && cache_hit.is_none() && cache_mode == "default"
    {
        http_cache::lookup_full(&method, &url_str, &cache_req_headers).filter(|h| h.swr)
    } else {
        None
    };
    // `only-if-cached` with no cached entry is a network error (TypeError).
    #[cfg(feature = "fetch_cache")]
    let no_cache_entry = cache_mode == "only-if-cached" && cache_hit.is_none();
    // Without the `fetch_cache` feature nothing is ever cached, so every
    // `only-if-cached` request misses.
    #[cfg(not(feature = "fetch_cache"))]
    let no_cache_entry = cache_mode == "only-if-cached";

    if no_cache_entry {
        return throw_transport_error(
            ctx,
            TransportError {
                code: "other",
                message: "only-if-cached: no cached response for the request URL".into(),
            },
        );
    }


    #[cfg(feature = "fetch_cache")]
    if let Some(hit) = cache_hit {
        // `only-if-cached` requires `mode: "same-origin"`; if the cached
        // response came from a cross-origin redirect, same-origin mode makes it
        // a network error (WPT request-cache-only-if-cached cross-origin).
        if cache_mode == "only-if-cached" && mode == "same-origin" {
            let hit_origin = url::Url::parse(&hit.final_url)
                .ok()
                .map(|u| u.origin().ascii_serialization());
            let same = match (&client_origin, &hit_origin) {
                (Some(c), Some(h)) => c == h,
                _ => false,
            };
            if !same {
                return throw_transport_error(
                    ctx,
                    TransportError {
                        code: "other",
                        message: "only-if-cached: cached response is cross-origin".into(),
                    },
                );
            }
        }
        let response = build_response_from_transport(
            ctx,
            TransportResponse {
                status: hit.status,
                status_text: "OK".to_string(),
                headers: hit.headers,
                content_type: String::new(),
                content_length: Some(hit.body.len() as u64),
                http_version: "1.1",
                resp: None,
                final_url: hit.final_url.clone(),
                synthetic_body: Some(hit.body),
                origin_opaque: false,
            },
            RespType::Basic,
            &hit.final_url,
            false,
            signal_val,
        )?;

        // `fetch()` returns a promise; resolve it with the cached Response.
        return Promise::from_resolve_value(ctx, response).map(JSValue::from);
    }


    // RFC 9111 §3.3: a stored *incomplete* (`206`) response cannot be served
    // for a request for the complete resource, but the fetch is completed by
    // forwarding a request for the missing remainder (a `Range` for everything
    // after the stored prefix). The caller's own `Range` takes precedence.
    #[cfg(feature = "fetch_cache")]
    if cacheable
        && !has_conditional
        && !header_list.has("range")
        && matches!(cache_mode.as_str(), "default" | "force-cache")
        && let Some(range) =
            http_cache::partial_remainder_range(&method, &url_str, &cache_req_headers)
    {
        header_list.set("Range", &range);
    }

    // RFC 9111 §5.2.1.7: a request carrying `Cache-Control: only-if-cached`
    // that misses the cache must yield a `504 Gateway Timeout` rather than
    // reaching the network. (Distinct from the `cache: "only-if-cached"` *init
    // option*, which the Fetch spec turns into a network error above.)
    #[cfg(feature = "fetch_cache")]
    if header_list
        .get("cache-control")
        .is_some_and(|v| v.to_ascii_lowercase().contains("only-if-cached"))
    {
        let response = build_response_from_transport(
            ctx,
            TransportResponse {
                status: 504,
                status_text: "Gateway Timeout".to_string(),
                headers: Vec::new(),
                content_type: String::new(),
                content_length: Some(0),
                http_version: "1.1",
                resp: None,
                final_url: url_str.clone(),
                synthetic_body: Some(Vec::new()),
                origin_opaque: false,
            },
            RespType::Basic,
            &url_str,
            false,
            signal_val,
        )?;
        return Promise::from_resolve_value(ctx, response).map(JSValue::from);
    }

    // `blob:` scheme: resolve the object URL against the global blob store
    // populated by `URL.createObjectURL`. A revoked or unknown blob URL is a
    // network error; a valid one yields a basic 200 response carrying the
    // blob's bytes and MIME type (WPT `scheme-blob.sub.any.js`).
    //
    // Fetch spec (blob scheme fetch) only performs the fetch for a GET request;
    // any other method is a network error (TypeError). So reject non-GET
    // methods before touching the store (WPT `scheme-blob.sub.any.js` expects
    // POST/OPTIONS/HEAD/PUT/DELETE/INVALID on a blob: URL to reject).
    if url_str.starts_with("blob:") {
        if !method.eq_ignore_ascii_case("GET") {
            return throw_transport_error(
                ctx,
                TransportError {
                    code: "method",
                    message: "Failed to fetch: blob: URLs only support GET".into(),
                },
            );
        }

        match crate::url::blob_store_get(&url_str) {
            Some(blob) => {
                let all = blob.bytes().to_vec();
                let mime = blob.type_().to_string();
                // A `Range` header selects a 206 slice of the blob (WPT `range/blob`).
                let (status, status_text, mut headers, bytes) =
                    match header_list.get("range").as_deref() {
                        None => (200, "OK", Vec::new(), all),
                        Some(range) => {
                            let size = all.len() as u64;
                            let Some((start, end)) = parse_blob_range(range, size) else {
                                return throw_transport_error(
                                    ctx,
                                    TransportError {
                                        code: "other",
                                        message: "Failed to fetch: invalid blob Range".into(),
                                    },
                                );
                            };
                            let slice = all[start as usize..=end as usize].to_vec();
                            let content_range = format!("bytes {start}-{end}/{size}");
                            (
                                206,
                                "Partial Content",
                                vec![("Content-Range".to_string(), content_range)],
                                slice,
                            )
                        }
                    };
                headers.push(("Content-Type".to_string(), mime.clone()));
                headers.push(("Content-Length".to_string(), bytes.len().to_string()));
                let response = build_response_from_transport(
                    ctx,
                    TransportResponse {
                        status,
                        status_text: status_text.to_string(),
                        headers,
                        content_type: mime,
                        content_length: Some(bytes.len() as u64),
                        http_version: "1.1",
                        resp: None,
                        final_url: url_str.clone(),
                        synthetic_body: Some(bytes),
                        origin_opaque: false,
                    },
                    RespType::Basic,
                    &url_str,
                    false,
                    signal_val,
                )?;

                return Promise::from_resolve_value(ctx, response).map(JSValue::from);
            }
            None => {
                return throw_transport_error(
                    ctx,
                    TransportError {
                        code: "other",
                        message: "Failed to fetch: unknown blob URL".into(),
                    },
                );
            }
        }
    }

    let result_slot = PromiseResultSlot::<Result<TransportResponse, FetchError>>::new();
    // Look up cached validators before issuing the request so the conditional
    // headers ride on the outgoing request and the `cache_driven` flag (copied
    // into the response closure below) reflects *our* revalidation.
    // `no-store`/`reload` never attach revalidation validators (they go to
    // network unconditionally); `default` stale and `no-cache` revalidate.
    let revalidate = !matches!(cache_mode.as_str(), "no-store" | "reload");
    // A conditional-header request is treated as no-store: no revalidation
    // validators are added on top of the caller's own conditional headers.
    #[cfg(feature = "fetch_cache")]
    let cached_validators = if cacheable && revalidate && !has_conditional {
        http_cache::lookup_validators(&method, &url_str, &header_list.to_vec())
    } else {
        None
    };
    #[cfg(not(feature = "fetch_cache"))]
    let cached_validators: Option<(Option<String>, Option<String>)> = None;
    // Only treat a `304` as cache-driven (to be turned into the cached
    // response) when *we* added the validators — if the caller supplied them
    // the `304` is theirs and must be passed through unchanged.
    let cache_driven = cached_validators.is_some() && !has_conditional;
    let url_clone = url_str.clone();
    let redirect_clone = redirect.clone();
    let method_clone = method.clone();
    // Whether the request body was a streaming (non-replayable) ReadableStream.
    // Captured into the result closure for the 401/407 auth-entry rejection.
    let had_stream_body = stream_body.is_some();
    // Credentials mode, cloned *before* the `move` closure so the original
    // `credentials` stays available for later use (e.g. validate_request_init).
    let credentials_clone = credentials.clone();
    let mode_clone = mode.clone();

    // Compute the outgoing Referer value per the Fetch `referrer`/`referrerPolicy`
    // algorithm. Covers the policies exercised by WPT `referrer.any.js`:
    // `origin-when-cross-origin` and the default (`client`-resolved) policy, plus
    // explicit `referrer` values with their credentials/fragment stripped.
    let effective_referrer = compute_request_referrer(
        &referrer,
        &referrer_policy,
        client_origin.as_deref(),
        client_url.as_deref(),
        &url_str,
    )
    .unwrap_or_default();

    // The probing above intentionally tolerates missing properties; clear any
    // exception it may have left behind so the caller does not observe a stale
    // pending error. (In practice the probe returns Ok/None and there is none.)
    let exc = ctx.take_exception();
    #[cfg(debug_assertions)]
    crate::helpers::print_exc(ctx, exc);

    // Clone the client origin for request-header injection; the original is
    // moved into the response callback closure below.
    let req_origin = client_origin.clone();

    // Same reason: keep a copy of the referrer-policy inputs for the transport,
    // which recomputes the header on each redirect hop.
    let rc_origin = client_origin.clone();
    let rc_url = client_url.clone();
    let rc_referrer = referrer.clone();
    let rc_policy = referrer_policy.clone();

    // Argument validation (method/mode/cache/referrer etc.) must take priority
    // over an already-aborted signal: WPT "TypeError from request constructor
    // takes priority" expects the `TypeError` to surface before the `AbortError`.
    // This must run before the result-slot promise/job below is created: a throw
    // here (or in the aborted-signal early return) must not leave a polling job
    // waiting forever on a slot that is never committed, which would keep the
    // event loop alive after the script finished.
    validate_request_init_options(
        ctx,
        &url_str,
        &method,
        &mode,
        &cache_mode,
        &credentials,
        &redirect,
        &referrer,
        &referrer_policy,
    )?;

    if already_aborted {
        // An already-aborted signal must reject on a microtask, *before* any
        // `Promise.resolve().then` callback (WPT "already aborted signal rejects
        // immediately"). Skip the thread/event-loop hop and reject synchronously
        // as a (microtask) job via the promise machinery.
        // Consuming a Request whose signal is already aborted marks its body as
        // used (Fetch spec): `request.bodyUsed` must become true.
        if JSRequest::from_value(input).is_some()
            && let Ok(p) = get_request_payload_mut(ctx, &mut input.clone())
        {
            p.body_consumed = true;
        }
        return Promise::from_reject_value(ctx, abort_reason).map(JSValue::from);
    }

    // Runtime TLS escape hatch: `fetch.allowInsecureTLS` skips cert validation
    // for this request's client.
    let insecure = AikeRuntimeState::of(ctx).fetch_allow_insecure_tls;

    // Fetch spec "HTTP defaults": a request carries default `Accept` and
    // `Accept-Language` headers unless the caller overrides them. reqwest's
    // own defaults are wiped by `perform_request` (it sets each header
    // explicitly), so we must supply them here.
    ensure_default_request_headers(&mut header_list);
    // WHATWG: silently drop forbidden request headers the caller tried to set.
    // The cookie headers are only forbidden when fetch owns the cookie jar —
    // i.e. in `fetch_cors_cookie` builds; lean builds leave `Cookie`/`Cookie2`
    // under the caller's control.
    strip_forbidden_request_headers(&mut header_list, fetch_cookie);
    // Validate header names/values per the Fetch spec. Must run on the JS
    // thread so a violation rejects the returned promise with a `TypeError`
    // (WPT header-values expects `promise_rejects_js(t, TypeError, ...)`).
    validate_header_list_for_fetch(ctx, &header_list)?;

    // `Origin` is a forbidden request header (scripts cannot set it), so it is
    // added here *after* the forbidden-header strip. Per the Fetch spec an
    // `Origin` header is appended when the method is not GET/HEAD, OR when the
    // request is CORS-tainted. The value is the client's origin, or the
    // literal `null` when the client origin is opaque.
    if should_append_origin(&method, cors_tainted) {
        header_list.set("Origin", &serialized_origin(req_origin.as_deref()));
    }

    // `Content-Length` is likewise forbidden for scripts, so it too is derived
    // here from the actual payload. With no body only POST/PUT still report 0
    // (they normally carry one); other methods send no length at all.
    let implies_body = method.eq_ignore_ascii_case("POST") || method.eq_ignore_ascii_case("PUT");

    if let Some(b) = &body_bytes {
        header_list.set("Content-Length", &b.len().to_string());
    } else if implies_body {
        header_list.set("Content-Length", "0");
    }

    // Snapshot after the HTTP-default and forbidden-header passes so the
    // conditional-revalidation headers added below ride on the final list.
    let mut req_headers = header_list.to_vec();
    // Apply conditional-revalidation validators (from the HTTP cache) to the
    // finalized request headers; this must run after the forbidden-header
    // strip above so it cannot revive a dropped header.
    #[cfg(feature = "fetch_cache")]
    if let Some(validators) = &cached_validators {
        http_cache::add_conditional_headers(&mut req_headers, validators.clone());
    }

    // Whether a CORS preflight is *ever* needed for this request (non-safelisted
    // method or header). This is independent of CORS tainting: even a same-origin
    // request needs a preflight once a redirect makes it cross-origin, so the
    // preflight decision must be made per hop in the transport layer (see
    // `TransportRequest::before_hop`).
    let preflight_possible = needs_preflight(&method, &req_headers, true);

    // The `Access-Control-Request-Headers` list must be derived from the same
    // author-supplied header set, i.e. *before* the UA-added Fetch Metadata
    // headers below are appended. Computing it later would leak
    // `Sec-Fetch-Dest`/`Sec-Fetch-Mode`/`Sec-Fetch-Site` into the preflight,
    // making servers that do not allow-list them fail the preflight.
    let requested_headers = preflight_request_headers(&req_headers);

    // Fetch Metadata Request Headers (Fetch spec "append fetch metadata
    // headers"). Appended *after* the preflight decision: these are UA-supplied
    // headers, not author ones, so they must not themselves force a preflight
    // (a `fetch()` with no custom header must not preflight). `fetch()` is never
    // a navigation, so the destination is always "empty", and `Sec-Fetch-User`
    // is only sent for navigations from a user activation, so it is omitted
    // (WPT `fetch/metadata`).
    append_fetch_metadata_headers(&mut header_list, &mode, req_origin.as_deref(), &url_str);
    req_headers = header_list.to_vec();

    #[cfg(feature = "fetch_cache")]
    if let Some(validators) = &cached_validators {
        http_cache::add_conditional_headers(&mut req_headers, validators.clone());
    }

    // Always follow redirects manually when `redirect == "follow"`. Every hop
    // must recompute the outgoing `Referer` (per the hop's referrer policy) and,
    // for cors-mode, the `Origin` header; a cross-origin redirect also makes the
    // origin opaque. reqwest's auto-follow replays the *initial* headers verbatim
    // and would (a) leak the full referrer on cross-origin hops (WPT
    // `redirect-referrer`), (b) wrongly send a `Referer` under `no-referrer`
    // after a redirect, and (c) never re-run a CORS preflight for the new URL
    // (Fetch spec: a redirect re-enters HTTP-network-or-cache fetch). Manual
    // following is the only path that honors the per-hop recomputation.
    //
    // For `manual`/`error` we also must *not* let reqwest auto-follow: the spec
    // wants the first 3xx response surfaced as an `opaqueredirect` (status 0) or
    // a TypeError, which the dispatch below handles. So reqwest's auto-follow is
    // disabled in every case — the redirect handling is fully owned here.
    let manual_redirect = redirect == "follow";

    // Runtime TLS escape: `insecure` (from `fetch.allowInsecureTLS`) skips cert
    // validation for this request's client.
    let mut cfg = crate::fetch::config::HttpClientConfig::default();
    cfg.protocol = crate::fetch::config::ProtocolMode::Http1Only;
    // WHATWG `fetch` manages cookies itself via the shared global jar (driven
    // by the `credentials` mode), so disable reqwest's automatic store which
    // would otherwise send cookies unconditionally.
    cfg.cookie_jar = false;
    // Disable reqwest's auto-follow in all redirect modes: `follow` is handled
    // manually here (per-hop referrer/origin recomputation); `manual`/`error`
    // must surface the first 3xx response rather than following it.
    cfg.follow_redirects = false;

    // Build the client *before* the result-slot promise below: a client-build
    // failure must reject (via the caller) without leaving the polling job
    // behind. The `client` is only consumed by the spawned transport task.
    let client = match cfg.build_http_client_ex(insecure) {
        Ok(c) => c,
        Err(e) => {
            return Err(ctx.throw_internal_error(&format!("failed to build HTTP client: {e}")));
        }
    };

    // Captured into the result closure so an *in-flight* abort (one that fires
    // while the request is on the network) rejects with the signal's live
    // reason — including any custom reason passed to `abort()` — exactly like
    // the already-aborted path below. A JSValue is not `Send`, so it must live
    // in the engine job closure (not the `tokio::spawn` closure that does the
    // network I/O), where it is read only after the abort has committed.
    //
    // The `convert` closure is NOT traced by `create_with_result_slot`, so we
    // register the signal as a GC root for the fetch's lifetime (see
    // `gc_trace_fetch`) and clear it once the closure has run, preventing the
    // AbortSignal from being collected into a dangling pointer mid-flight.
    // Register the signal as a GC root only when one is present (id 0 is the
    // "no signal" sentinel, since ids start at 1). `signal_for_reason` indexes
    // the entry that the convert closure's Drop guard removes on settle.
    let signal_for_reason: usize = match &signal_val {
        Some(s) => {
            let st = AikeRuntimeState::of(ctx);
            let id = st.fetch_signal_next_id;
            st.fetch_signal_next_id = id.wrapping_add(1);
            st.fetch_signals.insert(id, *s);
            id
        }
        None => 0,
    };

    let promise = Promise::create_with_result_slot(
        ctx,
        result_slot.clone(),
        move |cx, data| -> JSResult {
            // Release the GC root now and keep the signal in a local for the
            // abort-reason path below. The convert closure runs exactly once
            // (on commit), so this mirrors the previous Drop guard while
            // needing no context in a destructor.
            let signal_root = if signal_for_reason != 0 {
                AikeRuntimeState::of(cx)
                    .fetch_signals
                    .remove(&signal_for_reason)
            } else {
                None
            };

            let client_origin = client_origin.clone();
            // Captured for the 401/407 authentication-entry check below: a
            // streaming (non-replayable) request body cannot be re-sent when the
            // server issues an auth challenge, so the fetch must reject.
            let had_stream_body = had_stream_body;
            let credentials_clone = credentials_clone;
            let mut tr = match data {
                Ok(tr) => {
                    // `AbortSignal` wakeups are edge-triggered (`notify_waiters`
                    // stores no permit), so an abort that raced the in-flight
                    // request's `notified()` registration can be missed and the
                    // request still completes. The promise has not settled yet,
                    // so re-check here and reject with the signal's reason
                    // (WPT "aborted after fetch() called").
                    if let Some(sig) = signal_root.as_ref()
                        && let Some(reason) = signal_reason(sig)
                    {
                        cx.throw(Exception::Error(reason));
                        return Err(-1);
                    }
                    tr
                }
                Err(e) => {
                    return match e {
                        FetchError::Abort => {
                            // Reject with the signal's live abort reason — a
                            // custom reason passed to `abort()` must surface even
                            // when the abort fires mid-flight (while the request
                            // is on the network). Fall back to the default
                            // "AbortError" DOMException if no signal is present.
                            let reason = signal_root
                                .as_ref()
                                .and_then(signal_reason)
                                .unwrap_or_else(|| {
                                    make_dom_exception(
                                        cx,
                                        "AbortError",
                                        "The operation was aborted.",
                                    )
                                    .unwrap_or(JSValue::UNDEFINED)
                                });
                            cx.throw(Exception::Error(reason));
                            Err(-1)
                        }
                        FetchError::Other(te) => throw_transport_error(cx, te),
                    };
                }
            };

            let status = tr.status;

            // RFC 5861: the request above already revalidated the stored entry
            // (the transport stored the fresh response); hand the caller the
            // stale copy we matched, so `stale-while-revalidate` serves stale
            // first and refreshes in the background.
            #[cfg(feature = "fetch_cache")]
            if let Some(hit) = swr_hit {
                let final_url = hit.final_url.clone();
                return build_response_from_transport(
                    cx,
                    TransportResponse {
                        status: hit.status,
                        status_text: "OK".to_string(),
                        headers: hit.headers,
                        content_type: String::new(),
                        content_length: Some(hit.body.len() as u64),
                        http_version: "1.1",
                        resp: None,
                        final_url: hit.final_url,
                        synthetic_body: Some(hit.body),
                        origin_opaque: false,
                    },
                    RespType::Basic,
                    &final_url,
                    false,
                    signal_val,
                );
            }

            // Fetch spec (HTTP-network fetch, authentication entries): a 401 or
            // 407 response with credentials mode other than "omit" is an auth
            // challenge that normally triggers a credentialed re-issue of the
            // request. A streaming (non-replayable) body cannot be re-sent, so
            // the re-issue is impossible and the fetch becomes a network error
            // (rejects with TypeError). Browsers reject such streaming uploads
            // on a 401 (WPT `request-upload.h2.any.js`:
            // "Streaming upload should fail on a 401 response").
            if (status == 401 || status == 407) && credentials_clone != "omit" && had_stream_body {
                return throw_transport_error(
                    cx,
                    TransportError {
                        code: "unauthorized",
                        message: "Failed to fetch: streaming upload cannot be retried on an authentication challenge".into(),
                    },
                );
            }

            if matches!(redirect_clone.as_str(), "error" | "manual") && (300..400).contains(&status)
            {
                if redirect_clone == "error" {
                    return Err(
                        cx.throw_type_error("Failed to fetch: redirect not allowed (mode 'error')")
                    );
                }
                // `manual` mode surfaces the first 3xx response as an opaqueredirect,
                // but a cross-origin 3xx is invalid for a `no-cors` request (no-cors
                // only allows `follow`), so it must reject (WPT redirect-mode.any.js).
                // A `cors`-mode cross-origin 3xx without a valid
                // `Access-Control-Allow-Origin` is also a CORS failure and rejects.
                let cross_origin =
                    fetch_cors && is_cross_origin(client_origin.as_deref(), &url_clone);
                if mode_clone == "no-cors" && cross_origin {
                    return Err(cx.throw_type_error(
                        "Failed to fetch: no-cors request cannot follow a cross-origin redirect with manual/error mode",
                    ));
                }
                if mode_clone == "cors" && cors_tainted {
                    let acao = tr
                        .headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-origin"))
                        .map(|(_, v)| v.clone());
                    let allowed = check_allow_origin(
                        acao.as_deref(),
                        client_origin.as_deref().unwrap_or(""),
                        credentials_include,
                    )
                    .is_some();
                    if !allowed {
                        return Err(cx.throw_type_error(
                            "Failed to fetch: redirect response is a cross-origin CORS failure",
                        ));
                    }
                }
                return build_opaque_redirect_response(cx, &url_clone);
            }

            // Fetch spec: `mode: "same-origin"` requires the request (and every
            // redirect hop) to stay same-origin; a cross-origin URL is a network
            // error. Redirects are followed manually, so the *final* response URL
            // is checked here (the redirect target would otherwise hide the
            // violation).
            // Fetch spec, `no-cors` responses: when the response carries
            // `Cross-Origin-Resource-Policy`, a `no-cors` request that is not
            // same-origin (`same-origin` value) or not same-site (`same-site`
            // value) with the response URL is a network error. Applies only to
            // `no-cors`; a `cors` request already passed the CORS check
            // (WPT `fetch/cross-origin-resource-policy`).
            if fetch_cors
                && mode_clone == "no-cors"
                && let Some(msg) = corp_violation(
                    &HeaderList::from_vec(tr.headers.clone()),
                    client_origin.as_deref(),
                    &tr.final_url,
                )
            {
                return throw_transport_error(
                    cx,
                    TransportError {
                        code: "corp",
                        message: msg,
                    },
                );
            }

            if fetch_cors
                && mode_clone == "same-origin"
                && let Some(msg) = same_origin_violation(client_origin.as_deref(), &tr.final_url)
            {
                return throw_transport_error(
                    cx,
                    TransportError {
                        code: "same-origin",
                        message: msg,
                    },
                );
            }

            // HTTP cache: a `304` we drove via conditional headers becomes the
            // cached response (status 200) with the 304 headers merged on top.
            #[cfg(feature = "fetch_cache")]
            if let Some((cached_status, cached_headers, cached_body)) =
                http_cache::take_not_modified(
                    &method_clone,
                    &url_clone,
                    &cache_req_headers,
                    status,
                    &tr.headers,
                    cache_driven,
                )
            {
                return build_response_from_transport(
                    cx,
                    TransportResponse {
                        status: cached_status,
                        status_text: "OK".to_string(),
                        headers: cached_headers,
                        content_type: String::new(),
                        content_length: Some(cached_body.len() as u64),
                        http_version: "1.1",
                        resp: None,
                        final_url: url_clone.clone(),
                        synthetic_body: Some(cached_body),
                        origin_opaque: false,
                    },
                    RespType::Basic,
                    &url_clone,
                    false,
                    signal_val,
                );
            }
            // Caching a successful GET response (with its full body) is done in
            // the transport closure above, where the body bytes are available.
            // (Skipping `no-store` there too.) Nothing to do here.
            //
            // A `no-cors` request for a cross-origin (or unknown-origin) URL
            // yields an opaque response per Fetch spec (status 0, type opaque,
            // null body, CORS-filtered headers). Same-origin stays basic.
            let is_opaque = fetch_cors
                && mode_clone == "no-cors"
                && is_cross_origin(client_origin.as_deref(), &url_clone);
            let resp_type = if is_opaque {
                RespType::Opaque
            } else {
                RespType::Basic
            };
            // The response URL is the *final* URL after any redirect (Fetch spec
            // sets `response.url` to the last URL in the chain), and `redirected`
            // is true once the chain followed at least one redirect.
            let final_url = tr.final_url.clone();
            let redirected = final_url != url_clone;
            // Cross-origin `cors` mode: run the CORS check against the final
            // response origin and, on success, return a `cors` filtered
            // response (type `cors`, headers limited to the safelist +
            // `Access-Control-Expose-Headers`). A failed check is a network
            // error (rejects with TypeError).
            if !is_opaque && cors_tainted && mode_clone == "cors" {
                let final_cross = is_cross_origin(client_origin.as_deref(), &final_url);
                // A `cors` request that went through a cross-origin redirect keeps the
                // CORS-filtered (`cors`) response type even when the final URL ends up
                // same-origin again (whatwg/fetch#737). The CORS check still applies
                // when the *final* response is cross-origin; a same-origin final URL
                // always passes.
                if final_cross {
                    let headers = HeaderList::from_vec(tr.headers.clone());
                    // The request's origin may have become opaque ("null") after a
                    // cross-origin redirect; the CORS check must then compare the
                    // `Access-Control-Allow-Origin` header against "null" (the
                    // serialized opaque origin), not the client origin.
                    let check_origin = if tr.origin_opaque {
                        "null".to_string()
                    } else {
                        serialized_origin(client_origin.as_deref())
                    };
                    if cors_check(&headers, &check_origin, credentials_include).is_none() {
                        return throw_transport_error(
                            cx,
                            TransportError {
                                code: "cors",
                                message: "request failed: CORS check failed for the response"
                                    .into(),
                            },
                        );
                    }
                }
                // CORS-filter the exposed headers. `content-type` / `content-length`
                // are safelisted, so the payload's derived fields stay valid.
                let headers = HeaderList::from_vec(tr.headers.clone());
                let expose = headers.get("Access-Control-Expose-Headers");
                let filtered =
                    cors_filter_response_headers(&headers, expose.as_deref(), credentials_include);
                tr.headers = filtered;
                return build_response_from_transport(
                    cx,
                    tr,
                    RespType::Cors,
                    &final_url,
                    redirected,
                    signal_val,
                );
            }
            build_response_from_transport(cx, tr, resp_type, &final_url, redirected, signal_val)
        },
    )?;

    let referrer_ctx = manual_redirect.then_some(ReferrerCtx {
        referrer: rc_referrer,
        policy: rc_policy,
        client_origin: rc_origin,
        client_url: rc_url,
        max_redirects: 20,
    });

    // The actual request carries `User-Agent: Mozilla/5.0 (aike)` (injected by
    // `ensure_default_request_headers`); a CORS preflight must send the same
    // value so a server comparing the two (WPT `checkUserAgentHeaderInPreflight`)
    // accepts the actual request.
    let user_agent = req_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "Mozilla/5.0 (aike)".to_string());

    let client_origin_str = serialized_origin(req_origin.as_deref());

    // Per-hop gate for the transport layer (browser builds: a CORS preflight
    // runner). `possible` records whether this request *would* need a
    // preflight once tainted; the gate runs a fresh OPTIONS preflight against
    // each CORS-tainted hop target before sending the actual request there
    // (Fetch spec). A failed preflight rejects the fetch with a TypeError.
    let preflight = (fetch_cors && preflight_possible).then(|| PreflightCtx {
        possible: true,
        method: method.clone(),
        request_headers: join_request_headers(&requested_headers),
        client_origin: client_origin_str.clone(),
        credentials_include,
        user_agent,
    });

    let req = TransportRequest {
        method,
        url: url_str.clone(),
        headers: req_headers,
        body: body_bytes,
        timeout,
        referrer: effective_referrer,
        referrer_ctx,
        replayable: stream_body.is_none(),
        before_hop: make_before_hop_hook(preflight),
        // Feature-gated CORS: in lean builds the transport's cors-mode rules
        // (per-hop Origin recomputation, opaque-origin rule) never apply.
        cors_mode: fetch_cors && mode == "cors",
        cors_tainted,
        cors_client_origin: client_origin_str,
        credentials_mode: credentials.clone(),
        use_shared_cookies: fetch_cookie,
        cache_mode: cache_mode.clone(),
        corp_check: fetch_cors && mode == "no-cors",
    };

    // Issue the request on the tokio side. Taken as a closure because a stream
    // body must first be pumped on the JS thread, which defers this call to a
    // later event-loop turn.
    let rs = result_slot.clone();
    let notify2 = notify;
    let cache_mode_for_spawn = cache_mode.clone();
    let has_conditional_for_spawn = has_conditional;
    let spawn_request = move |req: TransportRequest| match notify2 {
        Some(n) => {
            let client = client.clone();
            let cfg = cfg.clone();
            tokio::spawn(async move {
                let fut = perform_request_retrying(&cfg, insecure, &client, req);
                tokio::select! {
                    r = fut => {
                        let _ = rs.commit(r.map_err(FetchError::Other));
                    }
                    _ = n.notified() => { let _ = rs.commit(Err(FetchError::Abort)); }
                }
            });
        }
        None => {
            let cache_mode = cache_mode_for_spawn.clone();
            let has_conditional = has_conditional_for_spawn;
            let cache_method = req.method.clone();
            let cache_url = req.url.clone();
            // The task's own snapshot of the outgoing headers for `Vary` matching:
            // a local, because it is moved into the spawned task and the response
            // handler above keeps its own (lookup-consistent) copy.
            let cache_req_headers = req.headers.clone();
            let client = client.clone();
            let cfg = cfg.clone();
            tokio::spawn(async move {
                let mut tr = match perform_request_retrying(&cfg, insecure, &client, req).await {
                    Ok(tr) => tr,
                    Err(e) => {
                        let _ = rs.commit(Err(FetchError::Other(e)));
                        return;
                    }
                };
                // Subresource Integrity: for a non-empty `integrity`, the whole
                // body must be read and its hash matched against the metadata,
                // otherwise the response is rejected (fetch spec §6.4).
                if !integrity.is_empty() {
                    let bytes = match tr.resp.take() {
                        Some(resp) => match resp.bytes().await {
                            Ok(b) => b.to_vec(),
                            Err(e) => {
                                let _ = rs.commit(Err(FetchError::Other(TransportError {
                                    code: "integrity",
                                    message: format!(
                                        "request failed: reading body for integrity check: {e}"
                                    ),
                                })));
                                return;
                            }
                        },
                        None => tr.synthetic_body.clone().unwrap_or_default(),
                    };
                    if let Err(msg) = check_integrity(&bytes, &integrity) {
                        let _ = rs.commit(Err(FetchError::Other(TransportError {
                            code: "integrity",
                            message: format!("request failed: {msg}"),
                        })));
                        return;
                    }
                    tr.synthetic_body = Some(bytes);
                }
                // RFC 9111 §4.4: a successful unsafe request invalidates the
                // stored responses for its target URL and for the URLs it names
                // in `Location` / `Content-Location` (WPT `http-cache/invalidate`).
                #[cfg(feature = "fetch_cache")]
                {
                    let method = cache_method.to_ascii_uppercase();
                    let is_get = method == "GET" || method == "HEAD";
                    let successful = tr.status >= 200 && tr.status < 400;
                    if !is_get && successful {
                        http_cache::invalidate(&cache_url);
                        http_cache::invalidate(&tr.final_url);
                        for name in ["location", "content-location"] {
                            if let Some(v) = tr
                                .headers
                                .iter()
                                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                                .map(|(_, v)| v.as_str())
                            {
                                // Resolve against the request URL, then drop
                                // any stored entry for it.
                                if let Ok(abs) = url::Url::parse(&cache_url).and_then(|b| b.join(v))
                                {
                                    http_cache::invalidate(abs.as_str());
                                }
                            }
                        }
                    }
                }

                // HTTP cache: buffer the body of a cacheable response so it can
                // be stored and later served/revalidated from cache.
                #[cfg(feature = "fetch_cache")]
                if cache_mode != "no-store"
                    && !has_conditional
                    && cache_method.eq_ignore_ascii_case("GET")
                    // Caching is not limited to 2xx: RFC 9111 §3 lets a cache
                    // store any status that carries explicit freshness info
                    // (`store` makes that call, and also knows the
                    // heuristically-cacheable status set). WPT
                    // `http-cache/status` requires fresh 4xx/5xx to be reused.
                    // A 304 is a revalidation artifact (turned back into the
                    // cached response elsewhere), never a stored response; HEAD
                    // is already excluded by the method check above.
                    && tr.status != 304
                {
                    // The final URL (after any redirect) is stored so a later
                    // `same-origin` cache hit can reject a cross-origin redirect.
                    let final_url = tr.final_url.clone();
                    // 204/205 carry no body at all: nothing to buffer and no
                    // `Content-Length` to consult, but they must still be stored
                    // (WPT `http-cache/status` + `heuristic`: a fresh 204 must be
                    // served from cache). `tr.resp` stays intact so their
                    // null-body handling is unchanged.
                    let bodyless = matches!(tr.status, 204 | 205);
                    // Never buffer an unbounded body just to cache it: WPT
                    // `huge-fetch` is 8GiB and the in-memory cache (a plain
                    // HashMap) would OOM the process, yielding an empty chunk
                    // or a crash. Only cache when we know the body is small
                    // enough; otherwise keep `tr.resp` intact so the body is
                    // streamed lazily to the consumer, one chunk at a time.
                    let small_enough = bodyless
                        || matches!(
                            tr.content_length,
                            Some(len) if len <= http_cache::MAX_CACHE_BODY_BYTES
                        );
                    if small_enough {
                        let bytes = if bodyless {
                            Vec::new()
                        } else {
                            match tr.resp.take() {
                                Some(resp) => match resp.bytes().await {
                                    Ok(b) => b.to_vec(),
                                    Err(_) => Vec::new(),
                                },
                                None => tr.synthetic_body.clone().unwrap_or_default(),
                            }
                        };
                        http_cache::store(
                            &cache_method,
                            &cache_url,
                            tr.status,
                            &tr.headers,
                            bytes.clone(),
                            &final_url,
                            &cache_req_headers,
                        );
                        // Only a body we actually buffered replaces the payload.
                        if !bodyless {
                            tr.synthetic_body = Some(bytes);
                        }
                    }
                }

                let _ = rs.commit(Ok(tr));
            });
        }
    };

    // A buffered body can go out immediately; a stream body must be pumped to
    // completion on the JS thread first, then the request is issued with the
    // collected bytes (and the now-known Content-Length).
    match stream_body {
        None => spawn_request(req),
        Some(sv) => {
            let mut s = JSReadableStream::try_from(sv)
                .map_err(|_| ctx.throw_type_error("body is not a ReadableStream"))?;

            let drain_slot = PromiseResultSlot::<Result<Vec<u8>, String>>::new();
            let raw_err = Rc::new(RefCell::new(None::<JSValue>));
            let reader = s.acquire_reader(ctx, false)?;
            reader.drain(ctx, drain_slot.clone(), raw_err.clone(), BODY_TIMEOUT)?;

            // The job may run over several turns, so the request and the
            // one-shot dispatcher are parked in cells and taken on the turn
            // that actually dispatches.
            let req = RefCell::new(Some(req));
            let spawn_request = RefCell::new(Some(spawn_request));
            let fail_slot = result_slot.clone();

            ctx.queue_job(
                move |_cx| {
                    let Some(bytes) = drain_slot.try_take() else {
                        return Ok(JobState::Block);
                    };

                    match bytes {
                        Ok(b) => {
                            let Some(mut req) = req.take() else {
                                let _ = fail_slot.commit(Err(FetchError::Other(TransportError {
                                    code: "body",
                                    message: "request failed: stream drain job ran twice".into(),
                                })));
                                return Ok(JobState::Done);
                            };
                            set_content_length(&mut req.headers, b.len());
                            req.body = Some(b);

                            let Some(spawn) = spawn_request.take() else {
                                let _ = fail_slot.commit(Err(FetchError::Other(TransportError {
                                    code: "body",
                                    message: "request failed: dispatcher already used".into(),
                                })));
                                return Ok(JobState::Done);
                            };
                            spawn(req);
                        }
                        // The stream errored or produced a bad chunk; surface it
                        // as a network error so the fetch promise rejects.
                        Err(msg) => {
                            let _ = fail_slot.commit(Err(FetchError::Other(TransportError {
                                code: "body",
                                message: format!("request failed: {msg}"),
                            })));
                        }
                    }

                    Ok(JobState::Done)
                },
                (),
            );
        }
    }

    Ok(promise.into())
}

/// Whether an HTTP status is a redirect status (301/302/303/307/308).
/// Overwrite `Content-Length` on an already-built header list. Used once a
/// stream body has been pumped and its real length is known.
fn set_content_length(headers: &mut Vec<(String, String)>, len: usize) {
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
    headers.push(("Content-Length".into(), len.to_string()));
}

/// Install the `fetch` global and register all WHATWG classes.
pub(crate) fn init_fetch(ctx: &mut ScopedContext, mut global: Object) -> Result<(), i32> {
    // The fetch standard classes live in `client`; each ClassCtorDef carries
    // `expose_to_global()`, so registering them installs the `Request`,
    // `Response` and `Headers` globals.
    ctx.use_classes(&[
        JSRequest::class_id(),
        JSResponse::class_id(),
        JSHeaders::class_id(),
    ])?;

    // `Headers Iterator` backs `Headers.prototype[Symbol.iterator]` / keys() /
    // values() / entries(). It is not exposed as a global (no
    // `expose_to_global()`), but its class must be registered or the iterator
    // objects come back without a prototype and every method throws.
    ctx.use_classes(&[crate::fetch::headers::HeaderListIterator::class_id()])?;

    // CacheStorage / Cache back the `caches` global below; the engine needs them
    // registered before `new_instance` can resolve their payloads.
    #[cfg(feature = "fetch_cache")]
    ctx.use_classes(&[
        crate::cache_storage::JSCacheStorage::class_id(),
        crate::cache_storage::JSCache::class_id(),
    ])?;

    let func = ctx.create_native_function(Callback::Func(js_fetch), "fetch", 1, 0)?;

    // Runtime-level switches as accessor properties on the `fetch` function
    // object (not per-request). The getter/setter reads/writes
    // `AikeRuntimeState`. (Browser CORS/cookie semantics have no switch: they
    // are the compile-time `fetch_cors_cookie` decision.)
    {
        let mut func = func;

        // `fetch.allowInsecureTLS` — always available (a general TLS escape).
        let insecure_atom = zuqe::Atom::intern_static(ctx, "allowInsecureTLS")?;
        let insecure_get = ctx.create_native_function(
            Callback::Func(js_fetch_allow_insecure_get),
            "get allowInsecureTLS",
            0,
            0,
        )?;
        let insecure_set = ctx.create_native_function(
            Callback::Func(js_fetch_allow_insecure_set),
            "set allowInsecureTLS",
            1,
            0,
        )?;
        func.define_property_getset(
            ctx,
            insecure_atom,
            insecure_get.into(),
            insecure_set.into(),
            zuqe::JS_PROP_C_W_E,
        )?;
    }

    global.define_property_value_str(ctx, "fetch", func.into(), zuqe::JS_PROP_C_W_E)?;

    // Cache Storage API (only with the `fetch_cache` feature).
    #[cfg(feature = "fetch_cache")]
    {
        let caches = crate::cache_storage::JSCacheStorage::new_instance(
            ctx,
            JSValue::UNDEFINED,
            crate::cache_storage::CacheStoragePayload {
                stores: std::rc::Rc::new(std::cell::RefCell::new(std::collections::HashMap::new())),
            },
        )
        .map(JSValue::from)?;
        global.define_property_value_str(ctx, "caches", caches, zuqe::JS_PROP_C_W_E)?;
    }

    Ok(())
}

/// `fetch.allowInsecureTLS` getter — whether TLS validation is skipped.
fn js_fetch_allow_insecure_get(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    Ok(JSValue::from(
        AikeRuntimeState::of(ctx).fetch_allow_insecure_tls,
    ))
}

/// `fetch.allowInsecureTLS` setter — strict boolean.
fn js_fetch_allow_insecure_set(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let b = match cc.arg(0).as_bool() {
        Some(b) => b,
        None => {
            return Err(ctx.throw_type_error("`fetch.allowInsecureTLS` must be a boolean"));
        }
    };
    AikeRuntimeState::of(ctx).fetch_allow_insecure_tls = b;
    Ok(JSValue::UNDEFINED)
}

/// Parse a single `bytes` range (the `Range` header of a `blob:` fetch) against
/// a body of `size` bytes. Returns inclusive `(start, end)` offsets, or `None`
/// when the range is malformed or unsatisfiable. Whitespace is allowed around
/// the unit, `=` and `-`; multiple ranges are not supported.
fn parse_blob_range(value: &str, size: u64) -> Option<(u64, u64)> {
    let ws = |c: char| matches!(c, ' ' | '\t');
    let unit = value.get(..5)?;
    if !unit.eq_ignore_ascii_case("bytes") {
        return None;
    }
    let rest = value[5..].trim_start_matches(ws).strip_prefix('=')?;
    let (first, rest) = split_digits(rest.trim_start_matches(ws));
    let rest = rest.trim_start_matches(ws).strip_prefix('-')?;
    let (last, rest) = split_digits(rest.trim_start_matches(ws));
    if !rest.trim_matches(ws).is_empty() || (first.is_empty() && last.is_empty()) || size == 0 {
        return None;
    }
    // Overflowing numbers saturate; they are then clamped or unsatisfiable.
    let num = |s: &str| s.parse::<u64>().unwrap_or(u64::MAX);
    match (first.is_empty(), last.is_empty()) {
        (false, true) => {
            let start = num(first);
            (start < size).then_some((start, size - 1))
        }
        (false, false) => {
            let (start, end) = (num(first), num(last));
            (start <= end && start < size).then(|| (start, end.min(size - 1)))
        }
        (true, _) => {
            let suffix = num(last);
            (suffix > 0).then(|| (size.saturating_sub(suffix), size - 1))
        }
    }
}

/// Split the leading ASCII digits off `s`.
fn split_digits(s: &str) -> (&str, &str) {
    let n = s.bytes().take_while(u8::is_ascii_digit).count();
    s.split_at(n)
}

// ---------------------------------------------------------------------------
// Request-header policy
//
// Fetch-spec default headers and the forbidden request-header filter
// (including the conditional method-override headers). Applied by `fetch_impl`
// only — `Headers` guards its own writes at set time.
// ---------------------------------------------------------------------------

// Inject Fetch-spec default request headers (`Accept`, `Accept-Language`)
// when the caller did not supply them. Called after RequestInit/Request
// inheritance is applied, so explicit headers always win.
fn ensure_default_request_headers(h: &mut HeaderList) {
    if !h.has("accept") {
        h.append("Accept", "*/*");
    }
    if !h.has("accept-language") {
        h.append("Accept-Language", "*");
    }
    // Browsers always send a User-Agent; WPT checks for its presence.
    if !h.has("user-agent") {
        h.append("User-Agent", "Mozilla/5.0 (aike)");
    }
}

/// WHATWG "forbidden request-header" names: a `fetch()` must silently drop any
/// header whose name (case-insensitively) is in this set, or begins with
/// `Proxy-` / `Sec-`. The browser (or underlying transport) owns these; a
/// script must not be able to set them. (Set-Cookie is also forbidden as a
/// request header but Headers does not expose it for sending anyway.)
///
/// The three `x-*` method-override headers are *conditionally* forbidden: only
/// when their value resolves to a forbidden method (see
/// `is_forbidden_override_value`).
fn is_forbidden_request_header(name: &str, value: &str) -> bool {
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
    // `x-http-method` / `x-http-method-override` / `x-method-override`: forbidden
    // only when the value resolves to a forbidden method (CONNECT/TRACE/TRACK).
    if matches!(
        lower.as_str(),
        "x-http-method" | "x-http-method-override" | "x-method-override"
    ) {
        return is_forbidden_override_value(value);
    }
    false
}

/// WHATWG Fetch: the three method-override headers are forbidden when their
/// value, after "get, decode, and split" (split on commas, with quoted strings
/// kept intact and each item trimmed), yields a forbidden method
/// (CONNECT/TRACE/TRACK, byte-case-insensitive). A quoted method like
/// `"TRACE"` does NOT match (the quotes are part of the token), so a value such
/// as `",TRACE,"` is permitted.
fn is_forbidden_override_value(value: &str) -> bool {
    for method in split_on_commas(value) {
        if matches!(
            method.to_ascii_lowercase().as_str(),
            "connect" | "trace" | "track"
        ) {
            return true;
        }
    }
    false
}

/// Fetch "get, decode, and split" for a header value: split on commas, but a
/// comma inside an HTTP quoted string (`"..."`) is not a separator, and each
/// item is trimmed of surrounding whitespace. Quoted strings keep their quote
/// characters (so `"TRACE"` is a distinct token from `TRACE`). Backslash
/// escapes inside a quoted string are preserved verbatim.
fn split_on_commas(value: &str) -> Vec<String> {
    let chars: Vec<char> = value.chars().collect();
    let mut pos = 0;
    let mut out: Vec<String> = Vec::new();
    let mut temp = String::new();
    loop {
        while pos < chars.len() && chars[pos] != '"' && chars[pos] != ',' {
            temp.push(chars[pos]);
            pos += 1;
        }
        if pos < chars.len() && chars[pos] == '"' {
            // Collect the HTTP quoted string, keeping the quote characters.
            temp.push('"');
            pos += 1;
            while pos < chars.len() {
                let c = chars[pos];
                temp.push(c);
                pos += 1;
                if c == '"' {
                    break;
                }
                if c == '\\' && pos < chars.len() {
                    temp.push(chars[pos]);
                    pos += 1;
                }
            }
            if pos < chars.len() {
                continue;
            }
        }
        out.push(temp.trim().to_string());
        temp.clear();
        if pos >= chars.len() {
            return out;
        }
        if chars[pos] == ',' {
            pos += 1;
        }
    }
}

/// Drop all forbidden request headers set by the caller. Called after default
/// headers are injected (Accept / Accept-Language are not forbidden, so they
/// survive). The transport layer adds its own Content-Length / Host later.
///
/// `strip_cookies` controls the cookie headers: in `fetch_cors_cookie` builds
/// fetch owns the jar so `Cookie`/`Cookie2` are forbidden and dropped; lean
/// builds leave them under the caller's control.
fn strip_forbidden_request_headers(h: &mut HeaderList, strip_cookies: bool) {
    let drop: Vec<String> = h
        .to_vec()
        .into_iter()
        .filter(|(k, v)| {
            if !strip_cookies
                && (k.eq_ignore_ascii_case("cookie") || k.eq_ignore_ascii_case("cookie2"))
            {
                return false;
            }
            is_forbidden_request_header(k, v)
        })
        .map(|(k, _)| k)
        .collect();
    for k in drop {
        h.delete(&k);
    }
}
