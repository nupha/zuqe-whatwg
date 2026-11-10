// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! Browser-security layer of the Fetch API: the WHATWG CORS protocol
//! (preflight, `Access-Control-Allow-*` validation, response-header
//! filtering), request-mode/tainting decisions, and the per-hop preflight
//! gate driven through the transport's neutral [`BeforeHopHook`](super::transport::
//! BeforeHopHook).
//!
//! Gated by the `fetch_cors_cookie` feature. With the feature disabled the
//! decision functions below compile to constant stubs (`false` / always-pass),
//! which lets LLVM fold away every browser-only branch in the fetch pipeline;
//! the engine then behaves like a plain HTTP client. The preflight execution
//! machinery ([`self::preflight`]) exists only in browser builds.

use crate::fetch::headers::{HeaderList, is_cors_safelisted};

/// CORS-safelisted response-header names (Fetch spec §5.1.1). These are the
/// only headers exposed on a `cors` filtered response unless the server lists
/// more via `Access-Control-Expose-Headers`.
const CORS_SAFELISTED_RESPONSE_HEADERS: &[&str] = &[
    "cache-control",
    "content-language",
    "content-length",
    "content-type",
    "expires",
    "last-modified",
    "pragma",
];

/// CORS-forbidden response-header names: never exposed on a `cors` response.
const CORS_FORBIDDEN_RESPONSE_HEADERS: &[&str] = &["set-cookie", "set-cookie2"];

/// Serialized origin of the client (the document origin), or the literal
/// `null` when the origin is opaque/unknown. Used for the `Origin` header and
/// `Access-Control-Allow-Origin` comparison.
pub(crate) fn serialized_origin(client_origin: Option<&str>) -> String {
    client_origin
        .map(|s| s.to_string())
        .unwrap_or_else(|| "null".to_string())
}

/// Whether a request URL is cross-origin with respect to the client origin.
/// An unparsable request URL or an unknown client origin counts as
/// cross-origin (conservative: such requests get CORS treatment).
///
/// `data:` URLs are same-origin with any client per the Fetch scheme fetch
/// algorithm (their origin is the client's), so they are never cross-origin.
/// Treating them as cross-origin would wrongly CORS-taint `fetch("data:...")`
/// (default `cors` mode) and fail the response CORS check.
#[cfg(feature = "fetch_cors_cookie")]
pub(crate) fn is_cross_origin(client_origin: Option<&str>, url: &str) -> bool {
    if url.to_ascii_lowercase().starts_with("data:") {
        return false;
    }
    let req_origin = url::Url::parse(url)
        .ok()
        .map(|u| u.origin().ascii_serialization());
    match (&client_origin, &req_origin) {
        (Some(co), Some(ro)) => co != ro,
        _ => true,
    }
}

/// Server build: no client-origin concept exists, so nothing is ever
/// cross-origin (every fetch behaves like a plain same-origin request).
#[cfg(not(feature = "fetch_cors_cookie"))]
pub(crate) fn is_cross_origin(_client_origin: Option<&str>, _url: &str) -> bool {
    false
}

/// Whether the `Origin` header should be appended to a request (Fetch spec
/// "append a request `Origin` header"): set when the method is not GET/HEAD,
/// or when the request's response tainting is `cors` (i.e. a cross-origin
/// `cors`-mode request).
///
/// The transport layer inlines the identical rule for per-hop recomputation;
/// this copy drives the initial request header built here.
#[cfg(feature = "fetch_cors_cookie")]
pub(crate) fn should_append_origin(method: &str, cors_tainted: bool) -> bool {
    let safe_method = method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD");
    !safe_method || cors_tainted
}

/// Server build: no `Origin` header is ever appended.
#[cfg(not(feature = "fetch_cors_cookie"))]
pub(crate) fn should_append_origin(_method: &str, _cors_tainted: bool) -> bool {
    false
}

/// Fetch spec "append fetch metadata headers": add `Sec-Fetch-Dest`,
/// `Sec-Fetch-Mode` and `Sec-Fetch-Site`. `Sec-Fetch-User` is omitted — it is
/// only sent for navigations caused by a user activation, and `fetch()` is
/// never a navigation.
///
/// `Sec-Fetch-Site` compares the request URL with the client origin:
/// `same-origin`, then `same-site` (same host, ignoring scheme/port — aike has
/// no public-suffix list), then `cross-site`.
#[cfg(feature = "fetch_cors_cookie")]
pub(crate) fn append_fetch_metadata_headers(
    headers: &mut HeaderList,
    mode: &str,
    client_origin: Option<&str>,
    url: &str,
) {
    headers.set("Sec-Fetch-Dest", "empty");
    headers.set("Sec-Fetch-Mode", mode);
    headers.set(
        "Sec-Fetch-Site",
        match fetch_site(client_origin, url) {
            Some(s) => s,
            None => return,
        },
    );
}

/// `Sec-Fetch-Site` value, or `None` when no client origin is known (the header
/// is then left off, since the site relation is undefined).
///
/// Per Fetch Metadata's "set the `Sec-Fetch-Site` header": `same-origin`, else
/// `same-site` (HTML's *schemeful* same site — same scheme and a shared
/// registrable domain), else `cross-site`.
#[cfg(feature = "fetch_cors_cookie")]
fn fetch_site(client_origin: Option<&str>, url: &str) -> Option<&'static str> {
    let client = client_origin?;
    let req = url::Url::parse(url).ok()?;
    if client == req.origin().ascii_serialization() {
        return Some("same-origin");
    }
    let c = url::Url::parse(client).ok()?;
    if c.scheme() == req.scheme() && same_site_host(c.host_str()?, req.host_str()?) {
        Some("same-site")
    } else {
        Some("cross-site")
    }
}

/// Whether two host names share a registrable domain (HTML "schemelessly same
/// site"). aike carries no Public Suffix List, so the registrable domain is
/// approximated as the host's final two labels — exact for the `web-platform.test`
/// family the suites use and for `not-web-platform.test` (its final two labels
/// differ); multi-label public suffixes (`co.uk`) are the known imprecision.
#[cfg(feature = "fetch_cors_cookie")]
fn same_site_host(a: &str, b: &str) -> bool {
    fn registrable(host: &str) -> &str {
        host.rmatch_indices('.')
            .nth(1)
            .map_or(host, |(i, _)| &host[i + 1..])
    }
    registrable(a).eq_ignore_ascii_case(registrable(b))
}

/// Server build: no Fetch Metadata headers are appended.
#[cfg(not(feature = "fetch_cors_cookie"))]
pub(crate) fn append_fetch_metadata_headers(
    _headers: &mut HeaderList,
    _mode: &str,
    _client_origin: Option<&str>,
    _url: &str,
) {
}

/// CORS-safelisted method (Fetch spec): GET, HEAD, or POST (case-insensitive).
#[cfg(feature = "fetch_cors_cookie")]
pub(crate) fn cors_safelisted_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "POST"
    )
}

/// Whether a request-header is CORS-safelisted (name+value).
fn cors_safelisted_request_header(name: &str, value: &str) -> bool {
    is_cors_safelisted(name, value)
}

/// UA-controlled request-header names (Fetch spec). These are set by the
/// browser/UA (or the fetch algorithm itself), not the script, so they never
/// trigger a CORS preflight and are never sent in
/// `Access-Control-Request-Headers`. `Accept`/`Accept-Language`/
/// `Content-Language` are deliberately NOT listed here: a script-set unsafe
/// value on those must still force a preflight (checked via
/// `is_cors_safelisted`).
fn is_ua_controlled_request_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "content-length" | "origin" | "referer" | "user-agent"
    )
}

/// Whether a request-header would need preflight permission: not CORS-safelisted
/// (name+value) and not UA-controlled.
fn is_cors_unsafe_request_header(name: &str, value: &str) -> bool {
    !cors_safelisted_request_header(name, value) && !is_ua_controlled_request_header(name)
}

/// Whether a cross-origin `cors`-mode request must be preflighted.
///
/// A preflight is required when the method is not CORS-safelisted, or when any
/// request header is CORS-unsafe (non-safelisted and not UA-controlled).
/// Credentials mode on its own does not force a preflight.
#[cfg(feature = "fetch_cors_cookie")]
pub(crate) fn needs_preflight(
    method: &str,
    headers: &[(String, String)],
    cors_tainted: bool,
) -> bool {
    if !cors_tainted {
        return false;
    }
    if !cors_safelisted_method(method) {
        return true;
    }
    headers
        .iter()
        .any(|(name, value)| is_cors_unsafe_request_header(name, value))
}

/// Server build: no CORS taint exists, so no request ever needs a preflight.
#[cfg(not(feature = "fetch_cors_cookie"))]
pub(crate) fn needs_preflight(
    _method: &str,
    _headers: &[(String, String)],
    _cors_tainted: bool,
) -> bool {
    false
}

/// Validate an `Access-Control-Allow-Origin` header against the client origin.
///
/// Returns the matched origin string (`*` when the wildcard is used) on
/// success, or `None` when the CORS check fails. A `*` only matches when
/// credentials mode is not `include`.
pub(crate) fn check_allow_origin(
    allow_origin: Option<&str>,
    client_origin: &str,
    credentials_include: bool,
) -> Option<String> {
    let ao = allow_origin?.trim();
    if ao == "*" && !credentials_include {
        return Some("*".to_string());
    }
    if ao == client_origin {
        return Some(ao.to_string());
    }
    None
}

/// Validate a CORS response (Fetch spec "CORS-check" algorithm, the part
/// relevant to the `Access-Control-Allow-Origin` header).
///
/// `status` is unused for the non-preflight check but kept for symmetry with
/// `check_preflight`. Returns the matched origin on success.
pub(crate) fn cors_check(
    headers: &HeaderList,
    client_origin: &str,
    credentials_include: bool,
) -> Option<String> {
    let allow_origin = headers.get("Access-Control-Allow-Origin");
    if credentials_include {
        // With credentials, the server must both allow the exact origin and
        // send `Access-Control-Allow-Credentials: true`.
        let allow_credentials = headers.get("Access-Control-Allow-Credentials");
        if allow_credentials.as_deref() != Some("true") {
            return None;
        }
    }
    check_allow_origin(allow_origin.as_deref(), client_origin, credentials_include)
}

/// Fetch spec `mode: "same-origin"` enforcement: the request (and every
/// redirect hop) must stay same-origin; a cross-origin final URL is a network
/// error. Returns the error message on violation, `None` when allowed.
///
/// `data:` URLs are same-origin with any client per the Fetch scheme fetch
/// algorithm, so they never trip the check regardless of the client origin.
#[cfg(feature = "fetch_cors_cookie")]
pub(crate) fn same_origin_violation(
    client_origin: Option<&str>,
    final_url: &str,
) -> Option<String> {
    if final_url.to_ascii_lowercase().starts_with("data:") {
        return None;
    }
    let req_origin = url::Url::parse(final_url)
        .map(|u| u.origin().ascii_serialization())
        .unwrap_or_default();
    let same = client_origin == Some(req_origin.as_str());
    if same {
        None
    } else {
        Some(format!(
            "request failed: mode 'same-origin' requires a same-origin \
             request, but URL is cross-origin: {final_url}"
        ))
    }
}

/// Fetch spec: enforce `Cross-Origin-Resource-Policy` on a `no-cors` response.
/// `same-origin` requires the client origin to be same-origin with the response
/// URL; `same-site` requires them to be same-site — same scheme and same host
/// (port ignored), since aike carries no public-suffix list. Returns the error
/// message on violation, `None` when the response is allowed through.
#[cfg(feature = "fetch_cors_cookie")]
pub(crate) fn corp_violation(
    headers: &HeaderList,
    client_origin: Option<&str>,
    final_url: &str,
) -> Option<String> {
    let value = headers.get("Cross-Origin-Resource-Policy")?;
    // Structured-field tokens are case-sensitive: only the exact `same-origin`
    // / `same-site` members enforce anything (WPT `syntax.any.js` asserts that
    // `SAME-ORIGIN` is not honoured).
    let value = value.trim();
    let req = url::Url::parse(final_url).ok()?;
    let client = client_origin?;
    if client == req.origin().ascii_serialization() {
        // Same-origin satisfies both policy values.
        return None;
    }
    // HTML "same site" is schemeful: `http://a.test:1234` and
    // `https://a.test:8443` are *schemelessly* same site but not same site, and
    // the port is ignored either way. (WPT `cross-origin-resource-policy`: the
    // cross-scheme HTTP→HTTPS case must be blocked, the same-scheme
    // different-port case must not.) There is no public-suffix list here, so
    // the host is compared as-is.
    let same_site = url::Url::parse(client)
        .ok()
        .zip(req.host_str())
        .is_some_and(|(c, h)| c.host_str() == Some(h) && c.scheme() == req.scheme());
    match value {
        "same-origin" => Some(format!(
            "request failed: 'no-cors' response is cross-origin and blocked by \
             Cross-Origin-Resource-Policy: same-origin ({final_url})"
        )),
        "same-site" if !same_site => Some(format!(
            "request failed: 'no-cors' response is not same-site and blocked by \
             Cross-Origin-Resource-Policy: same-site ({final_url})"
        )),
        _ => None,
    }
}

/// Server build: no Cross-Origin-Resource-Policy enforcement.
#[cfg(not(feature = "fetch_cors_cookie"))]
pub(crate) fn corp_violation(
    _headers: &HeaderList,
    _client_origin: Option<&str>,
    _final_url: &str,
) -> Option<String> {
    None
}

/// Server build: no same-origin mode semantics; the check never fires.
#[cfg(not(feature = "fetch_cors_cookie"))]
pub(crate) fn same_origin_violation(
    _client_origin: Option<&str>,
    _final_url: &str,
) -> Option<String> {
    None
}

/// Split a header value on commas, trimming whitespace around each item
/// (Fetch spec "get, decode, and split"). Empty items are dropped.
pub(crate) fn split_header_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// CORS-filter the response header list for a `cors` filtered response
/// (Fetch spec §5.1.2).
///
/// Keeps: CORS-safelisted response headers, plus any header named in
/// `Access-Control-Expose-Headers` (or everything except the CORS-forbidden
/// set when expose-headers is `*` and credentials mode is not `include`).
/// `Set-Cookie`/`Set-Cookie2` are always dropped.
pub(crate) fn cors_filter_response_headers(
    headers: &HeaderList,
    expose_headers: Option<&str>,
    credentials_include: bool,
) -> Vec<(String, String)> {
    let expose = expose_headers.map(split_header_list).unwrap_or_default();
    let wildcard = !credentials_include && expose.iter().any(|e| e == "*");

    headers
        .entries()
        .into_iter()
        .filter(|(name, _)| {
            let lower = name.to_lowercase();
            if CORS_FORBIDDEN_RESPONSE_HEADERS
                .iter()
                .any(|f| f.eq_ignore_ascii_case(&lower))
            {
                return false;
            }
            if CORS_SAFELISTED_RESPONSE_HEADERS
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&lower))
            {
                return true;
            }
            if wildcard {
                return true;
            }
            expose.iter().any(|e| e.eq_ignore_ascii_case(&lower))
        })
        .collect()
}

/// Compute the sorted list of non-CORS-safelisted request-header names for a
/// preflight's `Access-Control-Request-Headers` (lowercased, sorted,
/// deduplicated — matching what the WPT server echoes back).
pub(crate) fn preflight_request_headers(headers: &[(String, String)]) -> Vec<String> {
    let mut names: Vec<String> = headers
        .iter()
        .filter(|(name, value)| is_cors_unsafe_request_header(name, value))
        .map(|(name, _)| name.to_lowercase())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Build the `Access-Control-Request-Headers` value from a sorted name list.
pub(crate) fn join_request_headers(names: &[String]) -> String {
    names.join(",")
}

// ---------------------------------------------------------------------------
// Per-hop preflight gate — execution machinery is browser-builds-only
// ---------------------------------------------------------------------------

/// CORS-preflight inputs carried on a fetch request. The requested-header
/// names and method are constant across redirect hops; only the target URL
/// and CORS taint flag vary. `possible` is precomputed: whether this request
/// *would* need a preflight once it is CORS-tainted (non-safelisted method or
/// header). A tainted hop runs a preflight iff `possible` is set.
///
/// Constructed by the shared fetch pipeline in both builds; only browser
/// builds ever read the fields.
#[cfg_attr(not(feature = "fetch_cors_cookie"), allow(dead_code))]
pub(crate) struct PreflightCtx {
    /// Whether a preflight is ever needed for this request (method or header
    /// not CORS-safelisted). Drives the per-hop decision once tainted.
    pub possible: bool,
    /// The request's method (for `Access-Control-Request-Method` and method
    /// checking).
    pub method: String,
    /// Sorted, comma-joined non-safelisted request-header names
    /// (`Access-Control-Request-Headers`).
    pub request_headers: String,
    /// Serialized client origin (for the preflight's `Origin` header and the
    /// `Access-Control-Allow-Origin` comparison).
    pub client_origin: String,
    /// Whether the fetch `credentials` mode is "include" (drives the
    /// credentialed-preflight Allow-Origin/Allow-Credentials rules).
    pub credentials_include: bool,
    /// `User-Agent` to send on the preflight (must match the actual request so
    /// the server can verify it, e.g. WPT `checkUserAgentHeaderInPreflight`).
    pub user_agent: String,
}

#[cfg(feature = "fetch_cors_cookie")]
mod preflight {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex, OnceLock},
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::fetch::{
        headers::HeaderList,
        transport::{BeforeHopFuture, BeforeHopHook},
    };

    use super::{PreflightCtx, cors_check, cors_safelisted_method, split_header_list};

    /// Build the per-hop gate installed on a fetch `TransportRequest`. The
    /// transport invokes the hook before every CORS-tainted hop (initial URL
    /// and each redirect target); the hook decides whether a fresh OPTIONS
    /// preflight is due for that hop and runs it. Requests that can never need
    /// a preflight get `None`.
    pub(crate) fn make_before_hop_hook(pf: Option<PreflightCtx>) -> Option<BeforeHopHook> {
        pf.map(|pf| {
            // Shared with the returned futures so the closure stays `Fn` (each
            // invocation hands out an owned `Arc` clone, not a borrow of the
            // closure's captured state). The future owns its inputs (cheap
            // `reqwest::Client` clone, owned strings) so it is `'static` +
            // `Send`.
            let pf = Arc::new(pf);
            Arc::new(
                move |client: &reqwest::Client, url: &str, referrer: &str, creds_stripped: bool| {
                    let pf = Arc::clone(&pf);
                    let client = client.clone();
                    let url = url.to_string();
                    let referrer = referrer.to_string();
                    Box::pin(async move {
                        // Once credentials were stripped on a cross-origin
                        // redirect, the preflight is obsolete when the method
                        // is CORS-safelisted and the only unsafe request
                        // headers were those (now removed) credentials headers.
                        if creds_stripped && preflight_obsolete_after_credential_strip(&pf) {
                            return Ok(());
                        }
                        if !pf.possible {
                            return Ok(());
                        }
                        match run_preflight_hop(&client, &pf, &url, &referrer).await {
                            true => Ok(()),
                            false => {
                                Err("request failed: CORS preflight did not succeed".to_string())
                            }
                        }
                    }) as BeforeHopFuture
                },
            ) as BeforeHopHook
        })
    }

    /// Run (and validate) a CORS preflight against `url`, consulting the
    /// preflight cache first. Returns `true` on success. A failed preflight —
    /// network error, a redirect/4xx/5xx status, or missing Allow-* headers —
    /// returns `false` and aborts the fetch.
    async fn run_preflight_hop(
        client: &reqwest::Client,
        pf: &PreflightCtx,
        url: &str,
        referrer: &str,
    ) -> bool {
        let requested_headers: Vec<String> = if pf.request_headers.is_empty() {
            Vec::new()
        } else {
            pf.request_headers
                .split(',')
                .map(|s| s.to_string())
                .collect()
        };
        let cache_key = preflight_cache_key(&pf.client_origin, url, &pf.method, &requested_headers);
        if preflight_cache_hit(&cache_key) {
            return true;
        }

        let preflight = PreflightRequest {
            url: url.to_string(),
            request_method: pf.method.clone(),
            request_headers: pf.request_headers.clone(),
            origin: pf.client_origin.clone(),
            user_agent: pf.user_agent.clone(),
            referrer: referrer.to_string(),
        };
        let (status, raw_headers) = match perform_preflight(client, &preflight).await {
            Ok(r) => r,
            Err(_) => return false,
        };
        let headers = HeaderList::from_vec(raw_headers);
        if !check_preflight(
            status,
            &headers,
            &pf.client_origin,
            pf.credentials_include,
            &pf.method,
            &requested_headers,
        ) {
            return false;
        }
        // Cache the successful preflight per `Access-Control-Max-Age`.
        let max_age = headers
            .get("Access-Control-Max-Age")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);
        preflight_cache_store(&cache_key, max_age);
        true
    }

    /// Whether a preflight becomes unnecessary once credentials headers were
    /// stripped on a cross-origin redirect. True when the method is
    /// CORS-safelisted and every unsafe request header the preflight was asking
    /// about is one of the credentials headers
    /// (`Authorization`/`Proxy-Authorization`/`Cookie`) that a cross-origin
    /// redirect removes. In that case the stripped request no longer triggers a
    /// preflight (Fetch spec re-runs CORS-preflight per hop against the actual
    /// header set).
    fn preflight_obsolete_after_credential_strip(pf: &PreflightCtx) -> bool {
        if !cors_safelisted_method(&pf.method) {
            return false;
        }
        pf.request_headers.split(',').all(|h| {
            let h = h.trim().to_ascii_lowercase();
            h == "authorization" || h == "proxy-authorization" || h == "cookie"
        })
    }

    /// Validate a preflight response (Fetch spec "CORS-preflight fetch" /
    /// "CORS-preflight request" checking).
    ///
    /// Returns `true` when the preflight succeeded. A preflight fails on:
    /// - a redirect status (301/302/303/307/308) — the preflight is not followed;
    /// - any status outside 200–299;
    /// - `Access-Control-Allow-Methods` not covering the request method;
    /// - `Access-Control-Allow-Headers` not covering every requested header;
    /// - a failed `Access-Control-Allow-Origin` check (for credentialed requests
    ///   the wildcard is not allowed, and `Allow-Credentials` must be true).
    ///
    /// `requested_headers` is the sorted list of non-safelisted request-header
    /// names (lowercased) that the preflight must ask permission for.
    fn check_preflight(
        status: u16,
        headers: &HeaderList,
        client_origin: &str,
        credentials_include: bool,
        method: &str,
        requested_headers: &[String],
    ) -> bool {
        // Preflights must not follow redirects.
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            return false;
        }
        if !(200..=299).contains(&status) {
            return false;
        }

        // Allow-Origin check (same rules as the non-preflight CORS check).
        if cors_check(headers, client_origin, credentials_include).is_none() {
            return false;
        }

        // Allow-Methods must be a list of valid method tokens; an invalid token
        // (e.g. one containing a space) fails the whole preflight (Fetch spec:
        // "CORS-preflight fetch" parses it as a header list, and any invalid
        // item is a network error).
        let allow_methods = headers.get("Access-Control-Allow-Methods");
        if let Some(am) = allow_methods.as_deref() {
            let list = split_header_list(am);
            if !list.iter().all(|m| is_valid_http_token(m)) {
                return false;
            }
            // Method matching is byte-case-insensitive for CORS-safelisted
            // methods (GET/HEAD/POST) and byte-case-sensitive for everything
            // else (Fetch spec; the method-normalize step uppercases the 6
            // known methods but not custom ones like `patch`).
            let covered = list.iter().any(|m| {
                if m == "*" {
                    // The `*` wildcard covers any method only without
                    // credentials; but an exact `*` request method matches even
                    // with credentials (Fetch spec: character match beats the
                    // credentials rule).
                    return !credentials_include || method == "*";
                }
                if cors_safelisted_method(method) {
                    m.eq_ignore_ascii_case(method)
                } else {
                    m == method
                }
            });
            if !covered {
                return false;
            }
        } else if !cors_safelisted_method(method) {
            // A non-safelisted method needs an `Access-Control-Allow-Methods`.
            return false;
        }

        // Allow-Headers must be a list of valid header names; an invalid item
        // (e.g. `Bad value`) fails the whole preflight.
        if !requested_headers.is_empty() {
            let allow_headers = headers.get("Access-Control-Allow-Headers");
            let list = allow_headers
                .as_deref()
                .map(split_header_list)
                .unwrap_or_default();
            if !list.iter().all(|h| is_valid_header_name(h)) {
                return false;
            }
            let wildcard = list.iter().any(|h| h == "*");
            let covered = requested_headers.iter().all(|rh| {
                let non_wildcard = is_cors_non_wildcard_request_header_name(rh);
                if non_wildcard {
                    // `*` does not cover these; must be explicitly listed.
                    list.iter().any(|h| h.eq_ignore_ascii_case(rh))
                } else if wildcard && !credentials_include {
                    true
                } else {
                    list.iter().any(|h| h.eq_ignore_ascii_case(rh))
                }
            });
            if !covered {
                return false;
            }
        }

        true
    }

    /// Whether `s` is a valid HTTP token (used for header names / methods). A
    /// value containing anything other than tchars (e.g. a space) is invalid.
    fn is_valid_http_token(s: &str) -> bool {
        !s.is_empty()
            && s.bytes().all(|b| {
                matches!(b,
                    b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z'
                    | b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*'
                    | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~')
            })
    }

    /// A valid HTTP header name is a non-empty HTTP token.
    fn is_valid_header_name(s: &str) -> bool {
        is_valid_http_token(s)
    }

    /// CORS non-wildcard request-header names (Fetch spec): `*` in
    /// `Access-Control-Allow-Headers` does not cover these; they must be listed
    /// explicitly. `Sec-*` is also excluded but scripts cannot set those anyway.
    fn is_cors_non_wildcard_request_header_name(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        lower == "authorization" || lower == "proxy-authorization" || lower.starts_with("sec-")
    }

    /// Preflight request parameters for a CORS preflight.
    #[derive(Clone)]
    struct PreflightRequest {
        url: String,
        /// Value of `Access-Control-Request-Method` (the request's method).
        request_method: String,
        /// Sorted, comma-joined `Access-Control-Request-Headers` value (may be empty).
        request_headers: String,
        /// The client's serialized origin (for the `Origin` header).
        origin: String,
        /// `User-Agent` to send on the preflight (must match the actual request so
        /// the server can verify it, e.g. WPT's `checkUserAgentHeaderInPreflight`).
        user_agent: String,
        /// `Referer` to send on the preflight (same value as the actual request).
        /// "about:client" or empty means no `Referer` header.
        referrer: String,
    }

    /// Send a CORS preflight (OPTIONS) request and return the response status
    /// and raw header list for validation. Preflights never follow redirects (a
    /// redirect is a hard failure per the Fetch spec), so this is a single
    /// request.
    async fn perform_preflight(
        client: &reqwest::Client,
        preflight: &PreflightRequest,
    ) -> Result<(u16, Vec<(String, String)>), ()> {
        let mut rb = client
            .request(reqwest::Method::OPTIONS, &preflight.url)
            .header(reqwest::header::ACCEPT, "*/*")
            .header("Origin", &preflight.origin)
            .header("Access-Control-Request-Method", &preflight.request_method)
            // Fetch Metadata headers are appended to the preflight too; WPT's
            // `echo-as-json.py` rejects an OPTIONS without `Sec-Fetch-Mode: cors`.
            .header("Sec-Fetch-Dest", "empty")
            .header("Sec-Fetch-Mode", "cors")
            .header("User-Agent", &preflight.user_agent);
        if let Some(site) = super::fetch_site(Some(&preflight.origin), &preflight.url) {
            rb = rb.header("Sec-Fetch-Site", site);
        }

        if !preflight.request_headers.is_empty() {
            rb = rb.header("Access-Control-Request-Headers", &preflight.request_headers);
        }
        // The preflight carries the same `Referer` as the actual request (the UA
        // sets it; WPT checks it via `x-preflight-referrer`).
        if !preflight.referrer.is_empty() && preflight.referrer != "about:client" {
            rb = rb.header("Referer", &preflight.referrer);
        }

        let resp = rb.send().await.map_err(|_| ())?;

        let status = resp.status();
        // Decode values as latin-1, not UTF-8: a header value is a byte string
        // and bytes 0x80-0xFF are legal (RFC 7230 obs-text); `to_str()` would
        // drop the whole header on such values.
        let raw_headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                let vs = v.as_bytes().iter().map(|&b| b as char).collect::<String>();
                (k.to_string(), vs)
            })
            .collect();

        Ok((status.as_u16(), raw_headers))
    }

    struct PreflightCacheEntry {
        expiry_secs: u64,
    }

    /// Shared in-memory CORS preflight cache (Fetch spec §CORS-preflight fetch,
    /// step "If cache contains a CORS-preflight cache entry"). Keyed by the
    /// request's origin, URL, method, and requested-header names.
    type PreflightCache = Mutex<HashMap<String, PreflightCacheEntry>>;

    static PREFLIGHT_CACHE: OnceLock<PreflightCache> = OnceLock::new();

    fn preflight_cache() -> &'static PreflightCache {
        PREFLIGHT_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn now_unix_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Build the cache key for a preflight.
    fn preflight_cache_key(
        origin: &str,
        url: &str,
        method: &str,
        requested_headers: &[String],
    ) -> String {
        let mut parts = vec![
            origin.to_string(),
            url.to_string(),
            method.to_ascii_lowercase(),
        ];
        parts.extend(requested_headers.iter().cloned());
        parts.join("\u{0}")
    }

    /// Whether a valid (unexpired) cached preflight exists for `key`.
    fn preflight_cache_hit(key: &str) -> bool {
        let mut cache = preflight_cache().lock().unwrap();
        let now = now_unix_secs();
        match cache.get(key) {
            Some(e) if e.expiry_secs > now => true,
            Some(_) => {
                cache.remove(key);
                false
            }
            None => false,
        }
    }

    /// Store a successful preflight for `key` with the given `max_age`
    /// (seconds). `max_age == 0` disables caching (Fetch spec: 0 or absent → no
    /// cache entry).
    fn preflight_cache_store(key: &str, max_age: u64) {
        if max_age == 0 {
            return;
        }
        let mut cache = preflight_cache().lock().unwrap();
        cache.insert(
            key.to_string(),
            PreflightCacheEntry {
                expiry_secs: now_unix_secs() + max_age,
            },
        );
    }
}

#[cfg(feature = "fetch_cors_cookie")]
pub(crate) use preflight::make_before_hop_hook;

/// Server build: no client-origin concept exists, so no hop ever needs a gate.
#[cfg(not(feature = "fetch_cors_cookie"))]
pub(crate) fn make_before_hop_hook(
    _pf: Option<PreflightCtx>,
) -> Option<crate::fetch::transport::BeforeHopHook> {
    None
}
