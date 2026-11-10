// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

use std::{
    error::Error,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{Engine, alphabet, engine::general_purpose};
use zuqe::{ErrorKind, Exception, JSResult, JSValue, ScopedContext};

use crate::fetch::{
    config::HttpClientConfig, cors::corp_violation, headers::normalize_header_value,
};

/// Async gate invoked by the redirect loop before each hop that the request
/// owner flagged as needing one. This is a neutral extension point: the
/// WHATWG fetch layer installs a CORS-preflight gate here (browser builds);
/// everything else passes `None`. Arguments: `(client, hop URL, hop referrer,
/// credentials-stripped flag)`. An `Err(message)` aborts the whole fetch with
/// that error message.
pub(crate) type BeforeHopFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
pub(crate) type BeforeHopHook =
    Arc<dyn Fn(&reqwest::Client, &str, &str, bool) -> BeforeHopFuture + Send + Sync>;

/// Per-request data passed to [`perform_request`].
///
/// Contains only request-level fields.  Client-level settings (proxy, TLS,
/// cookie jar, redirect policy, …) belong in
/// [`HttpClientConfig`](crate::fetch::config::HttpClientConfig) and are baked into
/// the `reqwest::Client` at construction time.
#[derive(Clone)]
pub(crate) struct TransportRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    /// Total time budget for the request (connect + response head + body), or
    /// `None` when the caller set no `timeout` (browsers impose no total cap).
    pub timeout: Option<Duration>,
    /// Referrer URL for the initial hop; "about:client" means no Referer header.
    pub referrer: String,
    /// Inputs needed to recompute the referrer on each redirect hop. `None`
    /// disables manual redirect following (the client's own policy applies).
    pub referrer_ctx: Option<ReferrerCtx>,
    /// Whether the body may be sent a second time. False for a stream body,
    /// which the first attempt consumes, disabling the 421 retry.
    pub replayable: bool,
    /// Per-hop gate (e.g. a CORS preflight), invoked before the initial hop
    /// and before every redirect hop the request is tainted on. `None` when
    /// no gate applies.
    pub before_hop: Option<BeforeHopHook>,
    /// Whether the request follows the WHATWG cors-mode rules (per-hop Origin
    /// recomputation and the opaque-origin rule on cross-origin redirects).
    pub cors_mode: bool,
    /// Whether the initial request is CORS-tainted (cors mode + cross-origin).
    pub cors_tainted: bool,
    /// Serialized client origin (the document origin). Used as the `Origin`
    /// value; an opaque origin (after a cross-origin redirect of a cors request)
    /// is the literal `null`.
    pub cors_client_origin: String,
    /// The fetch `credentials` mode: "omit" | "same-origin" | "include". Drives
    /// whether cookies are sent/stored (via the shared global jar).
    pub credentials_mode: String,
    /// Whether this request manages cookies manually via the shared global jar
    /// (the WHATWG `fetch` path). The low-level HTTP client API keeps reqwest's
    /// own per-client cookie store and does not touch the global jar.
    pub use_shared_cookies: bool,
    /// The request's `cache` mode ("default" | "no-store" | "reload" |
    /// "no-cache" | "force-cache" | "only-if-cached"). The transport derives the
    /// UA-owned `Cache-Control` / `Pragma` request headers from it (both are
    /// forbidden header names, so JS cannot set them).
    pub cache_mode: String,
    /// Whether `Cross-Origin-Resource-Policy` must be enforced on each response:
    /// true for a `no-cors` request in a browser build.
    pub corp_check: bool,
}

/// Policy inputs carried across redirects so each hop can recompute its own
/// `Referer` value. Without this the initial header would be replayed verbatim,
/// which breaks `origin-when-cross-origin` when a hop crosses origins.
#[derive(Clone)]
pub(crate) struct ReferrerCtx {
    /// The request's `referrer` field ("about:client" or an explicit URL).
    pub referrer: String,
    pub policy: String,
    pub client_origin: Option<String>,
    pub client_url: Option<String>,
    /// Maximum hops to follow before reporting a redirect error.
    pub max_redirects: usize,
}

/// Result of [`perform_request`]. `resp` is kept open for lazy body streaming.
pub(crate) struct TransportResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub content_type: String,
    pub content_length: Option<u64>,
    /// Negotiated HTTP version: "0.9" | "1.0" | "1.1" | "2" | "3".
    pub http_version: &'static str,
    pub resp: Option<reqwest::Response>,
    /// Final URL after redirects. Recorded before `resp` is taken/consumed so
    /// the fetch layer always has the post-redirect URL even after the body is
    /// read (the `Response.url` property must reflect the last URL in the chain).
    pub final_url: String,
    /// Pre-decoded body for non-network responses (e.g. `data:` URLs).
    pub synthetic_body: Option<Vec<u8>>,
    /// The request's origin became opaque ("null") via a cross-origin redirect.
    /// The WHATWG fetch layer runs the final CORS check against the request's
    /// actual origin, which is "null" in that case (not the client origin).
    pub origin_opaque: bool,
}

/// WHATWG "data: URL processor": returns `(mimeType, body)`. A missing comma
/// or invalid base64 is a failure (a network error in fetch).
fn decode_data_url(url: &str) -> Result<(String, Vec<u8>), String> {
    // Exclude the fragment, then strip the "data:" scheme.
    let input = url["data:".len()..].split('#').next().unwrap_or_default();
    let (mime_raw, body) = input
        .split_once(',')
        .ok_or_else(|| "data: URL has no comma separator".to_string())?;

    // A trailing ";base64" (case-insensitive, spaces allowed before ';') marks a base64 body.
    let trimmed = mime_raw.trim_matches(is_ascii_ws);
    let (mime, is_base64) = match trimmed.len().checked_sub("base64".len()) {
        Some(i) if trimmed.is_char_boundary(i) && trimmed[i..].eq_ignore_ascii_case("base64") => {
            match trimmed[..i].trim_end_matches(' ').strip_suffix(';') {
                Some(m) => (m, true),
                None => (trimmed, false),
            }
        }
        _ => (trimmed, false),
    };

    // An empty or unparsable MIME type falls back to the spec default.
    let mime = if mime.starts_with(';') {
        format!("text/plain{mime}")
    } else {
        mime.to_string()
    };
    let content_type =
        parse_mime(&mime).unwrap_or_else(|| "text/plain;charset=US-ASCII".to_string());

    let bytes = percent_decode(body.as_bytes());
    let bytes = if is_base64 {
        forgiving_base64_decode(&bytes).map_err(|e| format!("invalid base64 in data: URL: {e}"))?
    } else {
        bytes
    };
    Ok((content_type, bytes))
}

/// ASCII whitespace as defined by the WHATWG Infra standard.
fn is_ascii_ws(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\x0c' | '\r' | ' ')
}

/// WHATWG "forgiving-base64 decode": padding is optional and ASCII whitespace is ignored.
fn forgiving_base64_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    const ENGINE: general_purpose::GeneralPurpose = general_purpose::GeneralPurpose::new(
        &alphabet::STANDARD,
        general_purpose::NO_PAD.with_decode_allow_trailing_bits(true),
    );
    let mut data: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !matches!(b, b'\t' | b'\n' | b'\x0c' | b'\r' | b' '))
        .collect();
    if data.len().is_multiple_of(4) {
        if data.ends_with(b"==") {
            data.truncate(data.len() - 2);
        } else if data.ends_with(b"=") {
            data.truncate(data.len() - 1);
        }
    }
    if data.len() % 4 == 1 {
        return Err("invalid length".into());
    }
    if data
        .iter()
        .any(|b| !(b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/'))
    {
        return Err("invalid character".into());
    }
    ENGINE.decode(data).map_err(|e| e.to_string())
}

/// HTTP token code point (RFC 9110 `tchar`).
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
}

/// WHATWG MIME Sniffing "parse a MIME type", returning the serialized form.
/// Malformed parameters are skipped; a malformed type or subtype is `None`.
fn parse_mime(input: &str) -> Option<String> {
    let input = input.trim_matches(is_ascii_ws);
    let (ty, rest) = input.split_once('/')?;
    let (sub, params) = match rest.split_once(';') {
        Some((s, p)) => (s.trim_end_matches(is_ascii_ws), p),
        None => (rest.trim_end_matches(is_ascii_ws), ""),
    };
    if !is_token(ty) || !is_token(sub) {
        return None;
    }
    let mut out = format!("{}/{}", ty.to_ascii_lowercase(), sub.to_ascii_lowercase());

    let chars: Vec<char> = params.chars().collect();
    let len = chars.len();
    let mut seen: Vec<String> = Vec::new();
    let mut pos = 0;
    while pos < len {
        while pos < len && chars[pos].is_ascii_whitespace() {
            pos += 1;
        }
        let start = pos;
        while pos < len && chars[pos] != ';' && chars[pos] != '=' {
            pos += 1;
        }
        let name: String = chars[start..pos]
            .iter()
            .collect::<String>()
            .to_ascii_lowercase();
        if pos >= len {
            break;
        }
        if chars[pos] == ';' {
            pos += 1;
            continue;
        }
        pos += 1; // skip '='
        if pos >= len {
            break;
        }
        let value: String = if chars[pos] == '"' {
            // Quoted-string: backslash escapes the next character.
            pos += 1;
            let mut v = String::new();
            while pos < len {
                match chars[pos] {
                    '\\' if pos + 1 < len => {
                        v.push(chars[pos + 1]);
                        pos += 2;
                    }
                    '"' => {
                        pos += 1;
                        break;
                    }
                    c => {
                        v.push(c);
                        pos += 1;
                    }
                }
            }
            while pos < len && chars[pos] != ';' {
                pos += 1;
            }
            v
        } else {
            let start = pos;
            while pos < len && chars[pos] != ';' {
                pos += 1;
            }
            let v: String = chars[start..pos].iter().collect();
            let v = v.trim_end_matches(is_ascii_ws).to_string();
            if v.is_empty() {
                continue;
            }
            v
        };
        let value_ok = value
            .chars()
            .all(|c| c == '\t' || (' '..='~').contains(&c) || ('\u{80}'..='\u{ff}').contains(&c));
        if is_token(&name) && value_ok && !seen.contains(&name) {
            out.push(';');
            out.push_str(&name);
            out.push('=');
            if is_token(&value) {
                out.push_str(&value);
            } else {
                out.push('"');
                for c in value.chars() {
                    if c == '"' || c == '\\' {
                        out.push('\\');
                    }
                    out.push(c);
                }
                out.push('"');
            }
            seen.push(name);
        }
    }
    Some(out)
}

/// Canonical HTTP reason phrase for a status code (IANA registry). The Fetch
/// spec exposes the response's status message via `Response.statusText`; for a
/// real HTTP response this is the status-line reason phrase (200 → "OK",
/// 304 → "Not Modified", ...). Unknown codes fall back to the empty string.
///
/// Two spellings deliberately keep the Node.js table instead of the `http`
/// crate's `canonical_reason()` (which drops the 203 hyphen and capitalizes
/// 418 "Teapot"); everything else comes straight from the crate.
fn canonical_status_text(status: u16) -> String {
    let phrase = match status {
        203 => Some("Non-Authoritative Information"),
        418 => Some("I'm a Teapot"),
        _ => reqwest::StatusCode::from_u16(status)
            .ok()
            .and_then(|s| s.canonical_reason()),
    };
    phrase.unwrap_or_default().to_string()
}

/// Percent-decode a `data:`-URL payload (so the body carries the raw octets,
/// e.g. `%EF%BB%BF` -> UTF-8 BOM bytes). Not a full URI decode: only the
/// escapes matter here, and `+` is not special in this context.
fn percent_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' if i + 2 < input.len() => {
                let hi = (input[i + 1] as char).to_digit(16);
                let lo = (input[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(input[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// Transport failure with a machine-readable category.
///
/// `code` is one of: "timeout" | "connect" | "dns" | "tls" | "redirect" | "other".
pub(crate) struct TransportError {
    pub code: &'static str,
    pub message: String,
}

/// Classify a reqwest error into a short error code for JS-side dispatch.
fn classify(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        return "timeout";
    }
    if e.is_redirect() {
        return "redirect";
    }
    // DNS / TLS causes are buried in the source chain; sniff before the
    // generic connect check (a TLS handshake failure is also is_connect).
    let mut src = std::error::Error::source(e);
    while let Some(s) = src {
        let msg = s.to_string().to_lowercase();
        if msg.contains("dns") {
            return "dns";
        }
        if msg.contains("certificate") || msg.contains("tls") || msg.contains("handshake") {
            return "tls";
        }
        src = s.source();
    }
    if e.is_connect() {
        return "connect";
    }
    "other"
}

/// Map `reqwest::Version` to a short version string.
fn version_str(v: reqwest::Version) -> &'static str {
    match v {
        reqwest::Version::HTTP_09 => "0.9",
        reqwest::Version::HTTP_10 => "1.0",
        reqwest::Version::HTTP_11 => "1.1",
        reqwest::Version::HTTP_2 => "2",
        reqwest::Version::HTTP_3 => "3",
        _ => "",
    }
}

/// Throw a JS `Error` carrying the transport error `code` property, so JS
/// can dispatch on it (e.g. retry on "timeout" but not on "tls").
pub(crate) fn throw_transport_error(cx: &mut ScopedContext, te: TransportError) -> JSResult {
    let mut err = match cx.create_error_object(ErrorKind::Type, &te.message, false) {
        Some(e) => e,
        None => return Err(-1),
    };
    let code = cx.create_string_from_utf8(te.code.as_bytes().to_vec())?;
    err.define_property_value_str(
        cx,
        "code",
        JSValue::make_string(code),
        zuqe::JS_PROP_WRITABLE | zuqe::JS_PROP_CONFIGURABLE,
    )?;
    cx.throw(Exception::Error(err.into()));
    Err(-1)
}

/// Follow redirects by hand, recomputing the `Referer` for every hop and, for
/// `cors`-mode requests, the `Origin` header (Fetch spec redirect handling).
///
/// The client's own redirect policy replays the initial request headers on
/// each hop, which is wrong for `origin-when-cross-origin` (once a hop crosses
/// origins the referrer must collapse to the origin) and for cors requests
/// (a cross-origin redirect makes the origin opaque → `Origin: null`). So the
/// caller disables auto-follow and we re-issue each hop with freshly computed
/// referrer and origin.
///
/// `send` receives `(url, referrer, cors_tainted, origin_opaque)` per hop.
/// `cors_tainted` tracks whether the request is currently CORS-tainted;
/// `origin_opaque` becomes true after a cross-origin redirect of a tainted
/// request, after which the `Origin` header is the literal `null`.
///
/// `preflight`, when `Some`, runs a CORS OPTIONS preflight before each tainted
/// hop's actual request (Fetch spec: a redirect re-enters HTTP-network-or-cache
/// fetch, which re-runs CORS-preflight for the new URL). A failed preflight
/// aborts the whole fetch with a "cors" network error.
#[allow(clippy::too_many_arguments)]
/// A response's headers as a `HeaderList`, latin-1 decoded so bytes 0x80-0xFF
/// survive (a header value is a byte string and obs-text is legal, RFC 7230 —
/// `to_str()` would drop the whole header).
fn response_header_list(resp: &reqwest::Response) -> crate::fetch::headers::HeaderList {
    crate::fetch::headers::HeaderList::from_vec(
        resp.headers()
            .iter()
            .map(|(k, v)| {
                let vs = v.as_bytes().iter().map(|&b| b as char).collect::<String>();
                (k.to_string(), vs)
            })
            .collect(),
    )
}

#[allow(clippy::too_many_arguments)]
async fn follow_redirects<F, Fut>(
    rc: &ReferrerCtx,
    start_url: &str,
    start_referrer: &str,
    start_method: &str,
    cors_mode: bool,
    cors_tainted: bool,
    cors_client_origin: &str,
    corp_check: bool,
    client: &reqwest::Client,
    before_hop: Option<&BeforeHopHook>,
    send: F,
) -> Result<(reqwest::Response, bool), TransportError>
where
    F: Fn(String, String, String, bool, bool, bool, bool) -> Fut,
    Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
{
    let mut url = start_url.to_string();
    let mut referrer = start_referrer.to_string();
    // The referrer already determined for the *initial* request (computed with
    // the init policy against the same-origin initial URL). Redirect responses
    // can only tighten it, never loosen it.
    let initial_referrer = referrer.clone();
    // The request method, which Fetch rewrites to GET on a 301/302/303 redirect
    // of a non-GET/HEAD request (history-preserving behavior; 303 always, and
    // 301/302 per the ubiquitous POST→GET convention the WPT suite asserts).
    let mut method = start_method.to_string();
    // The effective referrer policy, which a redirect response may tighten via
    // its `Referrer-Policy` response header (Fetch spec: the redirect's policy
    // overrides the initiating request's policy for the *next* hop).
    let mut policy = rc.policy.clone();
    let mut tainted = cors_tainted;
    let mut origin_opaque = false;
    // Origin of the previous hop (initially the start URL). When a redirect
    // changes origin, credentials headers (Authorization, Cookie,
    // Proxy-Authorization) must be stripped so they don't leak cross-origin
    // (Fetch spec HTTP-redirect fetch).
    let mut prev_url = start_url.to_string();
    // Whether the hop about to be sent is a *subsequent* one (reached through a
    // redirect). A non-GET/HEAD `Origin` is only sent for the initial request.
    let mut subsequent = false;
    // Set once a hop is reached via a cross-origin redirect: the credentials
    // headers (Authorization, Cookie, Proxy-Authorization) were stripped, so a
    // preflight whose only unsafe headers were those credentials is no longer
    // needed for any subsequent hop.
    let mut credentials_stripped = false;
    // Whether we have already followed at least one redirect. A request whose
    // initial method is non-safe (e.g. POST) must not emit an `Origin` header on
    // any *subsequent* hop, since POST redirects are treated as potentially
    // leaking and browsers strip `Origin`/`Authorization` across them (WPT
    // `redirect-origin.any.js`).
    for _ in 0..=rc.max_redirects {
        // A cross-origin redirect (current URL's origin differs from the
        // previous hop's) strips the credentials headers on this hop.
        let cross_origin_hop = origin_of(&url) != origin_of(&prev_url);
        if cross_origin_hop {
            credentials_stripped = true;
        }

        // A CORS-tainted hop runs the owner's per-hop gate before the actual
        // request (browser builds: a CORS OPTIONS preflight against this hop's
        // URL — Fetch spec: a redirect re-enters HTTP-network-or-cache fetch,
        // which re-runs CORS-preflight for the new URL). A failed gate is a
        // network error and the fetch never reaches the target.
        if tainted
            && let Some(hook) = before_hop
            && let Err(msg) = hook(client, &url, &referrer, credentials_stripped).await
        {
            return Err(TransportError {
                code: "cors",
                message: msg,
            });
        }

        let resp = send(
            method.clone(),
            url.clone(),
            referrer.clone(),
            tainted,
            origin_opaque,
            cross_origin_hop,
            subsequent,
        )
        .await
        .map_err(|e| {
            let mut msg = format!("request failed: {e}");
            let mut src = e.source();
            while let Some(s) = src {
                msg.push_str(&format!("; caused by: {s}"));
                src = s.source();
            }
            TransportError {
                code: classify(&e),
                message: msg,
            }
        })?;

        // Fetch spec: `Cross-Origin-Resource-Policy` is enforced on *every*
        // response in the chain, a redirect's included — a cross-origin 302
        // carrying `CORP: same-origin` is a network error even when the target
        // itself is same-origin (WPT `cross-origin-resource-policy`, the
        // "... redirect response header" cases).
        if corp_check
            && let Some(msg) =
                corp_violation(&response_header_list(&resp), Some(cors_client_origin), &url)
        {
            return Err(TransportError {
                code: "corp",
                message: msg,
            });
        }

        // A redirect without a usable `Location` is delivered as-is; WPT serves
        // `.any.js` via a 302 with an empty `Location` (self-redirect) so the
        // engine must tolerate it and surface the response rather than reject.
        let next = match redirect_target(&resp, &url) {
            Some(u) => u,
            None => return Ok((resp, origin_opaque)),
        };

        // A redirect response's `Referrer-Policy` header overrides the policy
        // used to compute the referrer for the *next* hop (Fetch spec). This is
        // how a server can tighten the referrer after a redirect (e.g. WPT
        // `redirect-referrer-override`).
        if let Some(hdr) = resp
            .headers()
            .get(reqwest::header::HeaderName::from_static("referrer-policy"))
            && let Ok(v) = hdr.to_str()
        {
            let v = v.trim().to_ascii_lowercase();
            if !v.is_empty() {
                policy = v;
            }
        }

        // 301/302/303 rewrite a non-GET/HEAD method to GET for the next hop (the
        // ubiquitous POST→GET behavior; 303 always does). The request body is
        // dropped for GET automatically in `send_once`.
        let status = resp.status().as_u16();
        if matches!(status, 301..=303) && !method_is_safe(&method) {
            method = "GET".to_string();
        }

        // Fetch spec: a cors request must not follow a redirect to a URL that
        // carries credentials (userinfo); that is a network error.
        if cors_mode
            && url::Url::parse(&next)
                .map(|u| u.username() != "" || u.password().is_some())
                .unwrap_or(false)
        {
            return Err(TransportError {
                code: "cors",
                message: format!("request failed: redirect to a URL with credentials ({next})"),
            });
        }

        // Opaque-origin rule: a cors request whose redirect target's origin
        // differs from the current URL's origin gets a unique opaque origin,
        // so its `Origin` header becomes `null`.
        if cors_mode && tainted && origin_of(&url) != origin_of(&next) {
            origin_opaque = true;
        }
        // A cors-mode request becomes CORS-tainted once the current URL is
        // cross-origin with the client (relevant for a same-origin → cross
        // redirect, which starts untamed). `null` (opaque client origin) is
        // always treated as cross-origin.
        let client_is_opaque = cors_client_origin == "null";
        if cors_mode
            && (client_is_opaque || origin_of(&next) != Some(cors_client_origin.to_string()))
        {
            tainted = true;
        }

        // Recompute the referrer against the *next* URL so a hop that changes
        // origin gets the origin-only form.
        //
        // Per the Fetch spec + WPT `redirect-referrer-override`, the referrer of
        // a hop that follows a redirect is the *more conservative* of:
        //   (a) the referrer already determined for the initial request
        //       (`initial_referrer`, computed with the init policy against the
        //       same-origin initial URL), and
        //   (b) the referrer recomputed with the redirect response's
        //       `Referrer-Policy` against the new (possibly cross-origin) URL.
        // A redirect response only ever *tightens* the referrer. An omitted
        // referrer (`""`) always wins, and an origin-only form
        // (`http://h:port/`) is more conservative than a full URL.
        let ref_resp = crate::fetch::compute_request_referrer(
            &rc.referrer,
            &policy,
            rc.client_origin.as_deref(),
            rc.client_url.as_deref(),
            &next,
        )
        .unwrap_or_default();
        referrer = if initial_referrer.is_empty() || ref_resp.is_empty() {
            String::new()
        } else if initial_referrer.len() <= ref_resp.len() {
            initial_referrer.clone()
        } else {
            ref_resp
        };
        prev_url = url;
        url = next;
        subsequent = true;
    }

    Err(TransportError {
        code: "redirect",
        message: format!("too many redirects (limit {})", rc.max_redirects),
    })
}

/// Origin (scheme://host[:port]) of a URL string, or `None` if unparsable.
fn origin_of(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .map(|u| u.origin().ascii_serialization())
}

/// Whether a method is a "safe"/idempotent method (GET or HEAD, case-insensitive).
/// The Fetch spec appends an `Origin` header for any other method.
fn method_is_safe(method: &str) -> bool {
    method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")
}

/// Whether cookies may be sent/stored for a request per its `credentials` mode:
/// "include" always; "same-origin" only when the target URL's origin matches
/// the client origin; "omit" never.
fn cookies_allowed(credentials_mode: &str, client_origin: &str, url: &str) -> bool {
    match credentials_mode {
        "include" => true,
        "same-origin" => url::Url::parse(url)
            .ok()
            .map(|u| u.origin().ascii_serialization() == client_origin)
            .unwrap_or(false),
        _ => false,
    }
}

/// Resolve a redirect response's `Location` against the current URL.
/// Returns `None` when the response is not a redirect or has no valid target.
fn redirect_target(resp: &reqwest::Response, current: &str) -> Option<String> {
    if !matches!(resp.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
        return None;
    }

    let raw = resp.headers().get(reqwest::header::LOCATION)?;
    // A `Location` value is a byte sequence: WPT `redirect-location-escape`
    // sends raw UTF-8 bytes (e.g. a snowman) which are not valid `HeaderValue`
    // text, so `to_str()` fails on them. Percent-encode the non-ASCII bytes
    // rather than dropping the redirect.
    let loc = match raw.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => raw
            .as_bytes()
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect(),
    };
    let base = url::Url::parse(current).ok()?;
    let joined = base.join(&loc).ok()?;
    let joined = joined.to_string();
    Some(joined)
}

/// Perform an HTTP request on a pre-built `reqwest::Client`.
///
/// The caller is responsible for building the client with the desired
/// proxy / TLS / cookie / redirect settings via [`HttpClientConfig`].
pub(crate) async fn perform_request(
    client: &reqwest::Client,
    req: TransportRequest,
) -> Result<TransportResponse, TransportError> {
    // `data:` URLs are not network requests — decode them directly.
    if req.url.to_ascii_lowercase().starts_with("data:") {
        let (content_type, body) = decode_data_url(&req.url).map_err(|e| TransportError {
            code: "other",
            message: e,
        })?;
        // HEAD requests carry no body (fetch spec), even for `data:` URLs.
        let is_head = req.method.eq_ignore_ascii_case("HEAD");
        return Ok(TransportResponse {
            status: 200,
            // Non-network (synthetic) responses such as `data:` URLs get the
            // default status 200 with statusText "OK" and type "default", per
            // the WHATWG fetch scheme fetch algorithm. (Network HTTP responses
            // keep statusText "" — the reason phrase is not exposed to scripts.)
            status_text: "OK".to_string(),
            headers: vec![("content-type".into(), content_type.clone())],
            content_type,
            content_length: Some(body.len() as u64),
            http_version: "1.1",
            resp: None,
            final_url: req.url.clone(),
            synthetic_body: if is_head { None } else { Some(body) },
            origin_opaque: false,
        });
    }

    // WHATWG fetch: a 421 (Misdirected Request) response means the connection
    // was reused for the wrong origin; retry the request exactly once on a
    // fresh connection. The reqwest client is built with
    // `pool_max_idle_per_host(0)`, so a second attempt opens a clean
    // connection (the server counts it as a new connection).
    // Build one request. Owned args keep the returned future free of borrows,
    // so it can be handed to the redirect loop. `cors_tainted`/`origin_opaque`
    // drive the per-hop `Origin` header (Fetch spec redirect handling).
    let send_once = |method: String,
                     url: String,
                     referrer: String,
                     tainted: bool,
                     origin_opaque: bool,
                     cross_origin_hop: bool,
                     subsequent: bool| {
        let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET);
        let mut rb = client.request(method.clone(), &url);
        if let Some(total) = req.timeout {
            rb = rb.timeout(total);
        }

        let mut headers = req.headers.clone();
        // A redirect may rewrite the method to GET (see `follow_redirects`).
        // Such a hop must not carry the original body's headers: Fetch spec
        // "HTTP-redirect fetch" removes `Content-Encoding`, `Content-Language`,
        // `Content-Location` and `Content-Type`, and a stale `Content-Length`
        // would make the server block waiting for a body that is never sent
        // (WPT `redirect-method`: 301/302/303 + POST timed out).
        if !method.as_str().eq_ignore_ascii_case(&req.method) {
            headers.retain(|(k, _)| {
                let k = k.to_ascii_lowercase();
                !matches!(
                    k.as_str(),
                    "content-encoding"
                        | "content-language"
                        | "content-location"
                        | "content-type"
                        | "content-length"
                        | "transfer-encoding"
                )
            });
        }
        // A cross-origin redirect must not leak the request's credentials
        // (Fetch spec HTTP-redirect fetch): strip `Authorization`,
        // `Proxy-Authorization`, and `Cookie` so they don't reach the new
        // origin. Cookies are re-added from the jar below only if the
        // `credentials` mode permits them for this hop's origin.
        if cross_origin_hop {
            headers.retain(|(k, _)| {
                !k.eq_ignore_ascii_case("authorization")
                    && !k.eq_ignore_ascii_case("proxy-authorization")
                    && !k.eq_ignore_ascii_case("cookie")
            });
        }
        if referrer != "about:client" && !referrer.is_empty() {
            let has_referer = headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("referer"));
            if !has_referer {
                headers.push(("Referer".to_string(), referrer));
            }
        }
        // For `cors`-mode requests, recompute the `Origin` header for this hop.
        // Fetch spec "append a request Origin header": a request whose response
        // tainting is "cors" ALWAYS carries `Origin` (so every hop of a
        // cross-origin cors request keeps it, including hops that stay on the
        // same origin as the previous one). Otherwise a non-GET/HEAD request
        // carries it, and a `no-cors` one serializes to `null`. An origin made
        // opaque by a cross-origin redirect serializes to the literal `null`.
        // `Origin` is a forbidden request header, so any caller-provided value
        // is replaced. Non-cors requests keep whatever `Origin` the caller set.
        if req.cors_mode {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("origin"));
            let origin_value: Option<String> = if origin_opaque {
                Some("null".to_string())
            } else if tainted || (!method_is_safe(method.as_str()) && !subsequent) {
                // A hop reached through a redirect drops `Origin` when the
                // request is not CORS-tainted: a POST's `Origin` is only ever
                // sent for the initial request, since redirects are treated as
                // potentially leaking it (WPT `redirect-origin.any.js`: "[POST]
                // Redirect 307 Same origin to same origin" expects no Origin on
                // the target). A 301/302/303 already rewrote the method to GET,
                // so those hops carry none either.
                Some(req.cors_client_origin.clone())
            } else {
                None
            };
            if let Some(ov) = origin_value {
                headers.push(("Origin".to_string(), ov));
            }
        }

        // Fetch cookies from the shared jar when the `credentials` mode permits
        // (include, or same-origin for a same-origin URL). `omit` never sends.
        if req.use_shared_cookies
            && cookies_allowed(&req.credentials_mode, &req.cors_client_origin, &url)
            && let Ok(u) = url::Url::parse(&url)
            && let Some(cv) = crate::fetch::config::global_cookie_jar().cookies(&u)
        {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("cookie"));
            if let Ok(s) = cv.to_str() {
                // Present cookies in creation order (WPT `cookies.any.js`).
                let s = crate::fetch::config::reorder_cookie_header(s);
                headers.push(("Cookie".to_string(), s));
            }
        }

        for (k, v) in &headers {
            // Fetch spec: strip leading/trailing HTTP whitespace (0x09/0x0A/
            // 0x0D/0x20) from header values before they hit the wire.
            let v = normalize_header_value(v);

            // Header values are latin-1 strings (validated in JS). Encode to raw
            // bytes and bypass the http crate's validation so control characters
            // permitted by the Fetch spec (e.g. 0x01) are sent verbatim, matching
            // WPT header-values-normalize expectations. Requires the `http` crate
            // to be compiled without debug-assertions (see aike/Cargo.toml) so
            // `from_maybe_shared_unchecked` skips its UTF-8/byte validity check.
            let bytes: Vec<u8> = v
                .chars()
                .filter_map(|c| {
                    let cp = c as u32;
                    if cp <= 0xFF { Some(cp as u8) } else { None }
                })
                .collect();
            // `http`'s HeaderValue rejects several control bytes that the Fetch
            // spec permits in header values (0x01-0x08, 0x0B, 0x0C, ...). The
            // unchecked constructor sends them verbatim, but asserts in debug
            // builds; prefer graceful failure there over corrupting the run.
            let hv = match reqwest::header::HeaderValue::from_bytes(&bytes) {
                Ok(hv) => hv,
                Err(_) => {
                    #[cfg(not(debug_assertions))]
                    unsafe {
                        reqwest::header::HeaderValue::from_maybe_shared_unchecked(bytes)
                    }
                    #[cfg(debug_assertions)]
                    {
                        // Debug builds assert inside that constructor; drop the
                        // header instead of corrupting the whole run.
                        continue;
                    }
                }
            };
            rb = rb.header(k, hv);
        }

        // Fetch spec "HTTP fetch" (cache mode): `Cache-Control` and `Pragma` are
        // forbidden request header names, so the UA owns them. A caller-supplied
        // value (possible only through a header the spec allows, e.g. a
        // cache-mode-independent one) is left untouched.
        // WPT `http-cache/cache-mode`.
        if !headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("cache-control"))
        {
            if req.cache_mode == "no-cache" {
                rb = rb.header(reqwest::header::CACHE_CONTROL, "max-age=0");
            } else if req.cache_mode == "no-store" {
                rb = rb.header(reqwest::header::CACHE_CONTROL, "no-cache");
            }
        }
        if req.cache_mode == "no-store"
            && !headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("pragma"))
        {
            rb = rb.header(reqwest::header::PRAGMA, "no-cache");
        }

        // Fetch spec "add a range header": a request carrying `Range` must be
        // sent with `Accept-Encoding: identity`, so a compressed body cannot
        // break the byte range. reqwest otherwise advertises its default
        // encodings, and the Fetch layer cannot set this itself because
        // `Accept-Encoding` is a forbidden request header.
        if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("range")) {
            rb = rb.header(reqwest::header::ACCEPT_ENCODING, "identity");
        }

        // A redirect rewrites the method to GET (see `follow_redirects`); a GET
        // request must not carry the original request body, so only attach it for
        // non-GET/HEAD methods.
        if !method_is_safe(method.as_ref())
            && let Some(b) = &req.body
        {
            rb = rb.body(b.clone());
        }

        async move { rb.send().await }
    };

    // One attempt at `url`, transparently retried once on a 421 — but only for
    // a replayable body. A stream body is consumed by the first attempt, so the
    // spec requires the 421 to be surfaced instead.
    let replayable = req.replayable;
    let send_with_retry = move |method: String,
                                url: String,
                                referrer: String,
                                tainted: bool,
                                origin_opaque: bool,
                                cross_origin_hop: bool,
                                subsequent: bool| {
        let first = send_once(
            method.clone(),
            url.clone(),
            referrer.clone(),
            tainted,
            origin_opaque,
            cross_origin_hop,
            subsequent,
        );
        async move {
            match first.await {
                Ok(r) if replayable && r.status() == reqwest::StatusCode::MISDIRECTED_REQUEST => {
                    log::debug!("421 on {url}; retrying once on a fresh connection");
                    send_once(
                        method,
                        url,
                        referrer,
                        tainted,
                        origin_opaque,
                        cross_origin_hop,
                        subsequent,
                    )
                    .await
                }
                other => other,
            }
        }
    };

    let cors_tainted = req.cors_tainted;
    let cors_client_origin = req.cors_client_origin.clone();
    let cors_mode = req.cors_mode;
    let before_hop = req.before_hop.as_ref();
    // Whether the request's origin became opaque (a unique opaque origin) via a
    // cross-origin redirect. Reported on the response so the WHATWG fetch layer
    // can run the final CORS check against the request's actual origin ("null").
    let mut resp_origin_opaque = false;
    let resp = match &req.referrer_ctx {
        Some(rc) => {
            let (r, opaque) = follow_redirects(
                rc,
                &req.url,
                &req.referrer,
                &req.method,
                cors_mode,
                cors_tainted,
                &cors_client_origin,
                req.corp_check,
                client,
                before_hop,
                send_with_retry,
            )
            .await?;
            resp_origin_opaque = opaque;
            r
        }
        None => {
            if cors_tainted
                && let Some(hook) = before_hop
                && let Err(msg) = hook(client, &req.url, &req.referrer, false).await
            {
                return Err(TransportError {
                    code: "cors",
                    message: msg,
                });
            }
            send_with_retry(
                req.method.clone(),
                req.url.clone(),
                req.referrer.clone(),
                cors_tainted,
                false,
                false,
                false,
            )
            .await
            .map_err(|e| {
                let mut msg = format!("request failed: {e}");
                let mut src = e.source();
                while let Some(s) = src {
                    msg.push_str(&format!("; caused by: {s}"));
                    src = s.source();
                }
                TransportError {
                    code: classify(&e),
                    message: msg,
                }
            })?
        }
    };

    // Store `Set-Cookie` response cookies into the shared jar when the
    // `credentials` mode permits, so a later `fetch()` (with include/same-origin)
    // to the same origin sends them (WPT cors-cookies).
    if req.use_shared_cookies
        && cookies_allowed(
            &req.credentials_mode,
            &cors_client_origin,
            resp.url().as_str(),
        )
    {
        let url_for_cookie = resp.url().clone();
        let jar = crate::fetch::config::global_cookie_jar();
        // `get_all` walks the same-name entries in append (wire) order; the
        // generic `headers()` iterator leaves the order of duplicate names
        // unspecified, which reversed the recorded creation order and made the
        // outgoing `Cookie` header come out backwards (WPT `credentials/cookies`
        // "Include mode: 2 cookies": `b=2` is set before `c=3`, so the request
        // must carry `b=2; c=3`).
        for v in resp.headers().get_all(reqwest::header::SET_COOKIE) {
            if let Ok(s) = v.to_str() {
                jar.add_cookie_str(s, &url_for_cookie);
                // Track the first-seen order for the `Cookie` header (WPT).
                crate::fetch::config::cookie_order_record(s);
            }
        }
    }

    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // Decode values as latin-1, not UTF-8: a header value is a byte string and
    // bytes 0x80-0xFF are legal (RFC 7230 obs-text). `to_str()` rejects those,
    // so using it here would silently drop the whole header.
    let raw_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            let vs = v.as_bytes().iter().map(|&b| b as char).collect::<String>();
            (k.to_string(), vs)
        })
        .collect();
    // The header list is exposed as received: duplicate `Content-Length`
    // headers are kept, so `Headers.get` joins them (WPT
    // `content-length/api-and-duplicate-headers` expects "6, 6"). Body framing
    // is hyper's own single-`Content-Length` decision, independent of this list.
    let headers = raw_headers;
    // `Response.statusText` is the response's status message: the HTTP reason
    // phrase for a real response (200 → "OK", 304 → "Not Modified", ...).
    // HTTP/2 has no reason phrase, so the spec mandates an empty `statusText`
    // for h2 responses regardless of the status code (WPT `status.h2.any.js`).
    let http_ver = version_str(resp.version());
    let status_text = if http_ver.starts_with("HTTP/2") {
        String::new()
    } else {
        // hyper preserves a *non-canonical* reason phrase in the response
        // extensions (`hyper::ext::ReasonPhrase`); when it is absent the
        // canonical phrase for the status is implied. reqwest does not
        // re-export the type, hence the direct hyper dependency.
        match resp.extensions().get::<hyper::ext::ReasonPhrase>() {
            Some(reason) => reason.as_bytes().iter().map(|&b| b as char).collect(),
            None => canonical_status_text(status.as_u16()),
        }
    };
    // Read Content-Length from the header: resp.content_length() reports the
    // body size hint, which is erased by the auto-decompression wrapper.
    let content_length = resp
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    let final_url_val = resp.url().to_string();
    let mut tr = TransportResponse {
        status: status.as_u16(),
        status_text,
        headers,
        content_type,
        content_length,
        http_version: version_str(resp.version()),
        resp: Some(resp),
        final_url: final_url_val,
        synthetic_body: None,
        origin_opaque: resp_origin_opaque,
    };
    // WHATWG fetch: 204/205/304 responses and responses to HEAD requests carry
    // no body, so the JS-visible `Response.body` is null and `text()`/etc.
    // resolve to the empty string. Drop the underlying transport so body
    // consumers treat it as a null-body response.
    if req.method.eq_ignore_ascii_case("HEAD") || matches!(tr.status, 204 | 205 | 304) {
        tr.resp = None;
        tr.synthetic_body = None;
    }
    Ok(tr)
}

/// Pre-response budget for the final connection attempt: bounds TCP connect,
/// the TLS handshake, and the wait for the response head. The body is not
/// covered (it has its own idle guard), so a slow-but-alive download is not cut
/// short.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Budget for a non-final attempt. Shorter so a path that accepts TCP but
/// stalls later (a common broken-IPv6 symptom: the handshake hangs after the
/// SYN/ACK) is abandoned quickly in favour of the next address.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum connection attempts for one request: the configured client first,
/// then one attempt pinned to each resolved address.
const MAX_CONNECT_ATTEMPTS: usize = 4;

/// Where one connection attempt is sent.
#[derive(Clone)]
enum Attempt {
    /// The client as built (system resolver order + happy eyeballs).
    Configured,
    /// Pin the host to one resolved address, bypassing the resolver's order.
    Pinned { host: String, addr: SocketAddr },
}

/// Whether a transport error happened before any response head arrived, so the
/// request may be re-sent on another connection. `redirect` is the only class
/// excluded: it is a protocol decision, not a connectivity failure.
fn retryable_connect_error(e: &TransportError) -> bool {
    matches!(e.code, "timeout" | "connect" | "dns" | "tls" | "other")
}

/// Connection attempts for `req`: the configured client, then every resolved
/// address as a pinned fallback (IPv4 first — a dual-stack origin that stalls
/// in the TLS handshake is almost always the IPv6 path, while a `connect`
/// failure can come from either family, so all addresses are still tried).
///
/// Resolved lazily: only called after the first attempt failed, so a healthy
/// request pays no second DNS lookup.
async fn connection_attempts(req: &TransportRequest) -> Vec<Attempt> {
    let mut attempts = vec![Attempt::Configured];
    let Ok(url) = url::Url::parse(&req.url) else {
        attempts.push(Attempt::Configured);
        return attempts;
    };
    let Some(host) = url.host_str() else {
        attempts.push(Attempt::Configured);
        return attempts;
    };
    // An IP literal has exactly one address: the fallback is a plain retry.
    if matches!(url.host(), Some(url::Host::Ipv4(_) | url::Host::Ipv6(_))) {
        attempts.push(Attempt::Configured);
        return attempts;
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let Ok(addrs) = tokio::net::lookup_host((host, port)).await else {
        attempts.push(Attempt::Configured);
        return attempts;
    };
    let mut addrs: Vec<SocketAddr> = addrs.collect();
    // `sort_by_key` is stable, so each family keeps the resolver's order.
    addrs.sort_by_key(|a| a.is_ipv6());
    addrs.dedup();
    if addrs.len() <= 1 {
        attempts.push(Attempt::Configured);
    } else {
        for addr in addrs.into_iter().take(MAX_CONNECT_ATTEMPTS - 1) {
            attempts.push(Attempt::Pinned {
                host: host.to_string(),
                addr,
            });
        }
    }
    attempts
}

/// Perform `req`, transparently retrying connection-stage failures on other
/// addresses.
///
/// Fetch spec "obtain a connection": creating a connection is
/// implementation-defined, may be attempted several times in parallel, and may
/// be retried in case of a timeout; a TLS failure is a connection failure. So a
/// request whose response head never arrived may be re-sent on a fresh
/// connection. Only replayable (non-stream body) idempotent requests are
/// retried, and never past the caller's `timeout` budget. Once a response head
/// has been handed out, retries stop: the body consumer already owns the bytes.
pub(crate) async fn perform_request_retrying(
    cfg: &HttpClientConfig,
    insecure: bool,
    client: &reqwest::Client,
    req: TransportRequest,
) -> Result<TransportResponse, TransportError> {
    let retry_allowed = req.replayable && method_is_safe(&req.method);
    let deadline = req.timeout.map(|total| Instant::now() + total);
    // Resolved on the first retryable failure only.
    let mut attempts: Vec<Attempt> = Vec::new();
    let mut index = 0usize;
    let mut last: Option<TransportError> = None;

    loop {
        let attempt = if index == 0 {
            Attempt::Configured
        } else {
            match attempts.get(index).cloned() {
                Some(a) => a,
                None => break,
            }
        };

        let remaining = match deadline {
            Some(d) => d.saturating_duration_since(Instant::now()),
            None => ATTEMPT_TIMEOUT,
        };
        if remaining.is_zero() {
            break;
        }
        let is_probe = retry_allowed && index + 1 < MAX_CONNECT_ATTEMPTS;
        let budget = remaining.min(if is_probe {
            PROBE_TIMEOUT
        } else {
            ATTEMPT_TIMEOUT
        });

        // A pinned attempt needs its own client: `resolve` is client-level.
        let pinned = match &attempt {
            Attempt::Configured => None,
            Attempt::Pinned { host, addr } => {
                let mut pinned_cfg = cfg.clone();
                pinned_cfg.resolve_overrides = vec![(host.clone(), *addr)];
                pinned_cfg.build_http_client_ex(insecure).ok()
            }
        };
        let attempt_client = pinned.as_ref().unwrap_or(client);

        let mut attempt_req = req.clone();
        // The caller's budget is for the whole fetch, so each attempt only gets
        // what is left of it (bounds this attempt's body transfer too).
        attempt_req.timeout = req.timeout.map(|_| remaining);

        let err = match tokio::time::timeout(budget, perform_request(attempt_client, attempt_req))
            .await
        {
            Ok(Ok(tr)) => return Ok(tr),
            Ok(Err(e)) => e,
            Err(_) => TransportError {
                code: "timeout",
                message: format!("request timed out after {:.1}s", budget.as_secs_f64()),
            },
        };

        if !retry_allowed {
            return Err(err);
        }
        if attempts.is_empty() {
            attempts = connection_attempts(&req).await;
        }
        if index + 1 >= attempts.len() || !retryable_connect_error(&err) {
            return Err(err);
        }
        log::debug!(
            "fetch: connection attempt {} failed ({}), trying the next address",
            index + 1,
            err.code
        );
        last = Some(err);
        index += 1;
    }

    Err(last.unwrap_or_else(|| TransportError {
        code: "timeout",
        message: "request timed out".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::{TransportError, canonical_status_text, retryable_connect_error};

    fn err(code: &'static str) -> TransportError {
        TransportError {
            code,
            message: String::new(),
        }
    }

    #[test]
    fn connect_failures_are_retryable() {
        // No response head arrived: re-sending on a fresh connection is safe.
        for code in ["timeout", "connect", "dns", "tls", "other"] {
            assert!(retryable_connect_error(&err(code)), "{code} must retry");
        }
        // A redirect verdict is a protocol decision, not a connectivity failure.
        assert!(!retryable_connect_error(&err("redirect")));
    }

    #[test]
    fn known_phrases_unchanged() {
        // spot-check the old table's exact spellings (incl. the two
        // Node-compat overrides) plus a spread of methods
        assert_eq!(canonical_status_text(100), "Continue");
        assert_eq!(canonical_status_text(200), "OK");
        assert_eq!(canonical_status_text(203), "Non-Authoritative Information");
        assert_eq!(canonical_status_text(304), "Not Modified");
        assert_eq!(canonical_status_text(418), "I'm a Teapot");
        assert_eq!(canonical_status_text(414), "URI Too Long");
        assert_eq!(canonical_status_text(451), "Unavailable For Legal Reasons");
        assert_eq!(canonical_status_text(505), "HTTP Version Not Supported");
    }

    #[test]
    fn codes_added_from_http_crate() {
        // previously "" in the old table; now real phrases
        for (code, phrase) in [
            (102u16, "Processing"),
            (103, "Early Hints"),
            (207, "Multi-Status"),
            (208, "Already Reported"),
            (226, "IM Used"),
            (422, "Unprocessable Entity"),
            (423, "Locked"),
            (424, "Failed Dependency"),
            (425, "Too Early"),
            (511, "Network Authentication Required"),
        ] {
            assert_eq!(canonical_status_text(code), phrase);
        }
    }

    #[test]
    fn unknown_codes_empty() {
        assert_eq!(canonical_status_text(599), "");
        assert_eq!(canonical_status_text(0), "");
        assert_eq!(canonical_status_text(999), "");
    }
}
