// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! A minimal HTTP response cache (RFC 7234 / Fetch § HTTP-cache).
//!
//! Supports the cache modes exercised by WPT `fetch/api/request/request-cache-*`:
//! `default`, `no-store`, `reload`, `no-cache`, `force-cache`, `only-if-cached`.
//!
//! A successful GET response is remembered keyed by method + URL. Freshness is
//! judged from `Cache-Control: max-age` or `Expires`; a stale entry is
//! revalidated with conditional headers (`If-None-Match` / `If-Modified-Since`),
//! and a `304` is turned back into the cached response with the 304 headers
//! merged on top, as the Fetch spec requires.

use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

/// Snapshot of a stored response returned to the caller.
pub(crate) struct CacheHit {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Whether the entry is fresh per its `max-age`/`Expires` headers.
    pub fresh: bool,
    /// RFC 5861: whether the entry is stale but still inside its
    /// `stale-while-revalidate` window, so it may be served while a
    /// revalidation runs.
    pub swr: bool,
    /// The response's final URL after redirects (the requested URL when no
    /// redirect was followed), used for same-origin checks.
    pub final_url: String,
}

/// A cached successful response.
struct CacheEntry {
    status: u16,
    /// Lowercased-name → value header list of the stored response.
    headers: Vec<(String, String)>,
    /// Buffered body.
    body: Vec<u8>,
    /// `ETag` validator, if present.
    etag: Option<String>,
    /// `Last-Modified` validator, if present.
    last_modified: Option<String>,
    /// When the entry was stored (epoch seconds), for freshness calculation.
    stored_at: u64,
    /// Final response URL after redirects (same as key URL when not redirected).
    final_url: String,
    /// The `Vary` field names (lowercased) the stored response declared.
    vary: Vec<String>,
    /// The request headers this entry was stored for, used to decide whether a
    /// later request matches the `Vary` fields.
    req_headers: Vec<(String, String)>,
}

/// Upper bound on a body we are willing to hold in the in-memory cache.
///
/// The cache is an in-memory map; buffering an unbounded body (e.g. the 8GiB
/// file in WPT `huge-fetch`) would OOM the process or yield an empty chunk.
/// Responses larger than this are not cached (the spec does not require caching
/// every response), and the caller is expected to stream such bodies to the
/// consumer instead of buffering them.
pub(crate) const MAX_CACHE_BODY_BYTES: u64 = 64 * 1024 * 1024;

/// Upper bound on the stored variants for one URL. RFC 9111 §4.1 lets a URL
/// hold a separate response per `Vary` combination; cap the fan-out so a
/// pathological URL cannot grow the in-memory cache without bound.
const MAX_VARIANTS_PER_URL: usize = 16;

/// Global, process-wide cache. Keyed by (method, url); each value holds one
/// entry per `Vary` variant (RFC 9111 §4.1).
static CACHE: LazyLock<Mutex<HashMap<(String, String), Vec<CacheEntry>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Canonical URL used for cache keying.
///
/// The raw request string is not canonical: e.g. a doubled slash
/// (`http://h//p`) is a different string from its parsed form
/// (`http://h/p`), and the WHATWG URL parser collapses it. Storing under the
/// raw string while invalidation resolves a `Location` through the parser
/// makes the two disagree, leaving stale entries behind (WPT
/// `http-cache/invalidate`). Keying on the parsed serialization keeps store,
/// lookup and invalidate consistent; an unparseable URL falls back to itself.
fn cache_key_url(url: &str) -> String {
    url::Url::parse(url)
        .map(|u| u.to_string())
        .unwrap_or_else(|_| url.to_string())
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_ascii_lowercase() == lower)
        .map(|(_, v)| v.clone())
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    header_value(headers, name).is_some()
}

/// The value of header `name` (case-insensitive), or `None`.
fn pick_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// The stored variant whose `Vary` fields match this request (RFC 9111 §4.1).
/// `None` when no stored variant matches, including a `Vary: *` entry (which
/// never matches).
fn select_variant<'a>(
    entries: &'a [CacheEntry],
    req_headers: &[(String, String)],
) -> Option<&'a CacheEntry> {
    entries.iter().find(|e| vary_matches(e, req_headers))
}

/// Parse an IMF-fixdate HTTP-date (`Expires`/`Date`) into epoch seconds, or
/// `None` if unparsable. Cache tests emit `Date.toGMTString()`, which is the
/// IMF-fixdate form: `"Fri, 04 Aug 2026 00:00:00 GMT"`.
fn parse_http_date(value: &str) -> Option<u64> {
    let v = value.trim();
    // "ddd, DD Mon YYYY HH:MM:SS GMT"
    let parts: Vec<&str> = v.split_whitespace().collect();
    if parts.len() != 6 || !parts[0].ends_with(',') {
        return None;
    }
    let day: u32 = parts[1].parse().ok()?;
    let month = match parts[2].to_ascii_lowercase().as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    };
    let year: i64 = parts[3].parse().ok()?;
    let time: Vec<u32> = parts[4]
        .split(':')
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    if time.len() != 3 {
        return None;
    }
    let (hh, mm, ss) = (time[0], time[1], time[2]);
    days_from_civil(year, month, day)
        .and_then(|d| d.checked_mul(86400))
        .and_then(|d| d.checked_add((hh * 3600 + mm * 60 + ss) as i64))
        .and_then(|secs| u64::try_from(secs).ok())
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (month as i64 + if month > 2 { -3 } else { 9 }) + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe - 719468)
}

/// Explicit freshness lifetime in seconds: `Cache-Control: max-age`, else the
/// `Expires` date measured from when the response was stored. `None` when the
/// response carries no explicit lifetime (only heuristic freshness applies).
fn explicit_lifetime(entry: &CacheEntry) -> Option<u64> {
    if let Some(cc) = header_value(&entry.headers, "cache-control") {
        let cc = cc.to_ascii_lowercase();
        if let Some(pos) = cc.find("max-age=") {
            return cc[pos + "max-age=".len()..]
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|s| s.parse().ok());
        }
    }
    if let Some(expires) = header_value(&entry.headers, "expires") {
        // RFC 9111 §4.2.1: an invalid date — especially the value "0" — must be
        // interpreted as *already expired*, not as "no explicit lifetime", so
        // this must not fall through to heuristic freshness (WPT
        // `http-cache/freshness`: an invalid `Expires` alongside a past
        // `Last-Modified` must not be reused).
        return Some(parse_http_date(&expires).map_or(0, |e| e.saturating_sub(entry.stored_at)));
    }
    None
}

/// True when the stored entry is fresh: its explicit lifetime (`max-age` or
/// `Expires`) outlasts its current age — which includes the `Age` header
/// (RFC 9111 §4.2.3).
fn is_fresh(entry: &CacheEntry) -> bool {
    // A response `no-cache` directive forbids *reuse without revalidation*, no
    // matter how fresh `max-age`/`Expires` makes the entry (WPT
    // `http-cache/freshness`: "stores a response with Cache-Control: no-cache,
    // but revalidates upon use, even with max-age and Expires").
    if let Some(cc) = header_value(&entry.headers, "cache-control")
        && cc.to_ascii_lowercase().contains("no-cache")
    {
        return false;
    }
    if let Some(lifetime) = explicit_lifetime(entry) {
        return current_age(entry) < lifetime;
    }

    // RFC 9111 §4.2.2 heuristic freshness: with no explicit expiry, allow a
    // small fraction (10%) of the apparent age (time since `Last-Modified`).
    if let Some(lm) = header_value(&entry.headers, "last-modified")
        && let Some(modified) = parse_http_date(&lm)
    {
        let apparent_age = now_epoch().saturating_sub(modified);
        let current_age = now_epoch().saturating_sub(entry.stored_at);
        // Fresh while the entry is younger than 10% of the apparent age.
        return (current_age as f64) < (apparent_age as f64) * 0.1;
    }

    // No freshness info: conservatively treat as stale (requires revalidation).
    false
}

/// RFC 5861 `stale-while-revalidate`: the entry is stale, but its staleness is
/// within the window the response allowed for serving stale content while a
/// revalidation runs in the background.
fn stale_while_revalidate(entry: &CacheEntry) -> bool {
    let Some(cc) = header_value(&entry.headers, "cache-control") else {
        return false;
    };
    let cc = cc.to_ascii_lowercase();
    let Some(window) = directive_value(&cc, "stale-while-revalidate") else {
        return false;
    };
    // Needs an explicit lifetime to measure the staleness against.
    let Some(lifetime) = explicit_lifetime(entry) else {
        return false;
    };
    let age = current_age(entry);
    age >= lifetime && age - lifetime <= window
}

/// The response's `Age` header in seconds (0 when absent). An upstream cache
/// reports here how long it already held the response, so the client's view of
/// the current age must include it (RFC 9111 §4.2.3).
fn age_header(entry: &CacheEntry) -> u64 {
    header_value(&entry.headers, "age")
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

/// Current age of a stored response: resident time plus the `Age` header.
fn current_age(entry: &CacheEntry) -> u64 {
    now_epoch()
        .saturating_sub(entry.stored_at)
        .saturating_add(age_header(entry))
}

/// Read a numeric `Cache-Control` directive (`name=123`) from a lowercased
/// directive string.
fn directive_value(cc: &str, name: &str) -> Option<u64> {
    let pat = format!("{name}=");
    let pos = cc.find(&pat)?;
    let rest = &cc[pos + pat.len()..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Whether a stored entry may be reused given the request's own
/// `Cache-Control` directives (RFC 9111 §5.2.1). `None` means "not usable".
///
/// - `no-cache` / `no-store`: never reuse without going to the network.
/// - `max-age=N`: only if the entry's current age is at most `N`.
/// - `min-fresh=N`: only if it stays fresh for at least `N` more seconds.
/// - `max-stale[=N]`: accept a stale entry, optionally bounded to `N` seconds
///   of staleness (a bare `max-stale` accepts any amount).
fn usable_for_request(entry: &CacheEntry, req_headers: &[(String, String)]) -> bool {
    let Some(cc) = header_value(req_headers, "cache-control") else {
        return true; // no request directive: no constraint from this side
    };
    let cc = cc.to_ascii_lowercase();
    if cc.contains("no-cache") || cc.contains("no-store") {
        return false;
    }
    let age = current_age(entry);
    if let Some(n) = directive_value(&cc, "max-age")
        && age > n
    {
        return false;
    }
    if let Some(n) = directive_value(&cc, "min-fresh") {
        // Remaining freshness is the lifetime minus the current age, and that
        // age already includes the response's `Age` header.
        let remaining = explicit_lifetime(entry).map_or(0, |l| l.saturating_sub(age));
        if remaining < n {
            return false;
        }
    }
    // `max-stale` only matters for an entry that is already stale.
    if !is_fresh(entry) {
        let stale_for = explicit_lifetime(entry).map_or(u64::MAX, |l| age.saturating_sub(l));
        let accepted = match directive_value(&cc, "max-stale") {
            Some(n) => stale_for <= n,
            // A bare `max-stale` (no value) accepts any amount of staleness.
            None => cc.contains("max-stale"),
        };
        if !accepted {
            return false;
        }
    }
    true
}

/// Whether a request may reuse an entry given its `Vary` fields: every listed
/// field must have the same value in the stored and the current request, where
/// a field absent from *both* counts as equal (RFC 9111 §4.1). `Vary: *` never
/// matches.
fn vary_matches(entry: &CacheEntry, req_headers: &[(String, String)]) -> bool {
    for field in &entry.vary {
        if field == "*" {
            return false;
        }
        match (
            pick_header(&entry.req_headers, field),
            pick_header(req_headers, field),
        ) {
            // Present on both sides with the same value, or absent from both.
            (Some(a), Some(b)) if a == b => {}
            (None, None) => {}
            _ => return false,
        }
    }
    true
}

/// True when `entry` describes the same `Vary` variant as a response that varies
/// on `vary` and was requested with `req_headers`: the field list is identical
/// and every field has the same value on both requests. Used by `store` to
/// replace an existing variant instead of accumulating duplicates.
fn same_variant(entry: &CacheEntry, vary: &[String], req_headers: &[(String, String)]) -> bool {
    entry.vary == vary
        && vary
            .iter()
            .all(|f| pick_header(&entry.req_headers, f) == pick_header(req_headers, f))
}

/// RFC 9111 §3: the status codes a response may be cached from without an
/// explicit freshness directive. Anything else (e.g. an unknown 299) is only
/// cacheable when it carries `Cache-Control` / `Expires`
/// (WPT `http-cache/heuristic`).
fn is_heuristically_cacheable_status(status: u16) -> bool {
    matches!(
        status,
        200 | 203 | 204 | 300 | 301 | 308 | 404 | 405 | 410 | 414 | 501
    )
}

/// True when the caller supplied any conditional request header
/// (`If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`, `If-Match`,
/// `If-Range`). A request carrying one of these is treated as `no-store`:
/// it bypasses the cache (WPT request-cache-default-conditional) and its
/// response is not stored.
pub(crate) fn caller_supplied_validator(headers: &[(String, String)]) -> bool {
    const CONDITIONAL: &[&str] = &[
        "if-none-match",
        "if-modified-since",
        "if-unmodified-since",
        "if-match",
        "if-range",
    ];
    CONDITIONAL.iter().any(|h| has_header(headers, h))
}

/// Look up a cached entry for a GET request and, if found, return the
/// validators so the caller can attach conditional request headers.
pub(crate) fn lookup_validators(
    method: &str,
    url: &str,
    req_headers: &[(String, String)],
) -> Option<(Option<String>, Option<String>)> {
    if !method.eq_ignore_ascii_case("GET") {
        return None;
    }
    let cache = CACHE.lock().unwrap();
    let entries = cache.get(&(method.to_ascii_uppercase(), cache_key_url(url)))?;
    // A response that varies on fields this request does not match is not
    // revalidateable either (WPT `http-cache/vary`).
    let entry = select_variant(entries, req_headers)?;
    Some((entry.etag.clone(), entry.last_modified.clone()))
}

/// Return the full cached entry for a GET request, if present. Used by the
/// cache modes that can serve straight from cache (`default` fresh,
/// `force-cache`, `only-if-cached`).
pub(crate) fn lookup_full(
    method: &str,
    url: &str,
    req_headers: &[(String, String)],
) -> Option<CacheHit> {
    if !method.eq_ignore_ascii_case("GET") {
        return None;
    }
    let cache = CACHE.lock().unwrap();
    let entries = cache.get(&(method.to_ascii_uppercase(), cache_key_url(url)))?;
    // Reuse only a stored variant matching this request; `select_variant`
    // already rejects `Vary: *` (WPT request-cache-force-cache, http-cache/vary).
    let entry = select_variant(entries, req_headers)?;

    // Request `Cache-Control` directives constrain whether this entry may be
    // reused at all (RFC 9111 §5.2.1).
    if !usable_for_request(entry, req_headers) {
        return None;
    }

    // `fresh` is the caller's freshness filter (`fetch.rs` keeps only fresh
    // entries for the default cache mode). A request directive that explicitly
    // accepted a stale entry (`max-stale`) makes it reusable here.
    let fresh = is_fresh(entry) || header_value(req_headers, "cache-control").is_some();
    let range = req_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("range"))
        .map(|(_, v)| v.clone());

    // Without a `Range` request header the whole stored response is returned.
    // A stored *partial* response cannot answer such a request — the caller
    // wants the complete entity, so fall through to the network.
    let Some(range_value) = range else {
        if entry.status == 206 {
            return None;
        }
        return Some(CacheHit {
            status: entry.status,
            headers: entry.headers.clone(),
            body: entry.body.clone(),
            fresh,
            swr: stale_while_revalidate(entry),
            final_url: entry.final_url.clone(),
        });
    };

    // RFC 9111 §3.3 / §4.3.2: a `Range` request may be satisfied from the cache
    // as a `206 Partial Content`. A complete stored response is sliced; a stored
    // `206` can only answer ranges that lie inside the span it covers.
    let full_len = if entry.status == 206 {
        // The stored body is the resource's `start..` slice, so its byte 0 is
        // resource offset `start` and the last byte available is
        // `start + len - 1`. That makes `start + len` the resource length the
        // stored span implies — the `Content-Range` total is only used to
        // re-serialize the response header, since fixtures commonly report a
        // total wider than the body they actually send.
        let (start, _end, _total) = parse_content_range(&entry.headers)?;
        let stored_end = start + entry.body.len().saturating_sub(1) as u64;
        let eff_len = stored_end + 1;
        let (rs, re) = parse_byte_range(&range_value, eff_len)?;
        if rs < start || rs > stored_end {
            return None;
        }
        let re = re.min(stored_end);
        let offset = (rs - start) as usize;
        let take = (re - rs + 1) as usize;
        let body = entry.body.get(offset..offset + take)?.to_vec();
        let mut headers = entry.headers.clone();
        set_header(
            &mut headers,
            "Content-Range",
            &format!("bytes {rs}-{re}/{eff_len}"),
        );
        set_header(&mut headers, "Content-Length", &body.len().to_string());
        return Some(CacheHit {
            status: 206,
            headers,
            body,
            fresh,
            swr: stale_while_revalidate(entry),
            final_url: entry.final_url.clone(),
        });
    } else {
        entry.body.len() as u64
    };
    let (rs, re) = parse_byte_range(&range_value, full_len)?;
    let body = entry.body.get(rs as usize..=re as usize)?.to_vec();
    let mut headers = entry.headers.clone();
    set_header(
        &mut headers,
        "Content-Range",
        &format!("bytes {rs}-{re}/{full_len}"),
    );
    // The stored response carried the whole entity; the slice is partial.
    set_header(&mut headers, "Content-Length", &body.len().to_string());
    Some(CacheHit {
        status: 206,
        headers,
        body,
        fresh,
        swr: stale_while_revalidate(entry),
        final_url: entry.final_url.clone(),
    })
}

/// RFC 9111 §3.3: a request for the complete resource that matches a stored
/// *incomplete* (`206`) response cannot be served from cache, but the fetch can
/// be completed by forwarding a request for the missing remainder. Returns the
/// `Range` value to send (`bytes=<last stored byte + 1>-`), or `None` when there
/// is no stored prefix to complete.
pub(crate) fn partial_remainder_range(
    method: &str,
    url: &str,
    req_headers: &[(String, String)],
) -> Option<String> {
    if !method.eq_ignore_ascii_case("GET") {
        return None;
    }
    let cache = CACHE.lock().unwrap();
    let entries = cache.get(&(method.to_ascii_uppercase(), cache_key_url(url)))?;
    let entry = select_variant(entries, req_headers)?;
    if entry.status != 206 {
        return None;
    }
    let (start, end, total) = parse_content_range(&entry.headers)?;
    // Only a stored prefix (start 0) can be extended by a single open-ended
    // range, and only while the resource is still incomplete.
    if start != 0 || end + 1 >= total {
        return None;
    }
    Some(format!("bytes={}-", end + 1))
}

/// Parse a request `Range` header (`bytes=a-b`, `bytes=a-`, `bytes=-n`) against
/// a resource of `len` bytes, returning the inclusive `(start, end)` span. Only
/// the first byte-range-spec is used; an unsatisfiable or malformed value
/// returns `None` (the caller then falls back to the network).
fn parse_byte_range(value: &str, len: u64) -> Option<(u64, u64)> {
    let spec = value.trim();
    let spec = spec
        .strip_prefix("bytes=")
        .or_else(|| spec.strip_prefix("bytes ="))
        .or_else(|| spec.strip_prefix("BYTES="))?;
    let first = spec.split(',').next()?.trim();
    let (a, b) = first.split_once('-')?;
    let (a, b) = (a.trim(), b.trim());
    if len == 0 {
        return None;
    }
    if a.is_empty() {
        // suffix-byte-range-spec: the final `b` bytes.
        let n: u64 = b.parse().ok()?;
        if n == 0 {
            return None;
        }
        let n = n.min(len);
        return Some((len - n, len - 1));
    }
    let start: u64 = a.parse().ok()?;
    if start >= len {
        return None;
    }
    let end = if b.is_empty() {
        len - 1
    } else {
        b.parse::<u64>().ok()?.min(len - 1)
    };
    (start <= end).then_some((start, end))
}

/// Parse a stored `Content-Range: bytes start-end/total` into its parts.
fn parse_content_range(headers: &[(String, String)]) -> Option<(u64, u64, u64)> {
    let v = header_value(headers, "content-range")?;
    let v = v.trim();
    let rest = v.strip_prefix("bytes").map(str::trim).unwrap_or(v);
    let (span, total) = rest.split_once('/')?;
    let (start, end) = span.trim().split_once('-')?;
    Some((
        start.trim().parse().ok()?,
        end.trim().parse().ok()?,
        total.trim().parse().ok()?,
    ))
}

/// Replace (or append) a header, preserving the stored name casing of an
/// existing entry.
fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    if let Some(h) = headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
    {
        h.1 = value.to_string();
    } else {
        headers.push((name.to_string(), value.to_string()));
    }
}

/// Append conditional revalidation headers to `headers` from a cached entry,
/// but only for headers the caller did not already provide. Returns `true`
/// when any validator was actually added (i.e. the revalidation is cache-driven
/// and a resulting 304 must be turned into the cached response).
pub(crate) fn add_conditional_headers(
    headers: &mut Vec<(String, String)>,
    validators: (Option<String>, Option<String>),
) -> bool {
    let (etag, last_modified) = validators;
    let mut added = false;
    if let Some(etag) = etag
        && !has_header(headers, "if-none-match")
    {
        headers.push(("If-None-Match".to_string(), etag));
        added = true;
    }
    if let Some(lm) = last_modified
        && !has_header(headers, "if-modified-since")
    {
        headers.push(("If-Modified-Since".to_string(), lm));
        added = true;
    }

    added
}

/// Store a successful GET response so it can be reused or revalidated later.
pub(crate) fn store(
    method: &str,
    url: &str,
    status: u16,
    headers: &[(String, String)],
    body: Vec<u8>,
    final_url: &str,
    req_headers: &[(String, String)],
) {
    // Only a GET seeds the cache. POST/PATCH response caching (RFC 9111 §9.3.1,
    // a MAY) is deliberately not implemented: browsers have dropped it, and
    // serving a stored response in place of the one a fresh unsafe request
    // produced is not something to guess at.
    if !method.eq_ignore_ascii_case("GET") {
        return;
    }
    // Never buffer an unbounded body in the in-memory cache: an 8GiB response
    // would OOM the process. The caller should stream such bodies instead.
    if (body.len() as u64) > MAX_CACHE_BODY_BYTES {
        return;
    }

    let etag = header_value(headers, "etag");
    let last_modified = header_value(headers, "last-modified");

    // A status outside the heuristically-cacheable set needs an explicit
    // freshness directive to be cached at all (RFC 9111 §3).
    let cc = header_value(headers, "cache-control")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let explicit_freshness = cc.contains("max-age")
        || cc.contains("s-maxage")
        || cc.contains("public")
        || has_header(headers, "expires");
    if !is_heuristically_cacheable_status(status) && !explicit_freshness {
        return;
    }

    // A stored response must be reusable: one with an explicit freshness
    // lifetime (`max-age`/`s-maxage`/`public`/`Expires`) is served straight from
    // cache while fresh and needs no validator at all; otherwise it can only be
    // *revalidated*, which requires an `ETag`/`Last-Modified`. Needing neither
    // means nothing could ever be judged about reuse, so do not store it.
    if !explicit_freshness && etag.is_none() && last_modified.is_none() {
        return;
    }

    // Never cache a `no-store` response. `private` is allowed: this cache is a
    // single-user (browser-style) cache, and RFC 9111 §5.2.2.7 only forbids
    // *shared* caches from storing `private`.
    if let Some(cc) = header_value(headers, "cache-control")
        && cc.to_ascii_lowercase().contains("no-store")
    {
        return;
    }
    let vary: Vec<String> = header_value(headers, "vary")
        .map(|v| {
            v.split(',')
                .map(|f| f.trim().to_ascii_lowercase())
                .filter(|f| !f.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let mut cache = CACHE.lock().unwrap();
    let key = (method.to_ascii_uppercase(), cache_key_url(url));
    let entry = CacheEntry {
        status,
        headers: headers.to_vec(),
        body,
        etag,
        last_modified,
        stored_at: now_epoch(),
        final_url: final_url.to_string(),
        vary,
        req_headers: req_headers
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
            .collect(),
    };

    // RFC 9111 §4.1: keep one entry per `Vary` variant, so a response for one
    // request header combination does not evict the one stored for another
    // (WPT `http-cache/vary` "doesn't invalidate existing Vary response").
    let entries = cache.entry(key).or_default();
    match entries
        .iter_mut()
        .find(|e| same_variant(e, &entry.vary, &entry.req_headers))
    {
        Some(slot) => *slot = entry,
        None => {
            if entries.len() >= MAX_VARIANTS_PER_URL {
                entries.remove(0);
            }
            entries.push(entry);
        }
    }
}

/// Drop the entry for `url`, if any. A successful unsafe request (POST/PUT/
/// DELETE/PATCH) invalidates the stored response for its target URL
/// (RFC 9111 §4.4), as do the URLs it redirects to or names in
/// `Location`/`Content-Location` (WPT `http-cache/invalidate`).
pub(crate) fn invalidate(url: &str) {
    CACHE
        .lock()
        .unwrap()
        .remove(&("GET".to_string(), cache_key_url(url)));
}

/// Merge `update` headers onto a stored entry and rebuild it. Used when the
/// server answers a revalidation with `304`: per Fetch, the 304 response's
/// headers update the stored response but the body stays the same. The variant
/// is the one matching the revalidating request.
fn merge_and_update(
    method: &str,
    url: &str,
    req_headers: &[(String, String)],
    update: &[(String, String)],
) {
    let mut cache = CACHE.lock().unwrap();
    let key = (method.to_ascii_uppercase(), cache_key_url(url));
    let Some(entries) = cache.get_mut(&key) else {
        return;
    };
    let Some(entry) = entries.iter_mut().find(|e| vary_matches(e, req_headers)) else {
        return;
    };
    for (k, v) in update {
        if let Some(slot) = entry
            .headers
            .iter_mut()
            .find(|(ek, _)| ek.eq_ignore_ascii_case(k))
        {
            slot.1 = v.clone();
        } else {
            entry.headers.push((k.clone(), v.clone()));
        }
    }
}

/// If `status == 304` and the cache has a matching entry that we drove the
/// revalidation for (`cache_driven` true), return the cached response's
/// (status, headers, body) with the 304 headers merged on top. Otherwise
/// `None`.
pub(crate) fn take_not_modified(
    method: &str,
    url: &str,
    req_headers: &[(String, String)],
    status: u16,
    not_modified_headers: &[(String, String)],
    cache_driven: bool,
) -> Option<(u16, Vec<(String, String)>, Vec<u8>)> {
    if status != 304 || !cache_driven {
        return None;
    }
    let key = (method.to_ascii_uppercase(), cache_key_url(url));
    let cached_status = {
        let cache = CACHE.lock().unwrap();
        let entries = cache.get(&key)?;
        select_variant(entries, req_headers)?.status
    };
    // Merge 304 headers onto the stored headers.
    merge_and_update(method, url, req_headers, not_modified_headers);
    let cache = CACHE.lock().unwrap();
    let entries = cache.get(&key)?;
    let entry = select_variant(entries, req_headers)?;
    Some((cached_status, entry.headers.clone(), entry.body.clone()))
}
