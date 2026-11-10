// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! The Fetch `referrer` / `referrerPolicy` algorithm.

/// Compute the outgoing `Referer` value per the Fetch `referrer`/`referrerPolicy`
/// algorithm.
///
/// `referrer` is the explicit `RequestInit.referrer` (or `"about:client"`).
/// `referrer_policy` is the explicit `referrerPolicy` string (empty = default).
/// `client_origin`/`client_url` come from the `self.location` shim (browser
/// document origin / URL). `request_url` is the serialized request URL.
///
/// Covers the policies exercised by WPT `referrer.any.js`:
/// `origin-when-cross-origin` and the implicit default, plus explicit `referrer`
/// values whose credentials and fragment are stripped to yield the request's
/// origin (+ trailing slash).
pub(crate) fn compute_request_referrer(
    referrer: &str,
    referrer_policy: &str,
    client_origin: Option<&str>,
    client_url: Option<&str>,
    request_url: &str,
) -> Option<String> {
    // Strip any fragment and trailing `#` from a URL string.
    let strip_fragment = |u: &str| -> String {
        match u.find('#') {
            Some(i) => u[..i].to_string(),
            None => u.to_string(),
        }
    };
    // Origin (scheme://host[:port]) of a URL, or None if unparsable.
    let origin_of = |u: &str| -> Option<String> {
        url::Url::parse(u)
            .ok()
            .map(|u| u.origin().ascii_serialization())
    };
    // Whether a URL is "potentially trustworthy" enough to send a referrer to
    // over a (non-)downgrade. http://localhost and https are trustworthy.
    let trustworthy = |u: &str| -> bool {
        match url::Url::parse(u) {
            Ok(parsed) => {
                parsed.scheme() == "https"
                    || (parsed.scheme() == "http"
                        && matches!(parsed.host_str(), Some("localhost") | Some("127.0.0.1")))
            }
            Err(_) => false,
        }
    };

    // `no-referrer` policy always yields an empty referrer.
    if referrer_policy == "no-referrer" {
        return Some(String::new());
    }

    // Resolve the referrer source URL. `"about:client"` (or empty) uses the
    // document URL; an explicit `referrer` may be absolute or relative and is
    // resolved against the document URL, then stripped of its fragment.
    let source: Option<String> = if referrer.is_empty() || referrer == "about:client" {
        client_url.map(&strip_fragment)
    } else {
        let resolved = if let Ok(u) = url::Url::parse(referrer) {
            u.to_string()
        } else if let Some(base) = client_url {
            url::Url::parse(base)
                .ok()
                .and_then(|b| b.join(referrer).ok())
                .map(|u| u.to_string())
                .unwrap_or_else(|| referrer.to_string())
        } else {
            referrer.to_string()
        };
        Some(strip_fragment(&resolved))
    };
    let source = source?;

    let req_origin = origin_of(request_url);
    let same_origin = match (&req_origin, client_origin) {
        (Some(ro), Some(co)) => ro == co,
        _ => false,
    };

    // Helper: origin of `source` with trailing slash (e.g. "http://h:8000/").
    let source_origin_slash = || -> Option<String> {
        let o = origin_of(&source)?;
        Some(if o.ends_with('/') { o } else { format!("{o}/") })
    };

    // Fetch spec "strip": if the referrer carries credentials (userinfo), it
    // collapses to its origin (+ trailing slash) regardless of policy.
    if url::Url::parse(&source)
        .map(|u| u.username() != "" || u.password().is_some())
        .unwrap_or(false)
    {
        return source_origin_slash();
    }

    let full = || {
        url::Url::parse(&source)
            .map(|u| u.to_string())
            .unwrap_or(source.clone())
    };

    // Apply the policy (Fetch spec referrer policy table).
    match referrer_policy {
        "origin" => source_origin_slash(),
        "same-origin" => {
            if same_origin {
                Some(source)
            } else {
                Some(String::new())
            }
        }
        "origin-when-cross-origin" => {
            if same_origin {
                Some(source)
            } else {
                source_origin_slash()
            }
        }
        "strict-origin" => {
            // Send the origin unless this is a downgrade (a trustworthy/encrypted
            // referrer being sent to a non-trustworthy request target).
            if trustworthy(&source) && !trustworthy(request_url) {
                Some(String::new())
            } else {
                source_origin_slash()
            }
        }
        "strict-origin-when-cross-origin" => {
            if same_origin {
                Some(source)
            } else if trustworthy(&source) && !trustworthy(request_url) {
                Some(String::new())
            } else {
                source_origin_slash()
            }
        }
        "unsafe-url" => Some(full()),
        // Implicit default (no explicit `referrerPolicy`): behaves like
        // `origin-when-cross-origin` (full referrer same-origin, origin-only
        // cross-origin), which is what WPT's default-policy tests expect.
        "" => {
            if same_origin {
                Some(source)
            } else {
                source_origin_slash()
            }
        }
        // `no-referrer-when-downgrade`: send the full referrer unless the
        // request would be a downgrade (https → http).
        _ => {
            let source_trusted = trustworthy(&source);
            let req_trusted = trustworthy(request_url);
            if source_trusted && !req_trusted {
                Some(String::new())
            } else {
                Some(full())
            }
        }
    }
}
