// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! Client-origin ("document origin") resolution for the Fetch API.
//!
//! In a browser the client origin is the document's origin; here it is read
//! from the `self.location` shim that WPT runners inject, with a fallback to
//! plain `__wptClientUrl`/`__wptClientOrigin` globals for runners that cannot
//! decorate the engine's native `self`. Gated by `fetch_cors_cookie`: server
//! builds have no location/origin concept at all.

#[cfg(feature = "fetch_cors_cookie")]
use zuqe::JSValue;
use zuqe::ScopedContext;

/// Resolve `(client_origin, client_url)` — the document origin and URL used
/// for same-origin checks, the default referrer, and CORS taint decisions.
/// A failed property read is expected and must not leak a pending exception,
/// so each probe takes/discards its error.
#[cfg(feature = "fetch_cors_cookie")]
pub(crate) fn resolve_client_origin(ctx: &mut ScopedContext) -> (Option<String>, Option<String>) {
    let loc = ctx
        .global_obj()
        .get_property_str(ctx, "self")
        .ok()
        .filter(|selfv| !selfv.is_undefined_or_null())
        .and_then(|selfv| selfv.get_property_str(ctx, "location").ok());
    let origin = loc
        .as_ref()
        .and_then(|loc| loc.get_property_str(ctx, "origin").ok())
        .and_then(|o| js_string_of(ctx, &o))
        .filter(|s| !s.is_empty());
    let url = loc
        .as_ref()
        .and_then(|loc| loc.get_property_str(ctx, "href").ok())
        .and_then(|h| js_string_of(ctx, &h))
        .filter(|s| !s.is_empty());
    // WPT runner shim: when the JS `self.location` shim is unavailable (e.g.
    // the engine's `self` is a native object the runner can't decorate), the
    // runner injects the document URL/origin here so the default referrer and
    // client origin resolve to the test document (not `None`).
    let wpt_url = global_string(ctx, "__wptClientUrl");
    let wpt_origin = global_string(ctx, "__wptClientOrigin");
    // The WPT runner injects `__wptClientUrl` (document URL) and
    // `__wptClientOrigin` (origin with port) as fallbacks when `self.location`
    // is unavailable to the engine; otherwise prefer `self.location`.
    let url = wpt_url.or(url);
    let origin = origin.or(wpt_origin);
    (origin, url)
}

/// Server build: no location/origin concept — every fetch runs origin-less
/// (null origin).
#[cfg(not(feature = "fetch_cors_cookie"))]
pub(crate) fn resolve_client_origin(_ctx: &mut ScopedContext) -> (Option<String>, Option<String>) {
    (None, None)
}

/// Read a non-nullish value as an owned UTF-8 string; `None` on undefined/null
/// or a failed conversion.
#[cfg(feature = "fetch_cors_cookie")]
fn js_string_of(ctx: &mut ScopedContext, v: &JSValue) -> Option<String> {
    if v.is_undefined_or_null() {
        None
    } else {
        v.to_string(ctx)
            .ok()
            .map(|s| s.content().encode_utf8(false).to_string())
    }
}

/// Read a global property as an owned UTF-8 string; `None` when absent/nullish
/// or empty.
#[cfg(feature = "fetch_cors_cookie")]
fn global_string(ctx: &mut ScopedContext, key: &str) -> Option<String> {
    ctx.global_obj()
        .get_property_str(ctx, key)
        .ok()
        .and_then(|v| {
            if v.is_undefined_or_null() {
                None
            } else {
                v.to_string(ctx)
                    .ok()
                    .map(|s| s.content().encode_utf8(false).to_string())
            }
        })
        .filter(|s| !s.is_empty())
}
