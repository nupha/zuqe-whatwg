// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WHATWG `fetch()`.
//!
//! The Fetch API object model — `headers` (the `Headers` class), `request`
//! (`Request`) and `response` (`Response`) — are all
//! `[Exposed=(Window,Worker)]` globals installed by `fetch::init_fetch`.
//!
//! `fetch` is the algorithm itself: the global `fetch()` method, the request
//! pipeline (`fetch_impl`) and the Fetch-spec request-header policy it applies.
//! `cors` holds the browser-security layer (the WHATWG CORS protocol +
//! mode/tainting decisions) and `origin` the client ("document") origin
//! resolution; both are gated by the `fetch_cors_cookie` feature — server builds
//! compile them down to constant pass-through stubs. `referrer` is the referrer
//! algorithm and `integrity` Subresource Integrity.
//!
//! `body`, `config`, `transport` and `cache` are the HTTP engine the pipeline
//! runs on (request/response bodies, connection config, the wire layer, the
//! RFC 7234 response cache). They expose no JS API and are shared with `stream`
//! and `cookie_store`. The Cache Storage API (`caches`) lives one level up, in
//! `whatwg::cache_storage`.

pub(crate) mod body;
// The HTTP response cache. Only compiled with the `fetch_cache` feature; the
// fetch layer gates every use the same way.
#[cfg(feature = "fetch_cache")]
pub(crate) mod cache;
pub(crate) mod config;
mod cors;
mod fetch;
mod headers;
mod integrity;
mod origin;
mod referrer;
pub(crate) mod request;
pub(crate) mod response;
pub(crate) mod transport;

pub(crate) use {fetch::init_fetch, referrer::compute_request_referrer};
