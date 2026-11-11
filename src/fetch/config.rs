// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! `HttpClientConfig` — client-level settings for the reusable `HttpClient`.
//!
//! Holds proxy, TLS, cookie, DNS, and connection-level options.
//! `build_http_client()` constructs a `reqwest::Client` from the config.

use std::{net::SocketAddr, time::Duration};

#[cfg(feature = "fetch_cors_cookie")]
use std::sync::{Arc, OnceLock, RwLock};

#[cfg(feature = "fetch_cors_cookie")]
use reqwest::header::HeaderValue;
#[cfg(feature = "fetch_cors_cookie")]
use url::Url;

/// Protocol version preference.
#[derive(Clone, Debug, Default)]
pub(crate) enum ProtocolMode {
    /// Let reqwest negotiate (H1/H2 via ALPN).
    #[default]
    Auto,
    /// Force HTTP/1.x only.
    Http1Only,
}

/// Connection-level configuration shared by every request that goes through
/// [`build_http_client_ex`](self::HttpClientConfig::build_http_client_ex).
/// The fetch pipeline builds one from `default()` and narrows it per request.
#[derive(Clone, Debug)]
pub(crate) struct HttpClientConfig {
    /// HTTP/HTTPS proxy URL.
    pub proxy: Option<String>,
    /// Comma-separated domains to bypass the proxy.
    pub no_proxy: Option<String>,

    /// Skip TLS certificate validation (dangerous).
    pub danger_accept_invalid_certs: bool,
    /// PEM-encoded CA certificate to add to the trust root.
    pub root_cert_pem: Option<String>,
    /// PEM-encoded client certificate (for mTLS).
    pub client_cert_pem: Option<String>,
    /// PEM-encoded client private key (for mTLS).
    pub client_key_pem: Option<String>,

    /// Enable cookie jar for cross-request persistence.
    pub cookie_jar: bool,

    /// DNS overrides: host → IP.
    pub resolve_overrides: Vec<(String, SocketAddr)>,
    /// Protocol version preference.
    pub protocol: ProtocolMode,

    /// Connection timeout (seconds): TCP connect plus TLS handshake.
    /// Matches reqwest's own default; 10s was too tight for origins whose TLS
    /// handshake legitimately takes several seconds.
    pub connect_timeout: Duration,

    /// Let the client follow redirects itself. Turn this off when the caller
    /// follows hops manually (e.g. fetch, which must recompute `Referer` per
    /// hop) so redirect responses are surfaced instead of swallowed.
    pub follow_redirects: bool,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            proxy: None,
            no_proxy: None,
            danger_accept_invalid_certs: false,
            root_cert_pem: None,
            client_cert_pem: None,
            client_key_pem: None,
            cookie_jar: true,
            resolve_overrides: vec![],
            protocol: ProtocolMode::Auto,
            connect_timeout: Duration::from_secs(30),
            follow_redirects: true,
        }
    }
}

impl HttpClientConfig {
    /// Build a `reqwest::Client` from the configuration.
    #[allow(dead_code)]
    pub fn build_http_client(&self) -> Result<reqwest::Client, String> {
        self.build_http_client_ex(self.danger_accept_invalid_certs)
    }

    /// Build a `reqwest::Client`, optionally skipping cert validation.
    ///
    /// When `insecure` is true the client accepts *any* certificate (the
    /// `fetch.allowInsecureTLS` / per-instance `rejectUnauthorized` escape
    /// hatch). Otherwise normal validation applies.
    pub fn build_http_client_ex(&self, insecure: bool) -> Result<reqwest::Client, String> {
        let redirect = if self.follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        };

        let mut builder = reqwest::Client::builder()
            .redirect(redirect)
            .connect_timeout(self.connect_timeout)
            // Disable idle connection pooling: every request opens a fresh
            // connection. Required for the 421 (Misdirected Request) retry to
            // land on a *new* connection, as the fetch spec and the WPT
            // connection-pool tests expect (otherwise the retry reuses the same
            // keep-alive socket and the server counts only one connection).
            .pool_max_idle_per_host(0);

        // --- Cookie jar ---
        // The WHATWG `fetch` path disables reqwest's automatic store
        // (`cookie_jar = false`) and manages cookies itself via the shared
        // global jar, so the fetch `credentials` mode decides whether a cookie
        // is sent/stored (reqwest's auto-store would send them unconditionally).
        if self.cookie_jar {
            builder = builder.cookie_store(true);
        }

        // --- Proxy ---
        if let Some(ref proxy_url) = self.proxy {
            let mut proxy =
                reqwest::Proxy::all(proxy_url).map_err(|e| format!("invalid proxy: {e}"))?;
            if let Some(ref no_proxy) = self.no_proxy {
                proxy = proxy.no_proxy(reqwest::NoProxy::from_string(no_proxy));
            }
            builder = builder.proxy(proxy);
        }
        // reqwest also reads http_proxy / https_proxy env vars by default.

        // --- TLS: skip validation (fetch.allowInsecureTLS / rejectUnauthorized) ---
        if insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }

        // --- TLS: custom CA (per-instance option, legacy path) ---
        if let Some(ref pem) = self.root_cert_pem {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| format!("invalid CA cert: {e}"))?;
            builder = builder.add_root_certificate(cert);
        }

        // --- TLS: client certificate (mTLS) ---
        if let (Some(cert_pem), Some(key_pem)) = (&self.client_cert_pem, &self.client_key_pem) {
            // reqwest expects cert + key concatenated in one PEM blob.
            let mut buf = cert_pem.as_bytes().to_vec();
            buf.extend_from_slice(key_pem.as_bytes());
            let identity = reqwest::Identity::from_pem(&buf)
                .map_err(|e| format!("invalid mTLS identity: {e}"))?;
            builder = builder.identity(identity);
        }

        // --- DNS overrides ---
        for (host, addr) in &self.resolve_overrides {
            builder = builder.resolve(host, *addr);
        }

        // --- Protocol ---
        if matches!(self.protocol, ProtocolMode::Http1Only) {
            builder = builder.http1_only();
        }

        builder
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))
    }
}

#[cfg(feature = "fetch_cors_cookie")]
mod cookie_jar_impl {
    use super::*;

    /// Shared cookie jar backing both `fetch()` and the `cookieStore` API.
    ///
    /// Mirrors `reqwest::cookie::Jar` — which wraps the very same
    /// `cookie_store::CookieStore` — but additionally exposes the store so the
    /// Cookie Store API can enumerate and remove cookies. `fetch` stores/reads
    /// through the same `add_cookie_str`/`cookies` surface, so the HTTP layer and
    /// the script API operate on a single store, as the spec requires.
    pub(crate) struct SharedCookieJar {
        store: RwLock<cookie_store::CookieStore>,
    }

    impl Default for SharedCookieJar {
        fn default() -> Self {
            Self {
                store: RwLock::new(cookie_store::CookieStore::new()),
            }
        }
    }

    impl SharedCookieJar {
        /// Parse a `Set-Cookie` value and store it as received from `url`.
        /// Mirrors `reqwest::cookie::Jar::add_cookie_str`, including its use of the
        /// `cookie` crate for parsing (re-exported by `cookie_store`).
        pub(crate) fn add_cookie_str(&self, cookie: &str, url: &Url) {
            let cookies = cookie_store::RawCookie::parse(cookie)
                .ok()
                .map(|c| c.into_owned())
                .into_iter();
            self.store
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .store_response_cookies(cookies, url);
        }

        /// Build the `Cookie` request header for `url`. Mirrors `reqwest`'s
        /// `Jar`: names/values joined with `"; "` in retrieval order.
        pub(crate) fn cookies(&self, url: &Url) -> Option<HeaderValue> {
            let s = self
                .store
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get_request_values(url)
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            if s.is_empty() {
                return None;
            }
            HeaderValue::from_str(&s).ok()
        }

        /// Run `f` with read access to the underlying store (Cookie Store API).
        pub(crate) fn with_store<R>(&self, f: impl FnOnce(&cookie_store::CookieStore) -> R) -> R {
            f(&self.store.read().unwrap_or_else(|e| e.into_inner()))
        }
    }

    /// The global cookie jar shared by WHATWG `fetch()` clients. Cookies persist
    /// across separate `fetch()` calls, matching the browser's per-origin cookie
    /// store. The fetch path reads/writes it manually according to the request's
    /// `credentials` mode.
    pub(crate) fn global_cookie_jar() -> Arc<SharedCookieJar> {
        static JAR: OnceLock<Arc<SharedCookieJar>> = OnceLock::new();
        JAR.get_or_init(|| Arc::new(SharedCookieJar::default()))
            .clone()
    }

    /// First-seen order of cookie names across the session, so the `Cookie` request
    /// header lists cookies in creation order (WPT `cookies.any.js`). The
    /// underlying `reqwest`/`cookie_store` jar returns cookies in hash order, which
    /// does not match the creation order a browser UA cookie store preserves.
    pub(crate) fn global_cookie_order() -> &'static std::sync::RwLock<Vec<String>> {
        static ORDER: OnceLock<std::sync::RwLock<Vec<String>>> = OnceLock::new();
        ORDER.get_or_init(|| std::sync::RwLock::new(Vec::new()))
    }

    /// Record the name of a cookie being stored, so it keeps its creation position
    /// in the `Cookie` header. The name is the token before the first `=` or `;`.
    pub(crate) fn cookie_order_record(set_cookie: &str) {
        let name = set_cookie
            .split(['=', ';'])
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if name.is_empty() {
            return;
        }
        let mut order = global_cookie_order()
            .write()
            .unwrap_or_else(|e| e.into_inner());
        // Re-register on every `Set-Cookie`: move the name to the end rather than
        // keeping its first-ever position. The table is process-global and never
        // pruned, so a stale entry left by an earlier test or file would otherwise
        // pin a name ahead of cookies set later, and a deleted cookie's name would
        // keep its old slot (WPT `credentials/cookies` "Include mode: 2 cookies"
        // expects the creation order of *this* response: `b=2; c=3`).
        order.retain(|n| n != &name);
        order.push(name);
    }

    /// Reorder a `Cookie` header value's `name=value` pairs into first-seen order.
    /// Names not in the recorded order (e.g. overwritten/expired) are kept at the
    /// end in their original relative order.
    pub(crate) fn reorder_cookie_header(value: &str) -> String {
        let order = global_cookie_order()
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let mut pairs: Vec<(usize, &str)> = value
            .split("; ")
            .map(|pair| {
                let name = pair
                    .split('=')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                let pos = order.iter().position(|n| n == &name).unwrap_or(usize::MAX);
                (pos, pair)
            })
            .collect();
        pairs.sort_by_key(|(pos, _)| *pos);
        pairs
            .into_iter()
            .map(|(_, pair)| pair)
            .collect::<Vec<_>>()
            .join("; ")
    }
}

#[cfg(feature = "fetch_cors_cookie")]
pub(crate) use cookie_jar_impl::{
    cookie_order_record, global_cookie_jar, global_cookie_order, reorder_cookie_header,
};
