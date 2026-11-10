// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WHATWG Cookie Store API — the global `cookieStore` object.
//!
//! Implements the `CookieStore` interface (`get` / `getAll` / `set` /
//! `delete`) and its algorithms over the shared cookie jar used by `fetch()`,
//! so scripts and the HTTP layer operate on one store (as the spec requires).
//!
//! Scope note: aike is a server runtime with no `Document` and no Service
//! Worker, so the "current URL" is the running script/module URL
//! (`import.meta.url`) and the Service-Worker-only parts of the spec
//! (`CookieStoreManager`, `ServiceWorkerRegistration.cookies`,
//! `ExtendableCookieChangeEvent`, `oncookiechange`) are not applicable. Change
//! events (`onchange` / `CookieChangeEvent`) are not implemented yet.
//!
//! Reference: <https://cookiestore.spec.whatwg.org/>

use url::{Host, Url};
use zuqe::{
    Array, CallContext, ClassCtorDef, Exception, FieldDef, JS_PROP_C_W_E, JSResult, JSValue,
    Object, ScopedContext, builtins::promise::Promise, def_native_object,
};

use crate::{
    dom::make_dom_exception,
    fetch::config::{cookie_order_record, global_cookie_jar, global_cookie_order},
};

/// Spec maximum name/value pair size (bytes).
const MAX_NAME_VALUE_PAIR_SIZE: usize = 4096;
/// Spec maximum attribute value size (bytes).
const MAX_ATTRIBUTE_VALUE_SIZE: usize = 1024;

// ---------------------------------------------------------------------------
// Outcomes that carry a rejected promise / fatal error
// ---------------------------------------------------------------------------

/// A `current_url()` failure: either the method must return a rejected promise
/// (the spec's `SecurityError` for an opaque origin), or the engine hit a fatal
/// error.
enum UrlOutcome {
    Url(Url),
    Reject(JSValue),
    Fatal(i32),
}

/// A URL-validation failure while reading `options.url`: a rejected promise
/// (`TypeError`) or a fatal error.
enum CheckErr {
    Reject(JSValue),
    Fatal(i32),
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Spec "normalize a cookie name or value": strip leading/trailing TAB/SPACE.
fn normalize(s: &str) -> String {
    s.trim_matches(|c| c == '\t' || c == ' ').to_string()
}

/// Spec step 3 character check: `;`, any C0 control except TAB, or DEL.
fn has_invalid_cookie_char(s: &str) -> bool {
    s.chars()
        .any(|c| c == ';' || c == '\u{7F}' || ((c as u32) <= 0x1F && c != '\t'))
}

/// RFC6265 "default-path" of `url` (used when `path` is the empty string).
fn default_path(url: &Url) -> String {
    let p = url.path();
    if !p.starts_with('/') || p == "/" {
        return "/".to_string();
    }
    match p[1..].rfind('/') {
        Some(i) => p[..=i].to_string(),
        None => "/".to_string(),
    }
}

/// Serialize a `DOMHighResTimeStamp` (ms since epoch) as a cookie-date.
fn date_serialize(ms: f64) -> String {
    let ms = if ms.is_finite() { ms as i64 } else { 0 };
    match chrono::DateTime::from_timestamp_millis(ms) {
        Some(dt) => dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
        None => "Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
    }
}

/// `ToString` for a JS value (used for USVString / DOMString conversion).
fn js_string(ctx: &mut ScopedContext, v: &JSValue) -> Result<String, i32> {
    Ok(v.to_string(ctx)?.content().encode_utf8(false).to_string())
}

/// Resolve a promise with `undefined`.
fn resolve_undefined(ctx: &mut ScopedContext) -> JSResult {
    Promise::from_resolve_value(ctx, JSValue::UNDEFINED).map(JSValue::from)
}

/// Reject a promise with a `TypeError`.
fn reject_type_error(ctx: &mut ScopedContext, msg: &str) -> JSResult {
    let _ = ctx.throw_type_error(msg);
    let reason = match ctx.take_exception() {
        Exception::Error(v) => v,
        other => {
            ctx.throw(other);
            return Err(-1);
        }
    };
    Promise::from_reject_value(ctx, reason).map(JSValue::from)
}

/// Reject a promise with a `SecurityError` `DOMException`.
fn reject_security_error(ctx: &mut ScopedContext, msg: &str) -> JSResult {
    let reason = make_dom_exception(ctx, "SecurityError", msg)?;
    Promise::from_reject_value(ctx, reason).map(JSValue::from)
}

/// Turn a `Result<JSValue, i32>` rejection helper into a [`CheckErr`].
fn to_check_err(r: Result<JSValue, i32>) -> CheckErr {
    match r {
        Ok(v) => CheckErr::Reject(v),
        Err(c) => CheckErr::Fatal(c),
    }
}

/// The "current URL" / creation URL of the running script (spec: the relevant
/// settings object's creation URL). aike has no `Document`, so this is the
/// script/module URL behind `import.meta.url`. A missing or opaque-origin URL
/// yields the spec's `SecurityError` rejection.
fn current_url(ctx: &mut ScopedContext) -> UrlOutcome {
    let parsed = ctx.current_module_name().and_then(|n| Url::parse(&n).ok());
    match parsed {
        Some(u) if u.origin().is_tuple() => UrlOutcome::Url(u),
        _ => to_url_outcome(reject_security_error(
            ctx,
            "cookieStore is not available: the current URL has an opaque origin",
        )),
    }
}

fn to_url_outcome(r: Result<JSValue, i32>) -> UrlOutcome {
    match r {
        Ok(v) => UrlOutcome::Reject(v),
        Err(c) => UrlOutcome::Fatal(c),
    }
}

/// Compare two URLs ignoring fragments.
fn url_eq_excluding_fragment(a: &Url, b: &Url) -> bool {
    let mut a = a.clone();
    let mut b = b.clone();
    a.set_fragment(None);
    b.set_fragment(None);
    a == b
}

/// Apply the spec's `options.url` validation: it must parse against the API
/// base URL, equal the creation URL (exclude fragments), and be same-origin.
fn check_options_url(
    ctx: &mut ScopedContext,
    base: &Url,
    url: Option<String>,
) -> Result<Url, CheckErr> {
    let Some(raw) = url else {
        return Ok(base.clone());
    };
    let parsed = match base.join(&raw) {
        Ok(p) => p,
        Err(_) => {
            return Err(to_check_err(reject_type_error(
                ctx,
                "cookieStore: options.url is not a valid URL",
            )));
        }
    };
    if !url_eq_excluding_fragment(&parsed, base) {
        return Err(to_check_err(reject_type_error(
            ctx,
            "cookieStore: options.url must equal the current URL",
        )));
    }
    if parsed.origin() != base.origin() {
        return Err(to_check_err(reject_type_error(
            ctx,
            "cookieStore: options.url is not same-origin with the current URL",
        )));
    }
    Ok(parsed)
}

// ---------------------------------------------------------------------------
// Query cookies
// ---------------------------------------------------------------------------

/// Build a `CookieListItem` (`{ name, value }`).
fn make_item(ctx: &mut ScopedContext, name: &str, value: &str) -> Result<JSValue, i32> {
    let mut o = ctx.create_base_object()?;
    let nv = ctx
        .create_string_from_utf8(name.as_bytes().to_vec())
        .map(JSValue::make_string)?;
    let vv = ctx
        .create_string_from_utf8(value.as_bytes().to_vec())
        .map(JSValue::make_string)?;
    o.define_property_value_str(ctx, "name", nv, JS_PROP_C_W_E)?;
    o.define_property_value_str(ctx, "value", vv, JS_PROP_C_W_E)?;
    Ok(JSValue::from(o))
}

/// Spec §7.1 "query cookies": the in-scope, script-visible cookies for `url`
/// (optionally filtered by `name`), in creation order.
fn query_cookies(
    ctx: &mut ScopedContext,
    url: &Url,
    name: Option<&str>,
) -> Result<Vec<JSValue>, i32> {
    let jar = global_cookie_jar();
    let mut items: Vec<(String, String)> = jar.with_store(|store| {
        store
            .matches(url)
            .into_iter()
            // Retrieval includes HttpOnly cookies (they ride HTTP requests);
            // the spec asserts they are excluded for this non-HTTP API.
            .filter(|c| !c.http_only().unwrap_or(false))
            .map(|c| (c.name().to_string(), c.value().to_string()))
            .collect()
    });
    if let Some(n) = name {
        items.retain(|(nm, _)| nm == n);
    }
    // Present in first-seen creation order (the store's iteration is
    // hash-ordered).
    {
        let order = global_cookie_order().read().unwrap();
        items.sort_by_key(|(nm, _)| order.iter().position(|o| o == nm).unwrap_or(usize::MAX));
    }
    let mut out = Vec::with_capacity(items.len());
    for (nm, val) in items {
        out.push(make_item(ctx, &nm, &val)?);
    }
    Ok(out)
}

fn resolve_first(ctx: &mut ScopedContext, items: Vec<JSValue>) -> JSResult {
    match items.into_iter().next() {
        Some(v) => Promise::from_resolve_value(ctx, v).map(JSValue::from),
        None => Promise::from_resolve_value(ctx, JSValue::NULL).map(JSValue::from),
    }
}

fn resolve_list(ctx: &mut ScopedContext, items: Vec<JSValue>) -> JSResult {
    let arr = Array::from_values(ctx, items)?;
    Promise::from_resolve_value(ctx, JSValue::from(arr)).map(JSValue::from)
}

// ---------------------------------------------------------------------------
// Overload parsing
// ---------------------------------------------------------------------------

/// The `get` / `getAll` argument overloads.
enum GetOverload {
    Name(String),
    Options {
        name: Option<String>,
        url: Option<String>,
        empty: bool,
    },
}

fn read_get_overload(ctx: &mut ScopedContext, cc: &CallContext) -> Result<GetOverload, i32> {
    let args = cc.arguments();
    if args.is_empty() {
        return Ok(GetOverload::Options {
            name: None,
            url: None,
            empty: true,
        });
    }
    let arg = args[0];
    if arg.is_null() || arg.as_object().is_some() {
        let (name, url) = match arg.as_object() {
            Some(o) => {
                let nv = o.get_property_str(ctx, "name")?;
                let uv = o.get_property_str(ctx, "url")?;
                let name = if nv.is_undefined() {
                    None
                } else {
                    Some(js_string(ctx, &nv)?)
                };
                let url = if uv.is_undefined() {
                    None
                } else {
                    Some(js_string(ctx, &uv)?)
                };
                (name, url)
            }
            None => (None, None),
        };
        let empty = name.is_none() && url.is_none();
        Ok(GetOverload::Options { name, url, empty })
    } else {
        Ok(GetOverload::Name(js_string(ctx, &arg)?))
    }
}

/// Run the shared get/getAll body: resolve the target URL, then query.
fn run_query(
    ctx: &mut ScopedContext,
    overload: GetOverload,
    base: &Url,
    want_first: bool,
) -> JSResult {
    match overload {
        GetOverload::Name(raw) => {
            let name = normalize(&raw);
            let items = query_cookies(ctx, base, Some(&name))?;
            if want_first {
                resolve_first(ctx, items)
            } else {
                resolve_list(ctx, items)
            }
        }
        GetOverload::Options { name, url, empty } => {
            if empty && want_first {
                return reject_type_error(ctx, "cookieStore.get: options must not be empty");
            }
            let target = match check_options_url(ctx, base, url) {
                Ok(u) => u,
                Err(CheckErr::Reject(v)) => return Ok(v),
                Err(CheckErr::Fatal(c)) => return Err(c),
            };
            let norm = name.map(|n| normalize(&n));
            let items = query_cookies(ctx, &target, norm.as_deref())?;
            if want_first {
                resolve_first(ctx, items)
            } else {
                resolve_list(ctx, items)
            }
        }
    }
}

fn js_cookie_store_get(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let base = match current_url(ctx) {
        UrlOutcome::Url(u) => u,
        UrlOutcome::Reject(v) => return Ok(v),
        UrlOutcome::Fatal(c) => return Err(c),
    };
    let overload = read_get_overload(ctx, &cc)?;
    run_query(ctx, overload, &base, true)
}

fn js_cookie_store_get_all(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let base = match current_url(ctx) {
        UrlOutcome::Url(u) => u,
        UrlOutcome::Reject(v) => return Ok(v),
        UrlOutcome::Fatal(c) => return Err(c),
    };
    let overload = read_get_overload(ctx, &cc)?;
    run_query(ctx, overload, &base, false)
}

// ---------------------------------------------------------------------------
// Set
// ---------------------------------------------------------------------------

struct SetArgs {
    name: String,
    value: String,
    expires_ms: Option<f64>,
    domain: Option<String>,
    path: String,
    same_site: String,
    partitioned: bool,
    max_age: Option<i64>,
}

/// Read a nullable number member (`undefined`/`null` → `None`).
fn read_nullable_f64(ctx: &mut ScopedContext, o: &Object, key: &str) -> Result<Option<f64>, i32> {
    let v = o.get_property_str(ctx, key)?;
    if v.is_undefined_or_null() {
        Ok(None)
    } else {
        Ok(Some(v.to_number(ctx)?.to_f64()))
    }
}

/// Read a nullable string member (`undefined`/`null` → `None`).
fn read_nullable_string(
    ctx: &mut ScopedContext,
    o: &Object,
    key: &str,
) -> Result<Option<String>, i32> {
    let v = o.get_property_str(ctx, key)?;
    if v.is_undefined_or_null() {
        Ok(None)
    } else {
        Ok(Some(js_string(ctx, &v)?))
    }
}

/// Read a string member with a default (absent → `default`).
fn read_string_default(
    ctx: &mut ScopedContext,
    o: &Object,
    key: &str,
    default: &str,
) -> Result<String, i32> {
    let v = o.get_property_str(ctx, key)?;
    if v.is_undefined() {
        Ok(default.to_string())
    } else {
        js_string(ctx, &v)
    }
}

/// Read a boolean member with a default (absent → `default`).
fn read_bool_default(
    ctx: &mut ScopedContext,
    o: &Object,
    key: &str,
    default: bool,
) -> Result<bool, i32> {
    let v = o.get_property_str(ctx, key)?;
    if v.is_undefined() {
        Ok(default)
    } else {
        v.to_bool()
    }
}

fn read_set_args(ctx: &mut ScopedContext, cc: &CallContext) -> Result<SetArgs, i32> {
    let args = cc.arguments();
    if args.is_empty() {
        return Err(ctx.throw_type_error("cookieStore.set requires arguments"));
    }
    let arg0 = args[0];
    if arg0.is_null() || arg0.as_object().is_some() {
        let Some(o) = arg0.as_object() else {
            return Err(ctx.throw_type_error("cookieStore.set: CookieInit.name is required"));
        };
        let nv = o.get_property_str(ctx, "name")?;
        let vv = o.get_property_str(ctx, "value")?;
        if nv.is_undefined() {
            return Err(ctx.throw_type_error("cookieStore.set: CookieInit.name is required"));
        }
        if vv.is_undefined() {
            return Err(ctx.throw_type_error("cookieStore.set: CookieInit.value is required"));
        }
        let name = js_string(ctx, &nv)?;
        let value = js_string(ctx, &vv)?;
        let same_site = read_string_default(ctx, &o, "sameSite", "strict")?;
        if !matches!(same_site.as_str(), "strict" | "lax" | "none") {
            return Err(
                ctx.throw_type_error("cookieStore.set: sameSite must be 'strict', 'lax' or 'none'")
            );
        }
        Ok(SetArgs {
            name,
            value,
            expires_ms: read_nullable_f64(ctx, &o, "expires")?,
            domain: read_nullable_string(ctx, &o, "domain")?,
            path: read_string_default(ctx, &o, "path", "/")?,
            same_site,
            partitioned: read_bool_default(ctx, &o, "partitioned", false)?,
            max_age: read_nullable_f64(ctx, &o, "maxAge")?.map(|n| n as i64),
        })
    } else {
        if args.len() < 2 {
            return Err(ctx.throw_type_error("cookieStore.set requires a value"));
        }
        Ok(SetArgs {
            name: js_string(ctx, &arg0)?,
            value: js_string(ctx, &args[1])?,
            expires_ms: None,
            domain: None,
            path: "/".to_string(),
            same_site: "strict".to_string(),
            partitioned: false,
            max_age: None,
        })
    }
}

/// Spec §7.2 "set a cookie". Returns `Err(message)` when the algorithm reports
/// failure (the caller rejects with a `TypeError`).
fn set_a_cookie(url: &Url, a: &SetArgs) -> Result<(), String> {
    let name = normalize(&a.name);
    let value = normalize(&a.value);

    if has_invalid_cookie_char(&name) || has_invalid_cookie_char(&value) {
        return Err("cookie name or value contains an invalid character".to_string());
    }
    if name.contains('=') {
        return Err("cookie name must not contain '='".to_string());
    }
    let name_lower = name.to_ascii_lowercase();
    if name.is_empty() {
        if value.contains('=') {
            return Err("cookie value must not contain '=' when the name is empty".to_string());
        }
        if value.is_empty() {
            return Err("cookie name and value must not both be empty".to_string());
        }
        let value_lower = value.to_ascii_lowercase();
        if value_lower.starts_with("__host-")
            || value_lower.starts_with("__host-http-")
            || value_lower.starts_with("__http-")
            || value_lower.starts_with("__secure-")
        {
            return Err("cookie value uses a reserved prefix".to_string());
        }
    }
    if name_lower.starts_with("__host-http-") || name_lower.starts_with("__http-") {
        return Err("cookie name uses a reserved prefix".to_string());
    }
    if name.len() + value.len() > MAX_NAME_VALUE_PAIR_SIZE {
        return Err("cookie name/value exceeds the maximum size".to_string());
    }

    let host = url.host_str().unwrap_or("").to_ascii_lowercase();
    let mut domain_attr: Option<String> = None;
    if let Some(domain) = &a.domain {
        if domain.starts_with('.') {
            return Err("cookie domain must not start with '.'".to_string());
        }
        if name_lower.starts_with("__host-") {
            return Err("__Host- cookies must not set a domain".to_string());
        }
        let d = domain.to_ascii_lowercase();
        let suffix = host == d || (!host.is_empty() && host.ends_with(&format!(".{d}")));
        if !suffix {
            return Err("cookie domain is not a suffix of the current host".to_string());
        }
        let parsed =
            Host::parse(&d).map_err(|_| "cookie domain is not a valid host".to_string())?;
        let encoded = parsed.to_string();
        if encoded.len() > MAX_ATTRIBUTE_VALUE_SIZE {
            return Err("cookie domain exceeds the maximum size".to_string());
        }
        domain_attr = Some(encoded);
    }

    if a.expires_ms.is_some() && a.max_age.is_some() {
        return Err("expires and maxAge are mutually exclusive".to_string());
    }

    let mut path = a.path.clone();
    if path.is_empty() {
        path = default_path(url);
    }
    if !path.starts_with('/') {
        return Err("cookie path must start with '/'".to_string());
    }
    if path != "/" && name_lower.starts_with("__host-") {
        return Err("__Host- cookies must use '/' as the path".to_string());
    }
    if path.len() > MAX_ATTRIBUTE_VALUE_SIZE {
        return Err("cookie path exceeds the maximum size".to_string());
    }

    // Assemble a Set-Cookie value and store it (best-effort per spec step 25).
    let mut s = format!("{name}={value}");
    if let Some(d) = &domain_attr {
        s.push_str(&format!("; Domain={d}"));
    }
    if let Some(ms) = a.expires_ms {
        s.push_str(&format!("; Expires={}", date_serialize(ms)));
    } else if let Some(ma) = a.max_age {
        s.push_str(&format!("; Max-Age={ma}"));
    }
    s.push_str(&format!("; Path={path}"));
    s.push_str("; Secure");
    let ss = match a.same_site.as_str() {
        "none" => "None",
        "lax" => "Lax",
        _ => "Strict",
    };
    s.push_str(&format!("; SameSite={ss}"));
    if a.partitioned {
        s.push_str("; Partitioned");
    }

    global_cookie_jar().add_cookie_str(&s, url);
    cookie_order_record(&s);
    Ok(())
}

fn js_cookie_store_set(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let url = match current_url(ctx) {
        UrlOutcome::Url(u) => u,
        UrlOutcome::Reject(v) => return Ok(v),
        UrlOutcome::Fatal(c) => return Err(c),
    };
    let args = read_set_args(ctx, &cc)?;
    match set_a_cookie(&url, &args) {
        Ok(()) => resolve_undefined(ctx),
        Err(msg) => reject_type_error(ctx, &msg),
    }
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

struct DeleteArgs {
    name: String,
    domain: Option<String>,
    path: String,
    partitioned: bool,
}

fn read_delete_args(ctx: &mut ScopedContext, cc: &CallContext) -> Result<DeleteArgs, i32> {
    let args = cc.arguments();
    if args.is_empty() {
        return Err(ctx.throw_type_error("cookieStore.delete requires arguments"));
    }
    let arg0 = args[0];
    if arg0.is_null() || arg0.as_object().is_some() {
        let Some(o) = arg0.as_object() else {
            return Err(ctx.throw_type_error(
                "cookieStore.delete: CookieStoreDeleteOptions.name is required",
            ));
        };
        let nv = o.get_property_str(ctx, "name")?;
        if nv.is_undefined() {
            return Err(ctx.throw_type_error(
                "cookieStore.delete: CookieStoreDeleteOptions.name is required",
            ));
        }
        Ok(DeleteArgs {
            name: js_string(ctx, &nv)?,
            domain: read_nullable_string(ctx, &o, "domain")?,
            path: read_string_default(ctx, &o, "path", "/")?,
            partitioned: read_bool_default(ctx, &o, "partitioned", false)?,
        })
    } else {
        Ok(DeleteArgs {
            name: js_string(ctx, &arg0)?,
            domain: None,
            path: "/".to_string(),
            partitioned: true,
        })
    }
}

/// Spec §7.3 "delete a cookie": set an already-expired cookie (`maxAge: 0`).
fn delete_a_cookie(url: &Url, a: &DeleteArgs) -> Result<(), String> {
    let name = normalize(&a.name);
    let value = if name.is_empty() {
        // Spec: any non-empty implementation-defined string.
        "deleted".to_string()
    } else {
        String::new()
    };
    set_a_cookie(
        url,
        &SetArgs {
            name,
            value,
            expires_ms: None,
            domain: a.domain.clone(),
            path: a.path.clone(),
            same_site: "strict".to_string(),
            partitioned: a.partitioned,
            max_age: Some(0),
        },
    )
}

fn js_cookie_store_delete(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let url = match current_url(ctx) {
        UrlOutcome::Url(u) => u,
        UrlOutcome::Reject(v) => return Ok(v),
        UrlOutcome::Fatal(c) => return Err(c),
    };
    let args = read_delete_args(ctx, &cc)?;
    match delete_a_cookie(&url, &args) {
        Ok(()) => resolve_undefined(ctx),
        Err(msg) => reject_type_error(ctx, &msg),
    }
}

// ---------------------------------------------------------------------------
// Class definition + installation
// ---------------------------------------------------------------------------

fn js_cookie_store_constructor(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    Err(ctx.throw_type_error("Illegal constructor"))
}

const COOKIE_STORE_PROTO: &[FieldDef] = &[
    FieldDef::FUNC_ENUM("get", 1, js_cookie_store_get, 0),
    FieldDef::FUNC_ENUM("getAll", 1, js_cookie_store_get_all, 0),
    FieldDef::FUNC_ENUM("set", 2, js_cookie_store_set, 0),
    FieldDef::FUNC_ENUM("delete", 2, js_cookie_store_delete, 0),
    // WebIDL class string (`Object.prototype.toString` -> "[object CookieStore]").
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "CookieStore",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "CookieStore",
    JSCookieStore,
    (),
    COOKIE_STORE_PROTO,
    Some(ClassCtorDef::new(js_cookie_store_constructor, 0, false).expose_to_global())
);

/// Install the `cookieStore` global (a `CookieStore` instance).
pub(crate) fn install_cookie_store(ctx: &mut ScopedContext, mut global: Object) -> Result<(), i32> {
    let store = JSCookieStore::new_instance(ctx, JSValue::UNDEFINED)?;
    global.define_property_value_str(ctx, "cookieStore", store.into(), JS_PROP_C_W_E)?;
    Ok(())
}
