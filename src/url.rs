// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WHATWG URL Standard — URL and URLSearchParams implementations.
//!
//! Both classes are backed by the `url` crate for spec-compliant parsing.
//! `URL.searchParams` returns a `URLSearchParams` that shares state via `Rc<RefCell<url::Url>>`.

use std::{
    cell::RefCell,
    collections::HashMap,
    rc::Rc,
    sync::{LazyLock, Mutex},
};

use url::Url;
use zuqe::{
    Array, CallContext, ClassCtorDef, FieldDef, JSResult, JSValue, Object, ScopedContext,
    WriteBarrier, def_native_object,
    gc_lite::GcTrace,
};

use crate::blob::BlobPayload;

/// Global registry of object URLs created by `URL.createObjectURL`. Keyed by the
/// full `blob:` URL string so `fetch` can resolve it back to its `Blob`.
static BLOB_URLS: LazyLock<Mutex<HashMap<String, BlobPayload>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Look up a `blob:` object URL, returning a clone of its `BlobPayload` if the
/// URL was created via `URL.createObjectURL` and not yet revoked.
pub(crate) fn blob_store_get(url: &str) -> Option<BlobPayload> {
    BLOB_URLS.lock().unwrap().get(url).cloned()
}

// ===========================================================================
// URL class
// ===========================================================================

#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct UrlPayload {
    /// Shared Url state (shared with URLSearchParams when created).
    #[gc(skip)]
    shared: Rc<RefCell<Url>>,
    /// Lazily created URLSearchParams tied to this URL.
    search_params: RefCell<WriteBarrier<Option<Object>>>,
}

fn get_url<'a>(ctx: &mut ScopedContext, val: &'a JSValue) -> Result<&'a UrlPayload, i32> {
    JSURL::payload_of(val).ok_or_else(|| ctx.throw_internal_error("not a URL instance"))
}

// -- Constructor -----------------------------------------------------------

fn js_url_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let new_target = cc.this();
    if cc.length() < 1 {
        return Err(ctx.throw_type_error("Failed to construct 'URL': 1 argument required"));
    }

    let url_str = cc.arg(0).to_string(ctx)?;
    let url_text = url_str.content().encode_utf8(false).to_string();

    let parsed = if cc.length() >= 2 {
        let base_str = cc.arg(1).to_string(ctx)?;
        let base_text = base_str.content().encode_utf8(false).to_string();
        let base = Url::parse(&base_text)
            .map_err(|_| ctx.throw_type_error("Failed to construct 'URL': Invalid base URL"))?;
        base.join(&url_text)
            .map_err(|_| ctx.throw_type_error("Failed to construct 'URL': Invalid URL"))
    } else {
        Url::parse(&url_text)
            .map_err(|_| ctx.throw_type_error("Failed to construct 'URL': Invalid URL"))
    }?;

    JSURL::new_instance(
        ctx,
        new_target,
        UrlPayload {
            shared: Rc::new(RefCell::new(parsed)),
            search_params: RefCell::new(WriteBarrier::new(None)),
        },
    )
    .map(JSValue::from)
}

// -- Getters / Setters -----------------------------------------------------
//
// All URL accessors share one getter and one setter native function; the
// `FieldDef::GETSET` magic value selects the field.

const URL_HREF: i16 = 0;
const URL_ORIGIN: i16 = 1;
const URL_PROTOCOL: i16 = 2;
const URL_USERNAME: i16 = 3;
const URL_PASSWORD: i16 = 4;
const URL_HOST: i16 = 5;
const URL_HOSTNAME: i16 = 6;
const URL_PORT: i16 = 7;
const URL_PATHNAME: i16 = 8;
const URL_SEARCH: i16 = 9;
const URL_HASH: i16 = 10;

fn js_url_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let url = get_url(ctx, &this)?;
    let u = url.shared.borrow();
    let s = match cc.magic() as i16 {
        URL_HREF => u.as_str().to_string(),
        URL_ORIGIN => match u.origin() {
            url::Origin::Opaque(_) => "null".to_string(),
            url::Origin::Tuple(scheme, host, port) => {
                if port > 0 {
                    format!("{}://{}:{}", scheme, host, port)
                } else {
                    format!("{}://{}", scheme, host)
                }
            }
        },
        URL_PROTOCOL => format!("{}:", u.scheme()),
        URL_USERNAME => u.username().to_string(),
        URL_PASSWORD => u.password().unwrap_or("").to_string(),
        URL_HOST => match (u.host_str(), u.port()) {
            (Some(host), Some(port)) => format!("{}:{}", host, port),
            (Some(host), None) => host.to_string(),
            _ => String::new(),
        },
        URL_HOSTNAME => u.host_str().unwrap_or("").to_string(),
        URL_PORT => match u.port() {
            Some(port) => port.to_string(),
            None => String::new(),
        },
        URL_PATHNAME => u.path().to_string(),
        URL_SEARCH => match u.query() {
            Some(q) if !q.is_empty() => format!("?{}", q),
            _ => String::new(),
        },
        URL_HASH => match u.fragment() {
            Some(f) if !f.is_empty() => format!("#{}", f),
            _ => String::new(),
        },
        _ => unreachable!(),
    };
    ctx.create_string_from_utf8(s.into_bytes())
        .map(JSValue::make_string)
}

fn js_url_setter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let url = get_url(ctx, &this)?;
    let val = cc.arg(0).to_string(ctx)?;
    let text = val.content().encode_utf8(false).to_string();

    match cc.magic() as i16 {
        URL_HREF => {
            let new_url = Url::parse(&text)
                .map_err(|_| ctx.throw_type_error("Failed to set 'href': Invalid URL"))?;
            *url.shared.borrow_mut() = new_url;
            // Invalidate cached searchParams on href change
            url.search_params.borrow_mut().take();
        }
        URL_PROTOCOL => {
            let scheme = text.trim_end_matches(':');
            let _ = url.shared.borrow_mut().set_scheme(scheme);
        }
        URL_USERNAME => {
            let _ = url.shared.borrow_mut().set_username(&text);
        }
        URL_PASSWORD => {
            let _ = url.shared.borrow_mut().set_password(if text.is_empty() {
                None
            } else {
                Some(&text)
            });
        }
        URL_HOST | URL_HOSTNAME => {
            let _ = url.shared.borrow_mut().set_host(Some(&text));
        }
        URL_PORT => {
            let mut u = url.shared.borrow_mut();
            if text.is_empty() {
                let _ = u.set_port(None);
            } else if let Ok(port) = text.parse::<u16>() {
                let _ = u.set_port(Some(port));
            }
        }
        URL_PATHNAME => {
            url.shared.borrow_mut().set_path(&text);
        }
        URL_SEARCH => {
            let mut u = url.shared.borrow_mut();
            let query = text.strip_prefix('?').unwrap_or(&text);
            if query.is_empty() {
                u.set_query(None);
            } else {
                u.set_query(Some(query));
            }
        }
        URL_HASH => {
            let mut u = url.shared.borrow_mut();
            let fragment = text.strip_prefix('#').unwrap_or(&text);
            if fragment.is_empty() {
                u.set_fragment(None);
            } else {
                u.set_fragment(Some(fragment));
            }
        }
        _ => unreachable!(),
    }
    Ok(JSValue::UNDEFINED)
}

// -- searchParams getter (lazy, shares Rc<RefCell<Url>>) ------------------

fn js_url_search_params_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let url = get_url(ctx, &this)?;

    // Return cached searchParams if already created
    if let Some(sp) = url.search_params.borrow().get() {
        return Ok(sp.into());
    }

    let sp = JSURLSearchParams::new_instance(
        ctx,
        JSValue::UNDEFINED,
        SearchParamsPayload {
            shared_url: Some(url.shared.clone()),
            standalone_query: RefCell::new(String::new()),
        },
    )?;
    // The guard slot records the old-URL→young-searchParams barrier itself.
    url.search_params
        .borrow_mut()
        .set(ctx, this, Some(*sp.as_object()));
    Ok(sp.into())
}

// -- toString / toJSON -----------------------------------------------------

fn js_url_to_string(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let url = get_url(ctx, &this)?;
    let s = url.shared.borrow().as_str().to_string();
    ctx.create_string_from_utf8(s.into_bytes())
        .map(JSValue::make_string)
}

// -- createObjectURL / revokeObjectURL --------------------------------------

/// Monotonic counter mixed with a process-random seed to synthesize unique
/// object-URL suffixes (good enough for `blob:` URL identity in this engine).
static BLOB_URL_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn js_url_create_object_url(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let arg = cc.arg(0);
    let bytes = crate::blob::blob_bytes_of(&arg)
        .ok_or_else(|| ctx.throw_type_error("createObjectURL requires a Blob"))?;
    let type_ = crate::blob::blob_type_of(&arg).unwrap_or_default();
    let seq = BLOB_URL_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let url = format!(
        "blob:{:016x}-{:016x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
        seq
    );
    BLOB_URLS
        .lock()
        .unwrap()
        .insert(url.clone(), BlobPayload { bytes, type_ });
    ctx.create_string_from_utf8(url.into_bytes())
        .map(JSValue::make_string)
}

fn js_url_revoke_object_url(_ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let arg = cc.arg(0);
    if let Some(s) = arg.as_string(false) {
        let key = s.content().encode_utf8(false);
        BLOB_URLS.lock().unwrap().remove(key.as_ref());
    }
    Ok(JSValue::UNDEFINED)
}

// ===========================================================================
// URLSearchParams
// ===========================================================================

#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct SearchParamsPayload {
    /// Shared URL state; None when standalone (not tied to a URL).
    #[gc(skip)]
    shared_url: Option<Rc<RefCell<Url>>>,
    /// Query string (used only when standalone).
    standalone_query: RefCell<String>,
}

fn get_sp<'a>(ctx: &mut ScopedContext, val: &'a JSValue) -> Result<&'a SearchParamsPayload, i32> {
    JSURLSearchParams::payload_of(val)
        .ok_or_else(|| ctx.throw_internal_error("not a URLSearchParams instance"))
}

/// Get current query string from shared URL or standalone.
fn sp_get_query(sp: &SearchParamsPayload) -> String {
    match sp.shared_url {
        Some(ref u) => u.borrow().query().unwrap_or("").to_string(),
        None => sp.standalone_query.borrow().clone(),
    }
}

/// Set current query string on shared URL and/or standalone.
fn sp_set_query(sp: &SearchParamsPayload, query: &str) {
    if let Some(ref u) = sp.shared_url {
        if query.is_empty() {
            u.borrow_mut().set_query(None);
        } else {
            u.borrow_mut().set_query(Some(query));
        }
    } else {
        *sp.standalone_query.borrow_mut() = query.to_string();
    }
}

// -- URLSearchParams constructor -------------------------------------------

fn js_sp_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let new_target = cc.this();

    let query = if cc.length() == 0 {
        String::new()
    } else {
        let arg = cc.arg(0);
        if let Some(s) = arg.as_string(true) {
            let text = s.content().encode_utf8(false).to_string();
            text.strip_prefix('?').unwrap_or(&text).to_string()
        } else if let Some(mut o) = arg.as_object() {
            let pks = o.get_own_property_names(
                ctx,
                zuqe::JS_GPN_ENUM_ONLY | zuqe::JS_GPN_STR_OR_INT_MASK,
            )?;
            let mut pairs: Vec<(String, String)> = Vec::new();
            for pk in pks.iter() {
                let key_v = pk.atom.to_value(ctx)?;
                let key_r = key_v.to_string(ctx)?;
                let k = key_r.content().encode_utf8(false).to_string();
                let val = o.get_property(ctx, pk.atom)?;
                let v = val.to_string(ctx)?.content().encode_utf8(false).to_string();
                let encoded_k =
                    url::form_urlencoded::byte_serialize(k.as_bytes()).collect::<String>();
                let encoded_v =
                    url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>();
                pairs.push((encoded_k, encoded_v));
            }
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            pairs
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&")
        } else {
            return Err(ctx.throw_type_error("URLSearchParams init must be string or object"));
        }
    };

    JSURLSearchParams::new_instance(
        ctx,
        new_target,
        SearchParamsPayload {
            shared_url: None,
            standalone_query: RefCell::new(query),
        },
    )
    .map(JSValue::from)
}

// -- URLSearchParams methods ----------------------------------------------

fn js_sp_append(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let sp = get_sp(ctx, &this)?;
    let name = cc.arg(0).to_string(ctx)?;
    let value = cc.arg(1).to_string(ctx)?;
    let n = name.content().encode_utf8(false);
    let v = value.content().encode_utf8(false);
    let encoded_n = url::form_urlencoded::byte_serialize(n.as_bytes()).collect::<String>();
    let encoded_v = url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>();

    let mut query = sp_get_query(sp);
    if query.is_empty() {
        query = format!("{}={}", encoded_n, encoded_v);
    } else {
        query.push_str(&format!("&{}={}", encoded_n, encoded_v));
    }
    sp_set_query(sp, &query);

    Ok(JSValue::UNDEFINED)
}

fn js_sp_delete(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let sp = get_sp(ctx, &this)?;
    let name = cc.arg(0).to_string(ctx)?;
    let n = name.content().encode_utf8(false).to_string();

    let query = sp_get_query(sp);
    let pairs: Vec<String> = url::form_urlencoded::parse(query.as_bytes())
        .filter(|(k, _)| !n.eq(k))
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    sp_set_query(sp, &pairs.join("&"));

    Ok(JSValue::UNDEFINED)
}

fn js_sp_get(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let sp = get_sp(ctx, &this)?;
    let name = cc.arg(0).to_string(ctx)?;
    let n = name.content().encode_utf8(false).to_string();

    let query = sp_get_query(sp);
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        if k == n {
            return ctx
                .create_string_from_utf8(v.as_bytes().to_vec())
                .map(JSValue::make_string);
        }
    }

    Ok(JSValue::NULL)
}

fn js_sp_get_all(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let sp = get_sp(ctx, &this)?;
    let name = cc.arg(0).to_string(ctx)?;
    let n = name.content().encode_utf8(false).to_string();

    let query = sp_get_query(sp);
    let values: Vec<JSValue> = url::form_urlencoded::parse(query.as_bytes())
        .filter(|(k, _)| n.eq(k))
        .map(|(_, v)| {
            let s = ctx.create_string_from_utf8(v.as_bytes().to_vec()).unwrap();
            JSValue::make_string(s)
        })
        .collect();

    let arr = Array::from_values(ctx, values)?;
    Ok(arr.into())
}

fn js_sp_has(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let sp = get_sp(ctx, &this)?;
    let name = cc.arg(0).to_string(ctx)?;
    let n = name.content().encode_utf8(false).to_string();

    let query = sp_get_query(sp);
    let found = url::form_urlencoded::parse(query.as_bytes()).any(|(k, _)| n.eq(&k));

    Ok(JSValue::from(found))
}

fn js_sp_set(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let sp = get_sp(ctx, &this)?;
    let name = cc.arg(0).to_string(ctx)?;
    let value = cc.arg(1).to_string(ctx)?;
    let n = name.content().encode_utf8(false);
    let v = value.content().encode_utf8(false);
    let encoded_n = url::form_urlencoded::byte_serialize(n.as_bytes()).collect::<String>();
    let encoded_v = url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>();

    let query = sp_get_query(sp);
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .map(|(k, val)| (k.to_string(), val.to_string()))
        .collect();

    let mut new_pairs = Vec::new();
    let mut replaced = false;
    for (k, val) in &pairs {
        if k == &n {
            if !replaced {
                new_pairs.push((encoded_n.clone(), encoded_v.clone()));
                replaced = true;
            }
        } else {
            new_pairs.push((k.clone(), val.clone()));
        }
    }
    if !replaced {
        new_pairs.push((encoded_n, encoded_v));
    }

    let new_query = new_pairs
        .iter()
        .map(|(k, val)| format!("{}={}", k, val))
        .collect::<Vec<_>>()
        .join("&");
    sp_set_query(sp, &new_query);

    Ok(JSValue::UNDEFINED)
}

fn js_sp_sort(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let sp = get_sp(ctx, &this)?;

    let query = sp_get_query(sp);
    let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));

    let new_query = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&");
    sp_set_query(sp, &new_query);

    Ok(JSValue::UNDEFINED)
}

fn js_sp_to_string(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let sp = get_sp(ctx, &this)?;
    let query = sp_get_query(sp);
    ctx.create_string_from_utf8(query.into_bytes())
        .map(JSValue::make_string)
}

fn js_sp_for_each(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let sp = get_sp(ctx, &this)?;
    if cc.length() == 0 {
        return Err(ctx.throw_type_error("forEach requires a callback"));
    }

    let cb = cc.arg(0).ensure_callable(ctx)?;
    let query = sp_get_query(sp);

    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        let val_js = JSValue::make_string(ctx.create_string_from_utf8(v.as_bytes().to_vec())?);
        let key_js = JSValue::make_string(ctx.create_string_from_utf8(k.as_bytes().to_vec())?);
        if cb
            .call(ctx, JSValue::UNDEFINED, &[val_js, key_js, this])
            .is_err()
        {
            return Err(-1);
        }
    }

    Ok(JSValue::UNDEFINED)
}

fn js_sp_entries(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    Err(ctx.throw_type_error("URLSearchParams.entries() not yet implemented"))
}

fn js_sp_keys(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    Err(ctx.throw_type_error("URLSearchParams.keys() not yet implemented"))
}

fn js_sp_values(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    Err(ctx.throw_type_error("URLSearchParams.values() not yet implemented"))
}

// ===========================================================================
// Registration: URL
// ===========================================================================

const CLASS_URL_PROTO: &[FieldDef] = &[
    FieldDef::GETSET_ENUM("href", Some(js_url_getter), Some(js_url_setter), URL_HREF),
    FieldDef::GETSET_ENUM("origin", Some(js_url_getter), None, URL_ORIGIN),
    FieldDef::GETSET_ENUM(
        "protocol",
        Some(js_url_getter),
        Some(js_url_setter),
        URL_PROTOCOL,
    ),
    FieldDef::GETSET_ENUM(
        "username",
        Some(js_url_getter),
        Some(js_url_setter),
        URL_USERNAME,
    ),
    FieldDef::GETSET_ENUM(
        "password",
        Some(js_url_getter),
        Some(js_url_setter),
        URL_PASSWORD,
    ),
    FieldDef::GETSET_ENUM("host", Some(js_url_getter), Some(js_url_setter), URL_HOST),
    FieldDef::GETSET_ENUM(
        "hostname",
        Some(js_url_getter),
        Some(js_url_setter),
        URL_HOSTNAME,
    ),
    FieldDef::GETSET_ENUM("port", Some(js_url_getter), Some(js_url_setter), URL_PORT),
    FieldDef::GETSET_ENUM(
        "pathname",
        Some(js_url_getter),
        Some(js_url_setter),
        URL_PATHNAME,
    ),
    FieldDef::GETSET_ENUM(
        "search",
        Some(js_url_getter),
        Some(js_url_setter),
        URL_SEARCH,
    ),
    FieldDef::GETSET_ENUM("hash", Some(js_url_getter), Some(js_url_setter), URL_HASH),
    FieldDef::GETSET_ENUM("searchParams", Some(js_url_search_params_getter), None, 0),
    FieldDef::FUNC_ENUM("toString", 0, js_url_to_string, 0),
    FieldDef::FUNC_ENUM("toJSON", 0, js_url_to_string, 0),
    // WebIDL class string (`Object.prototype.toString` -> "[object URL]").
    FieldDef::STR("[Symbol.toStringTag]", "URL", zuqe::JS_PROP_CONFIGURABLE),
];

def_native_object!(
    "URL",
    JSURL,
    UrlPayload,
    CLASS_URL_PROTO,
    Some(ClassCtorDef::new(js_url_constructor, 2, true).expose_to_global())
);

// ===========================================================================
// Registration: URL static methods (createObjectURL / revokeObjectURL)
// ===========================================================================

/// Mount `URL.createObjectURL` / `URL.revokeObjectURL` as static methods on the
/// global `URL` constructor. These back the WHATWG object-URL store used by
/// `fetch('blob:...')`.
pub fn init_url(ctx: &mut ScopedContext, global: &mut Object) -> Result<(), i32> {
    let create_fn = ctx.create_native_function(
        zuqe::Callback::Func(js_url_create_object_url),
        "createObjectURL",
        1,
        0,
    )?;
    let revoke_fn = ctx.create_native_function(
        zuqe::Callback::Func(js_url_revoke_object_url),
        "revokeObjectURL",
        1,
        0,
    )?;
    if let Some(mut ctor) = global.get_property_str(ctx, "URL")?.as_object() {
        ctor.define_property_value_str(
            ctx,
            "createObjectURL",
            create_fn.into(),
            zuqe::JS_PROP_C_W_E,
        )?;
        ctor.define_property_value_str(
            ctx,
            "revokeObjectURL",
            revoke_fn.into(),
            zuqe::JS_PROP_C_W_E,
        )?;
    }
    Ok(())
}

// ===========================================================================
// Registration: URLSearchParams
// ===========================================================================

const CLASS_SP_PROTO: &[FieldDef] = &[
    FieldDef::FUNC_ENUM("append", 2, js_sp_append, 0),
    FieldDef::FUNC_ENUM("delete", 1, js_sp_delete, 0),
    FieldDef::FUNC_ENUM("get", 1, js_sp_get, 0),
    FieldDef::FUNC_ENUM("getAll", 1, js_sp_get_all, 0),
    FieldDef::FUNC_ENUM("has", 1, js_sp_has, 0),
    FieldDef::FUNC_ENUM("set", 2, js_sp_set, 0),
    FieldDef::FUNC_ENUM("sort", 0, js_sp_sort, 0),
    FieldDef::FUNC_ENUM("toString", 0, js_sp_to_string, 0),
    FieldDef::FUNC_ENUM("forEach", 1, js_sp_for_each, 0),
    FieldDef::FUNC_ENUM("entries", 0, js_sp_entries, 0),
    FieldDef::FUNC_ENUM("keys", 0, js_sp_keys, 0),
    FieldDef::FUNC_ENUM("values", 0, js_sp_values, 0),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "URLSearchParams",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "URLSearchParams",
    JSURLSearchParams,
    SearchParamsPayload,
    CLASS_SP_PROTO,
    Some(ClassCtorDef::new(js_sp_constructor, 1, true).expose_to_global())
);

// ===========================================================================
// Shared helpers for other modules (path.fileURLToPath / path.pathToFileURL)
// ===========================================================================

/// Extract the URL text from a `URL` instance or a plain string. Used by
/// `path.fileURLToPath`; any other value throws a TypeError.
pub fn url_arg_to_str(ctx: &mut ScopedContext, val: &JSValue) -> Result<String, i32> {
    if let Some(s) = val.as_string(false) {
        return Ok(s.content().encode_utf8(false).to_string());
    }
    if let Some(p) = JSURL::payload_of(val) {
        return Ok(p.shared.borrow().as_str().to_string());
    }
    Err(ctx.throw_type_error("`url` must be a string or a URL object"))
}

/// Build a `URL` object from an already-parsed `url::Url`. Used by
/// `path.pathToFileURL`, which returns a URL per Node's convention.
pub fn new_url(ctx: &mut ScopedContext, parsed: Url) -> Result<JSValue, i32> {
    JSURL::new_instance(
        ctx,
        JSValue::UNDEFINED,
        UrlPayload {
            shared: Rc::new(RefCell::new(parsed)),
            search_params: RefCell::new(WriteBarrier::new(None)),
        },
    )
    .map(JSValue::from)
}
