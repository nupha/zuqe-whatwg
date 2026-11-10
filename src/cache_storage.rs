// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WPT `fetch/api/abort/cache.https.any.js` ("Signals are not stored in the
//! cache API") requires the [Cache Storage API][1]. This is a *separate*
//! facility from the HTTP response cache in `cache.rs` (RFC 7234 / Fetch
//! § HTTP-cache), so it is implemented independently here as two native
//! classes: `CacheStorage` (the global `caches` object) and `Cache`.
//!
//! [1]: https://w3c.github.io/Storage/#:~:text=The%20Cache%20interface

use std::{cell::RefCell, collections::HashMap, rc::Rc};

use zuqe::{
    Array, CallContext, ClassCtorDef, FieldDef, JSResult, JSValue, ScopedContext,
    builtins::promise::Promise,
    builtins::typed_array::TypedArray,
    def_native_object,
};

use crate::fetch::{request::JSRequest, response::JSResponse};

/// A stored request/response pair keyed by `method + " " + url`.
struct CacheEntry {
    request: RequestSnapshot,
    response: ResponseSnapshot,
}

#[derive(Clone)]
struct RequestSnapshot {
    method: String,
    url: String,
}

#[derive(Clone)]
struct ResponseSnapshot {
    status: u16,
    status_text: String,
    // `Vec<u8>` to keep the payload free of GC handles.
    body: Vec<u8>,
}

#[derive(Default)]
pub(crate) struct CacheData {
    entries: HashMap<String, CacheEntry>,
}

/// Shared, in-memory namespace of named caches. Process-local (single-threaded
/// engine), so an `Rc<RefCell<..>>` is sufficient. Both `CacheStorage` and the
/// `Cache` instances it vends reference the same backing store.
// No JS GC nodes in this payload.
pub(crate) struct CacheStoragePayload {
    pub(crate) stores: Rc<RefCell<HashMap<String, CacheData>>>,
}

zuqe::gc_lite::unsafe_empty_gc_trace!(CacheStoragePayload);

/// A single named cache. Holds only its name and a shared handle to the store.
// No JS GC nodes in this payload.
pub(crate) struct CachePayload {
    name: String,
    stores: Rc<RefCell<HashMap<String, CacheData>>>,
}

zuqe::gc_lite::unsafe_empty_gc_trace!(CachePayload);

fn cache_key(method: &str, url: &str) -> String {
    format!("{} {}", method.to_uppercase(), url)
}

fn snapshot_request(ctx: &mut ScopedContext, val: &JSValue) -> Result<RequestSnapshot, i32> {
    let p = JSRequest::payload_of(val)
        .ok_or_else(|| ctx.throw_type_error("argument is not a Request"))?;
    Ok(RequestSnapshot {
        method: p.method.to_string(),
        url: p.url.to_string(),
    })
}

/// Resolve a `RequestInfo` — a `Request` or a `USVString` URL, per the Cache
/// Storage spec — into a snapshot. A bare string means a `GET` for that URL.
fn snapshot_request_info(ctx: &mut ScopedContext, val: &JSValue) -> Result<RequestSnapshot, i32> {
    if let Some(s) = val.as_string(false) {
        return Ok(RequestSnapshot {
            method: "GET".to_string(),
            url: s.content().encode_utf8(false).to_string(),
        });
    }
    snapshot_request(ctx, val)
}

fn snapshot_response(ctx: &mut ScopedContext, val: &JSValue) -> Result<ResponseSnapshot, i32> {
    let p = JSResponse::payload_of(val)
        .ok_or_else(|| ctx.throw_type_error("argument is not a Response"))?;
    let body = p.synthetic_body.clone().unwrap_or_default();
    Ok(ResponseSnapshot {
        status: p.status,
        status_text: p.status_text.to_string(),
        body,
    })
}

fn rebuild_request(ctx: &mut ScopedContext, snap: &RequestSnapshot) -> Result<JSValue, i32> {
    let url = ctx
        .create_string_from_utf8(snap.url.clone().into_bytes())
        .map(JSValue::make_string)?;
    let method = ctx
        .create_string_from_utf8(snap.method.clone().into_bytes())
        .map(JSValue::make_string)?;
    let mut opts = ctx.create_base_object()?;
    opts.define_property_value_str(ctx, "method", method, 0)?;
    let global = ctx.global_obj();
    let req_ctor = global.get_property_str(ctx, "Request")?;
    let req_ctor = req_ctor
        .as_object()
        .ok_or_else(|| ctx.throw_type_error("Request is not a constructor"))?;
    req_ctor.call_ctor(ctx, &[url, opts.into()])
}

fn rebuild_response(ctx: &mut ScopedContext, snap: &ResponseSnapshot) -> Result<JSValue, i32> {
    let bytes = TypedArray::create_from_vec_u8(ctx, snap.body.clone())?;
    let status = ctx
        .create_string_from_utf8(snap.status.to_string().into_bytes())
        .map(JSValue::make_string)?;
    let status_text = ctx
        .create_string_from_utf8(snap.status_text.clone().into_bytes())
        .map(JSValue::make_string)?;
    let mut opts = ctx.create_base_object()?;
    opts.define_property_value_str(ctx, "status", status, 0)?;
    opts.define_property_value_str(ctx, "statusText", status_text, 0)?;
    let global = ctx.global_obj();
    let res_ctor = global.get_property_str(ctx, "Response")?;
    let res_ctor = res_ctor
        .as_object()
        .ok_or_else(|| ctx.throw_type_error("Response is not a constructor"))?;
    res_ctor.call_ctor(ctx, &[bytes.into(), opts.into()])
}

fn js_cache_storage_ctor(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    let payload = CacheStoragePayload {
        stores: Rc::new(RefCell::new(HashMap::new())),
    };
    JSCacheStorage::new_instance(ctx, JSValue::UNDEFINED, payload).map(JSValue::from)
}

fn js_cache_storage_open(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSCacheStorage::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("not a CacheStorage instance"))?;
    let name = cc
        .arg(0)
        .to_string(ctx)?
        .content()
        .encode_utf8(false)
        .to_string();
    let stores = p.stores.clone();
    {
        let mut s = stores.borrow_mut();
        s.entry(name.clone()).or_default();
    }
    let payload = CachePayload { name, stores };
    JSCache::new_instance(ctx, JSValue::UNDEFINED, payload).map(JSValue::from)
}

fn js_cache_storage_has(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSCacheStorage::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("not a CacheStorage instance"))?;
    let name = cc
        .arg(0)
        .to_string(ctx)?
        .content()
        .encode_utf8(false)
        .to_string();
    let has = p.stores.borrow().contains_key(&name);
    Promise::from_resolve_value(ctx, JSValue::from(has)).map(JSValue::from)
}

fn js_cache_storage_delete(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSCacheStorage::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("not a CacheStorage instance"))?;
    let name = cc
        .arg(0)
        .to_string(ctx)?
        .content()
        .encode_utf8(false)
        .to_string();
    let removed = p.stores.borrow_mut().remove(&name).is_some();
    Promise::from_resolve_value(ctx, JSValue::from(removed)).map(JSValue::from)
}

fn js_cache_storage_keys(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let stores = {
        let this = cc.this();
        let p = JSCacheStorage::payload_of(&this)
            .ok_or_else(|| ctx.throw_type_error("not a CacheStorage instance"))?;
        p.stores.clone()
    };

    let mut keys: Vec<JSValue> = Vec::new();
    for k in stores.borrow().keys() {
        let s = ctx
            .create_string_from_utf8(k.clone().into_bytes())
            .map(JSValue::make_string)
            .unwrap_or(JSValue::UNDEFINED);
        keys.push(s);
    }

    let arr = Array::from_values(ctx, keys)?;
    Promise::from_resolve_value(ctx, arr.into()).map(JSValue::from)
}

fn get_cache_stores(
    ctx: &mut ScopedContext,
    cc: &CallContext,
) -> Result<Rc<RefCell<HashMap<String, CacheData>>>, i32> {
    let this = cc.this();
    let p =
        JSCache::payload_of(&this).ok_or_else(|| ctx.throw_type_error("not a Cache instance"))?;
    Ok(p.stores.clone())
}

fn get_cache_name(ctx: &mut ScopedContext, cc: &CallContext) -> Result<String, i32> {
    let this = cc.this();
    let p =
        JSCache::payload_of(&this).ok_or_else(|| ctx.throw_type_error("not a Cache instance"))?;
    Ok(p.name.clone())
}

fn js_cache_put(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let stores = get_cache_stores(ctx, &cc)?;
    let name = get_cache_name(ctx, &cc)?;
    let req = cc.arg(0);
    let res = cc.arg(1);
    let req_snap = match snapshot_request_info(ctx, &req) {
        Ok(s) => s,
        Err(_) => return Err(-1),
    };
    let res_snap = match snapshot_response(ctx, &res) {
        Ok(s) => s,
        Err(_) => return Err(-1),
    };
    let key = cache_key(&req_snap.method, &req_snap.url);
    {
        let mut s = stores.borrow_mut();
        if let Some(cache) = s.get_mut(&name) {
            cache.entries.insert(
                key,
                CacheEntry {
                    request: req_snap,
                    response: res_snap,
                },
            );
        }
    }
    Promise::from_resolve_value(ctx, JSValue::UNDEFINED).map(JSValue::from)
}

fn js_cache_match(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let stores = get_cache_stores(ctx, &cc)?;
    let name = get_cache_name(ctx, &cc)?;
    let req = cc.arg(0);
    let req_snap = match snapshot_request_info(ctx, &req) {
        Ok(s) => s,
        Err(_) => return Err(-1),
    };
    let key = cache_key(&req_snap.method, &req_snap.url);
    let found = {
        let s = stores.borrow();
        s.get(&name)
            .and_then(|c| c.entries.get(&key))
            .map(|e| e.response.clone())
    };
    match found {
        Some(snap) => {
            let resp = rebuild_response(ctx, &snap)?;
            Promise::from_resolve_value(ctx, resp).map(JSValue::from)
        }
        None => Promise::from_resolve_value(ctx, JSValue::UNDEFINED).map(JSValue::from),
    }
}

fn js_cache_match_all(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let stores = get_cache_stores(ctx, &cc)?;
    let name = get_cache_name(ctx, &cc)?;
    let req_val = cc.arg(0);
    let wanted_key = if req_val.is_undefined() {
        None
    } else {
        snapshot_request_info(ctx, &req_val)
            .ok()
            .map(|s| cache_key(&s.method, &s.url))
    };
    let snaps: Vec<ResponseSnapshot> = {
        let s = stores.borrow();
        match s.get(&name) {
            Some(c) => c
                .entries
                .values()
                .filter(|e| match &wanted_key {
                    Some(k) => &cache_key(&e.request.method, &e.request.url) == k,
                    None => true,
                })
                .map(|e| e.response.clone())
                .collect(),
            None => Vec::new(),
        }
    };
    let arr_elems: Vec<JSValue> = snaps
        .iter()
        .map(|snap| rebuild_response(ctx, snap))
        .collect::<Result<_, _>>()?;
    let arr = Array::from_values(ctx, arr_elems)?;
    Promise::from_resolve_value(ctx, arr.into()).map(JSValue::from)
}

fn js_cache_delete(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let stores = get_cache_stores(ctx, &cc)?;
    let name = get_cache_name(ctx, &cc)?;
    let req = cc.arg(0);
    let req_snap = match snapshot_request_info(ctx, &req) {
        Ok(s) => s,
        Err(_) => return Err(-1),
    };
    let key = cache_key(&req_snap.method, &req_snap.url);
    let removed = {
        let mut s = stores.borrow_mut();
        s.get_mut(&name)
            .map(|c| c.entries.remove(&key).is_some())
            .unwrap_or(false)
    };
    Promise::from_resolve_value(ctx, JSValue::from(removed)).map(JSValue::from)
}

fn js_cache_keys(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let stores = get_cache_stores(ctx, &cc)?;
    let name = get_cache_name(ctx, &cc)?;
    let req_val = cc.arg(0);
    let wanted_key = if req_val.is_undefined() {
        None
    } else {
        snapshot_request_info(ctx, &req_val)
            .ok()
            .map(|s| cache_key(&s.method, &s.url))
    };
    let snaps: Vec<RequestSnapshot> = {
        let s = stores.borrow();
        match s.get(&name) {
            Some(c) => c
                .entries
                .values()
                .filter(|e| match &wanted_key {
                    Some(k) => &cache_key(&e.request.method, &e.request.url) == k,
                    None => true,
                })
                .map(|e| e.request.clone())
                .collect(),
            None => Vec::new(),
        }
    };
    let arr_elems: Vec<JSValue> = snaps
        .iter()
        .map(|snap| rebuild_request(ctx, snap))
        .collect::<Result<_, _>>()?;
    let arr = Array::from_values(ctx, arr_elems)?;
    Promise::from_resolve_value(ctx, arr.into()).map(JSValue::from)
}

const CACHE_STORAGE_PROTO: &[FieldDef] = &[
    FieldDef::FUNC_ENUM("open", 1, js_cache_storage_open, 0),
    FieldDef::FUNC_ENUM("has", 1, js_cache_storage_has, 0),
    FieldDef::FUNC_ENUM("delete", 1, js_cache_storage_delete, 0),
    FieldDef::FUNC_ENUM("keys", 0, js_cache_storage_keys, 0),
    // WebIDL class string (`Object.prototype.toString` -> "[object CacheStorage]").
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "CacheStorage",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

const CACHE_PROTO: &[FieldDef] = &[
    FieldDef::FUNC_ENUM("put", 2, js_cache_put, 0),
    FieldDef::FUNC_ENUM("match", 1, js_cache_match, 0),
    FieldDef::FUNC_ENUM("matchAll", 1, js_cache_match_all, 0),
    FieldDef::FUNC_ENUM("delete", 1, js_cache_delete, 0),
    FieldDef::FUNC_ENUM("keys", 1, js_cache_keys, 0),
    // WebIDL class string (`Object.prototype.toString` -> "[object Cache]").
    FieldDef::STR("[Symbol.toStringTag]", "Cache", zuqe::JS_PROP_CONFIGURABLE),
];

def_native_object!(
    "CacheStorage",
    JSCacheStorage,
    CacheStoragePayload,
    CACHE_STORAGE_PROTO,
    Some(ClassCtorDef::new(js_cache_storage_ctor, 0, false))
);

def_native_object!("Cache", JSCache, CachePayload, CACHE_PROTO, None);
