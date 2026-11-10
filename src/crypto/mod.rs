// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WHATWG Web Crypto API — `crypto` global and its classes.
//!
//! Implements the WebCrypto subset aike needs (see memo/api-todo.md P0):
//! `getRandomValues`, `randomUUID`, `subtle.digest` (SHA-1/256/384/512),
//! `subtle.sign`/`verify` (HMAC), `subtle.encrypt`/`decrypt` (AES-GCM),
//! `subtle.importKey`/`exportKey`, plus the aike extension `sha256Hex`.
//!
//! Per the WebCrypto spec, `crypto` is a global object and the interfaces
//! `Crypto`, `SubtleCrypto` and `CryptoKey` are exposed on the global as
//! non-constructable constructors.

pub(crate) mod subtle;

pub use subtle::JSCryptoSubtle;

use rand::TryRngCore;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zuqe::{
    Array, CallContext, ClassCtorDef, Exception, FieldDef, JSResult, JSValue, Object,
    ScopedContext,
    builtins::typed_array::{DataView, TypedArray},
    def_native_object,
    gc_lite::GcTrace,
};

use super::dom::make_dom_exception;

// ===========================================================================
// Shared helpers
// ===========================================================================

/// Throw a DOMException synchronously (WebCrypto surfaces most errors as
/// DOMExceptions with a specific `name`). `make_dom_exception` builds the
/// value; `Exception::Error` + `ctx.throw` turns it into the pending exception.
pub(crate) fn throw_dom_exception(ctx: &mut ScopedContext, name: &str, message: &str) -> i32 {
    let exc = match make_dom_exception(ctx, name, message) {
        Ok(v) => v,
        Err(code) => return code,
    };
    ctx.throw(Exception::Error(exc));
    -1
}

/// Copy the bytes of a WHATWG `BufferSource` (ArrayBuffer or ArrayBufferView,
/// including DataView). Mirrors the WebCrypto `copyBufferSource` abstract op.
/// Throws `TypeError` on a non-BufferSource value or a detached buffer.
pub fn get_buffer_source_bytes(ctx: &mut ScopedContext, val: &JSValue) -> Result<Vec<u8>, i32> {
    let mut out = Vec::new();
    if let Some(mut ab) = val.as_object_ArrayBuffer() {
        ab.ensure_attached(ctx)?;
        ab.payload_mut().with_bytes_mut(|b| out = b.to_vec());
        return Ok(out);
    }
    if let Ok(ta) = TypedArray::try_from(*val) {
        ta.ensure_attached(ctx)?;
        ta.with_bytes(|b| out = b.to_vec());
        return Ok(out);
    }
    if let Ok(dv) = DataView::try_from(*val) {
        dv.ensure_attached(ctx)?;
        dv.payload().with_bytes(|b| out = b.to_vec());
        return Ok(out);
    }
    Err(ctx.throw_type_error("expected a BufferSource (ArrayBuffer or ArrayBufferView)"))
}

/// Encode bytes as lowercase hexadecimal.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Resolve a WebCrypto `AlgorithmIdentifier` (a string or a dictionary with a
/// `name` member) to its normalized (ASCII-uppercased) algorithm name.
pub(crate) fn algorithm_name(ctx: &mut ScopedContext, alg: &JSValue) -> Result<String, i32> {
    let name = if let Some(s) = alg.as_string(false) {
        s.content().encode_utf8(false).to_string()
    } else if let Some(obj) = alg.as_object() {
        let n = obj.get_property_str(ctx, "name")?;
        if n.is_undefined() {
            return Err(ctx.throw_type_error("algorithm name is required"));
        }
        n.to_string(ctx)?.content().encode_utf8(false).to_string()
    } else {
        return Err(
            ctx.throw_type_error("algorithm must be a string or an object with a name member")
        );
    };
    Ok(name.to_ascii_uppercase())
}

/// All `KeyUsage` values recognized by WebCrypto.
const KEY_USAGES: &[&str] = &[
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "deriveKey",
    "deriveBits",
    "wrapKey",
    "unwrapKey",
];

/// Validate the `keyUsages` sequence: non-empty and a subset of `allowed`
/// (the usages the target algorithm recognizes). Violations are `SyntaxError`.
pub(crate) fn validate_key_usages(
    ctx: &mut ScopedContext,
    usages: &[String],
    allowed: &[&str],
) -> Result<(), i32> {
    if usages.is_empty() {
        return Err(throw_dom_exception(
            ctx,
            "SyntaxError",
            "keyUsages must not be empty",
        ));
    }
    for u in usages {
        if !KEY_USAGES.contains(&u.as_str()) || !allowed.contains(&u.as_str()) {
            return Err(throw_dom_exception(
                ctx,
                "SyntaxError",
                &format!("unsupported key usage '{u}' for this algorithm"),
            ));
        }
    }
    Ok(())
}

/// Extract the `keyUsages` argument as a list of usage strings.
pub(crate) fn get_key_usages(ctx: &mut ScopedContext, val: &JSValue) -> Result<Vec<String>, i32> {
    if val.is_undefined_or_null() {
        return Err(ctx.throw_type_error("keyUsages must be a sequence of KeyUsage"));
    }
    let arr = Array::try_from(*val)
        .map_err(|_| ctx.throw_type_error("keyUsages must be a sequence of KeyUsage"))?;
    let mut out = Vec::new();
    for v in arr.payload().values() {
        out.push(v.to_string(ctx)?.content().encode_utf8(false).to_string());
    }
    Ok(out)
}

/// Create a JS string value.
pub(crate) fn make_string(ctx: &mut ScopedContext, s: &str) -> JSResult {
    ctx.create_string_from_utf8(s.as_bytes().to_vec())
        .map(JSValue::make_string)
}

// ===========================================================================
// CryptoKey
// ===========================================================================

/// Native payload of a `CryptoKey`: raw key material plus WebCrypto metadata.
#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct CryptoKeyPayload {
    /// "secret" | "public" | "private"
    pub(crate) key_type: String,
    /// Whether the key material may be exported.
    pub(crate) extractable: bool,
    /// Raw key material bytes.
    pub(crate) raw: Vec<u8>,
    /// Algorithm name: "HMAC" | "AES-GCM".
    pub(crate) alg_name: String,
    /// Hash name for HMAC keys (SHA-1/256/384/512).
    pub(crate) hash_name: Option<String>,
    /// Key usages granted at import time.
    pub(crate) usages: Vec<String>,
}

/// Per WebCrypto, `CryptoKey` cannot be constructed from JS.
fn js_key_constructor(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    Err(ctx.throw_type_error("Illegal constructor: 'CryptoKey' is not constructable"))
}

fn js_key_type_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSCryptoKey::payload_of(&this)
        .ok_or_else(|| ctx.throw_internal_error("not a CryptoKey instance"))?;
    make_string(ctx, &p.key_type)
}

fn js_key_extractable_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSCryptoKey::payload_of(&this)
        .ok_or_else(|| ctx.throw_internal_error("not a CryptoKey instance"))?;
    Ok(JSValue::from(p.extractable))
}

/// The `algorithm` member is a fresh object per access, e.g.
/// `{ name: "HMAC", hash: "SHA-256", length: 256 }` or
/// `{ name: "AES-GCM", length: 256 }`.
fn js_key_algorithm_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSCryptoKey::payload_of(&this)
        .ok_or_else(|| ctx.throw_internal_error("not a CryptoKey instance"))?;
    let mut obj = ctx.create_base_object()?;
    let name = make_string(ctx, &p.alg_name)?;
    obj.set_property_str(ctx, "name", name)?;
    if let Some(hash) = &p.hash_name {
        let hash_val = make_string(ctx, hash)?;
        obj.set_property_str(ctx, "hash", hash_val)?;
    }
    obj.set_property_str(ctx, "length", JSValue::from((p.raw.len() * 8) as f64))?;
    Ok(obj.into())
}

fn js_key_usages_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSCryptoKey::payload_of(&this)
        .ok_or_else(|| ctx.throw_internal_error("not a CryptoKey instance"))?;
    let mut vals = Vec::with_capacity(p.usages.len());
    for u in &p.usages {
        vals.push(make_string(ctx, u)?);
    }
    let arr = Array::from_values(ctx, vals)?;
    Ok(arr.into())
}

const CLASS_KEY_PROTO: &[FieldDef] = &[
    FieldDef::GETSET_ENUM("type", Some(js_key_type_getter), None, 0),
    FieldDef::GETSET_ENUM("extractable", Some(js_key_extractable_getter), None, 0),
    FieldDef::GETSET_ENUM("algorithm", Some(js_key_algorithm_getter), None, 0),
    FieldDef::GETSET_ENUM("usages", Some(js_key_usages_getter), None, 0),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "CryptoKey",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "CryptoKey",
    JSCryptoKey,
    CryptoKeyPayload,
    CLASS_KEY_PROTO,
    Some(ClassCtorDef::new(js_key_constructor, 0, true).expose_to_global())
);

/// Build a `CryptoKey` with the given raw material and metadata.
pub(crate) fn make_key(
    ctx: &mut ScopedContext,
    raw: Vec<u8>,
    alg_name: String,
    hash_name: Option<String>,
    extractable: bool,
    usages: Vec<String>,
) -> Result<JSValue, i32> {
    let key = JSCryptoKey::new_instance(
        ctx,
        JSValue::UNDEFINED,
        CryptoKeyPayload {
            key_type: "secret".to_string(),
            extractable,
            raw,
            alg_name,
            hash_name,
            usages,
        },
    )?;
    Ok(key.into())
}

// ===========================================================================
// Crypto (the global `crypto` object)
// ===========================================================================

/// Native payload of a `Crypto` instance: the single shared `SubtleCrypto`.
#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct CryptoPayload {
    /// GC-traced; the subtle instance outlives via this reference.
    pub(crate) subtle: Object,
}

/// Per WebCrypto, `Crypto` cannot be constructed from JS; only the global
/// `crypto` instance exists.
fn js_crypto_constructor(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    Err(ctx.throw_type_error("Illegal constructor: 'Crypto' is not constructable"))
}

fn js_crypto_subtle_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSCrypto::payload_of(&this)
        .ok_or_else(|| ctx.throw_internal_error("not a Crypto instance"))?;
    Ok(p.subtle.into())
}

/// `getRandomValues(array)`: fill an integer-typed array with cryptographically
/// secure random bytes and return it. Throws `TypeError` for float arrays /
/// DataView and `QuotaExceededError` above 65536 bytes (per spec).
fn js_crypto_get_random_values(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let arr_val = cc.arg(0);
    let mut ta = TypedArray::try_from(arr_val)
        .map_err(|_| ctx.throw_type_error("getRandomValues expects an integer typed array"))?;
    // Spec: only the integer typed array types are accepted.
    let cid = ta.class_id();
    if cid == zuqe::JS_CLASS_FLOAT16_ARRAY
        || cid == zuqe::JS_CLASS_FLOAT32_ARRAY
        || cid == zuqe::JS_CLASS_FLOAT64_ARRAY
    {
        return Err(ctx.throw_type_error("getRandomValues expects an integer typed array"));
    }
    let byte_len = ta.byte_length();
    if byte_len > 65536 {
        return Err(throw_dom_exception(
            ctx,
            "QuotaExceededError",
            "getRandomValues() request exceeds 65536 bytes",
        ));
    }
    if ta
        .with_bytes_mut(|bytes| rand::rngs::OsRng.try_fill_bytes(bytes))
        .is_err()
    {
        return Err(ctx.throw_internal_error("failed to obtain random bytes"));
    }
    Ok(arr_val)
}

/// `randomUUID()`: a version 4 UUID string (cryptographically random).
fn js_crypto_random_uuid(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    let u = Uuid::new_v4().hyphenated().to_string();
    make_string(ctx, &u)
}

/// `sha256Hex(data)`: aike extension — SHA-256 of `data` as a lowercase hex
/// string. Accepts a UTF-8 string or a BufferSource (convenience over
/// `subtle.digest`, which returns an ArrayBuffer needing manual hex conversion).
fn js_crypto_sha256_hex(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let arg = cc.arg(0);
    let bytes = if let Some(s) = arg.as_string(false) {
        s.content().encode_utf8(false).as_bytes().to_vec()
    } else {
        get_buffer_source_bytes(ctx, &arg)?
    };
    let digest = Sha256::digest(&bytes);
    make_string(ctx, &hex_encode(&digest))
}

const CLASS_CRYPTO_PROTO: &[FieldDef] = &[
    FieldDef::GETSET_ENUM("subtle", Some(js_crypto_subtle_getter), None, 0),
    FieldDef::FUNC_ENUM("getRandomValues", 1, js_crypto_get_random_values, 0),
    FieldDef::FUNC_ENUM("randomUUID", 0, js_crypto_random_uuid, 0),
    FieldDef::FUNC_ENUM("sha256Hex", 1, js_crypto_sha256_hex, 0),
    FieldDef::STR("[Symbol.toStringTag]", "Crypto", zuqe::JS_PROP_CONFIGURABLE),
];

def_native_object!(
    "Crypto",
    JSCrypto,
    CryptoPayload,
    CLASS_CRYPTO_PROTO,
    Some(ClassCtorDef::new(js_crypto_constructor, 0, true).expose_to_global())
);

// ===========================================================================
// Installation
// ===========================================================================

/// Install the `crypto` global (a `Crypto` instance carrying its `subtle`).
pub fn init_crypto(ctx: &mut ScopedContext, mut global: Object) -> Result<(), i32> {
    let subtle = subtle::JSCryptoSubtle::new_instance(ctx, JSValue::UNDEFINED)?;
    let crypto = JSCrypto::new_instance(
        ctx,
        JSValue::UNDEFINED,
        CryptoPayload {
            subtle: subtle.into(),
        },
    )?;
    global.define_property_value_str(ctx, "crypto", crypto.into(), zuqe::JS_PROP_C_W_E)?;
    Ok(())
}
