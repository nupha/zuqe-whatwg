// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WHATWG Web Crypto API — `SubtleCrypto` implementation.
//!
//! Covers `digest` (SHA-1/256/384/512), `sign`/`verify` (HMAC),
//! `encrypt`/`decrypt` (AES-GCM), and `importKey`/`exportKey` (raw + JWK).
//!
//! WebCrypto methods always return a `Promise`: any error (validation or
//! operation) is surfaced as a rejection, never a synchronous throw. The
//! computation itself runs inline on the JS thread; the promise resolves on
//! the following microtask.

use std::ptr;

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;
use zuqe::{
    Array, CallContext, ClassCtorDef, Exception, FieldDef, JSResult, JSValue, Object,
    ScopedContext, builtins::array_buffer::ArrayBuffer, builtins::promise::Promise,
    def_native_object,
};

use super::{
    CryptoKeyPayload, JSCryptoKey, algorithm_name, get_buffer_source_bytes, get_key_usages,
    make_key, throw_dom_exception, validate_key_usages,
};

// ---------------------------------------------------------------------------
// Promise plumbing: WebCrypto rejects instead of throwing.
// ---------------------------------------------------------------------------

/// Convert an in-flight exception into a rejected promise (WebCrypto's async
/// error surface). Falls back to propagating the raw error code.
fn reject_from_exception(ctx: &mut ScopedContext, e: i32) -> JSResult {
    let Exception::Error(reason) = ctx.take_exception() else {
        return Err(e);
    };
    let (mut promise, _funcs) = Promise::create(ctx)?;
    promise.reject(ctx, reason);
    Ok(promise.into())
}

/// Wrap an operation so synchronous errors become promise rejections.
macro_rules! async_op {
    ($impl:ident, $js:ident) => {
        fn $js(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
            match $impl(ctx, cc) {
                Ok(v) => Ok(v),
                Err(e) => reject_from_exception(ctx, e),
            }
        }
    };
}

// ---------------------------------------------------------------------------
// digests
// ---------------------------------------------------------------------------

/// Compute the digest of `data` for a normalized algorithm name.
fn digest_bytes(name: &str, data: &[u8]) -> Option<Vec<u8>> {
    match name {
        "SHA-1" => Some(Sha1::digest(data).to_vec()),
        "SHA-256" => Some(Sha256::digest(data).to_vec()),
        "SHA-384" => Some(Sha384::digest(data).to_vec()),
        "SHA-512" => Some(Sha512::digest(data).to_vec()),
        _ => None,
    }
}

fn subtle_digest(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() < 2 {
        return Err(ctx.throw_type_error("digest() requires 2 arguments"));
    }
    let name = algorithm_name(ctx, &cc.arg(0))?;
    let data = get_buffer_source_bytes(ctx, &cc.arg(1))?;
    let bytes = digest_bytes(&name, &data).ok_or_else(|| {
        throw_dom_exception(
            ctx,
            "NotSupportedError",
            &format!("Unrecognized algorithm '{name}'"),
        )
    })?;
    let ab = ArrayBuffer::from_bytes(
        ctx,
        JSValue::UNDEFINED,
        bytes.into_boxed_slice(),
        ptr::null_mut(),
    )?;
    Promise::from_resolve_value(ctx, ab.into()).map(JSValue::from)
}

async_op!(subtle_digest, js_subtle_digest);

// ---------------------------------------------------------------------------
// HMAC sign / verify
// ---------------------------------------------------------------------------

/// The sign/verify algorithm may carry a `hash` member; when present it must
/// match the key's hash (spec), otherwise fall back to the key's hash.
fn resolve_hmac_hash(
    ctx: &mut ScopedContext,
    alg: &JSValue,
    key: &CryptoKeyPayload,
) -> Result<String, i32> {
    let key_hash = key.hash_name.clone().unwrap_or_default();
    if let Some(obj) = alg.as_object() {
        let h = obj.get_property_str(ctx, "hash")?;
        if !h.is_undefined() {
            let name = algorithm_name(ctx, &h)?;
            if !matches!(name.as_str(), "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512") {
                return Err(throw_dom_exception(
                    ctx,
                    "NotSupportedError",
                    &format!("Unsupported hash '{name}'"),
                ));
            }
            if name != key_hash {
                return Err(throw_dom_exception(
                    ctx,
                    "OperationError",
                    "the algorithm hash does not match the key's hash",
                ));
            }
            return Ok(name);
        }
    }
    if key_hash.is_empty() {
        return Err(throw_dom_exception(
            ctx,
            "OperationError",
            "HMAC key has no hash",
        ));
    }
    Ok(key_hash)
}

/// HMAC over `data` with the given key and hash; `None` on invalid key/hash.
fn hmac_mac(key: &[u8], hash: &str, data: &[u8]) -> Option<Vec<u8>> {
    fn mac<M: KeyInit + Mac>(mac_key: &[u8], mac_data: &[u8]) -> Option<Vec<u8>> {
        let mut m = M::new_from_slice(mac_key).ok()?;
        m.update(mac_data);
        Some(m.finalize().into_bytes().to_vec())
    }
    match hash {
        "SHA-1" => mac::<Hmac<Sha1>>(key, data),
        "SHA-256" => mac::<Hmac<Sha256>>(key, data),
        "SHA-384" => mac::<Hmac<Sha384>>(key, data),
        "SHA-512" => mac::<Hmac<Sha512>>(key, data),
        _ => None,
    }
}

/// Extract the HMAC key (type/algorithm/usages checked) from a CryptoKey.
fn get_hmac_key(
    ctx: &mut ScopedContext,
    key_val: &JSValue,
    usage: &str,
) -> Result<CryptoKeyPayload, i32> {
    let key = JSCryptoKey::payload_of(key_val)
        .ok_or_else(|| ctx.throw_type_error("key must be a CryptoKey"))?;
    if key.alg_name != "HMAC" {
        return Err(throw_dom_exception(
            ctx,
            "InvalidAccessError",
            "key is not an HMAC key",
        ));
    }
    if !key.usages.iter().any(|u| u == usage) {
        return Err(throw_dom_exception(
            ctx,
            "InvalidAccessError",
            &format!("key does not have the '{usage}' usage"),
        ));
    }
    // Clone the payload so the JS-thread borrow is released before creating
    // the resolved promise value (the payload borrows the GC heap).
    Ok(CryptoKeyPayload {
        key_type: key.key_type.clone(),
        extractable: key.extractable,
        raw: key.raw.clone(),
        alg_name: key.alg_name.clone(),
        hash_name: key.hash_name.clone(),
        usages: key.usages.clone(),
    })
}

fn subtle_sign(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() < 3 {
        return Err(ctx.throw_type_error("sign() requires 3 arguments"));
    }
    let alg_val = cc.arg(0);
    let data = get_buffer_source_bytes(ctx, &cc.arg(2))?;
    let name = algorithm_name(ctx, &alg_val)?;
    if name != "HMAC" {
        return Err(throw_dom_exception(
            ctx,
            "NotSupportedError",
            &format!("Unrecognized algorithm '{name}'"),
        ));
    }
    let key = get_hmac_key(ctx, &cc.arg(1), "sign")?;
    let hash = resolve_hmac_hash(ctx, &alg_val, &key)?;
    let mac = hmac_mac(&key.raw, &hash, &data)
        .ok_or_else(|| throw_dom_exception(ctx, "OperationError", "invalid HMAC key material"))?;
    let ab = ArrayBuffer::from_bytes(
        ctx,
        JSValue::UNDEFINED,
        mac.into_boxed_slice(),
        ptr::null_mut(),
    )?;
    Promise::from_resolve_value(ctx, ab.into()).map(JSValue::from)
}

async_op!(subtle_sign, js_subtle_sign);

fn subtle_verify(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() < 4 {
        return Err(ctx.throw_type_error("verify() requires 4 arguments"));
    }
    let alg_val = cc.arg(0);
    let signature = get_buffer_source_bytes(ctx, &cc.arg(2))?;
    let data = get_buffer_source_bytes(ctx, &cc.arg(3))?;
    let name = algorithm_name(ctx, &alg_val)?;
    if name != "HMAC" {
        return Err(throw_dom_exception(
            ctx,
            "NotSupportedError",
            &format!("Unrecognized algorithm '{name}'"),
        ));
    }
    let key = get_hmac_key(ctx, &cc.arg(1), "verify")?;
    let hash = resolve_hmac_hash(ctx, &alg_val, &key)?;
    let mac = hmac_mac(&key.raw, &hash, &data)
        .ok_or_else(|| throw_dom_exception(ctx, "OperationError", "invalid HMAC key material"))?;
    // Constant-time comparison; unequal lengths simply compare as false.
    let ok: bool = mac.ct_eq(&signature).into();
    Promise::from_resolve_value(ctx, JSValue::from(ok)).map(JSValue::from)
}

async_op!(subtle_verify, js_subtle_verify);

// ---------------------------------------------------------------------------
// AES-GCM encrypt / decrypt
// ---------------------------------------------------------------------------

struct GcmParams {
    iv: Vec<u8>,
    aad: Vec<u8>,
    tag_len: usize,
}

/// Parse the AES-GCM `algorithm` dictionary. The `iv` member is required;
/// `additionalData` is optional; `tagLength` defaults to 128 and must be one
/// of the spec's valid values.
fn parse_gcm_params(ctx: &mut ScopedContext, alg: &JSValue) -> Result<GcmParams, i32> {
    let obj = alg
        .as_object()
        .ok_or_else(|| ctx.throw_type_error("AES-GCM algorithm must be an object"))?;
    let iv_val = obj.get_property_str(ctx, "iv")?;
    if iv_val.is_undefined() {
        return Err(ctx.throw_type_error("AES-GCM algorithm requires an iv member"));
    }
    let iv = get_buffer_source_bytes(ctx, &iv_val)?;
    let aad_val = obj.get_property_str(ctx, "additionalData")?;
    let aad = if aad_val.is_undefined() {
        Vec::new()
    } else {
        get_buffer_source_bytes(ctx, &aad_val)?
    };
    let tag_val = obj.get_property_str(ctx, "tagLength")?;
    let tag_len = if tag_val.is_undefined() {
        128
    } else {
        let n = tag_val.to_number(ctx)?.to_f64();
        if !n.is_finite() || n <= 0.0 || n != n.floor() {
            return Err(throw_dom_exception(
                ctx,
                "OperationError",
                "tagLength must be a positive integer",
            ));
        }
        n as usize
    };
    if !matches!(tag_len, 32 | 64 | 96 | 104 | 112 | 120 | 128) {
        return Err(throw_dom_exception(
            ctx,
            "OperationError",
            &format!("invalid tagLength '{tag_len}'"),
        ));
    }
    Ok(GcmParams { iv, aad, tag_len })
}

/// Extract the AES-GCM key (type/algorithm/usages checked) from a CryptoKey.
fn get_aes_key(
    ctx: &mut ScopedContext,
    key_val: &JSValue,
    usage: &str,
) -> Result<CryptoKeyPayload, i32> {
    let key = JSCryptoKey::payload_of(key_val)
        .ok_or_else(|| ctx.throw_type_error("key must be a CryptoKey"))?;
    if key.alg_name != "AES-GCM" {
        return Err(throw_dom_exception(
            ctx,
            "InvalidAccessError",
            "key is not an AES-GCM key",
        ));
    }
    if !key.usages.iter().any(|u| u == usage) {
        return Err(throw_dom_exception(
            ctx,
            "InvalidAccessError",
            &format!("key does not have the '{usage}' usage"),
        ));
    }
    Ok(CryptoKeyPayload {
        key_type: key.key_type.clone(),
        extractable: key.extractable,
        raw: key.raw.clone(),
        alg_name: key.alg_name.clone(),
        hash_name: key.hash_name.clone(),
        usages: key.usages.clone(),
    })
}

/// AES-GCM encrypt/decrypt. Only 96-bit (12-byte) nonces are supported; the
/// tag size is dispatched to the right `TagSize` type parameter.
fn gcm_crypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    msg: &[u8],
    tag_len: usize,
    decrypt: bool,
) -> Option<Vec<u8>> {
    use aes_gcm::{
        AesGcm,
        aead::{
            Aead, AeadCore, KeyInit, Payload,
            array::typenum::consts::{U12, U13, U14, U15, U16},
        },
        aes::cipher::{BlockCipherEncrypt, BlockSizeUser},
    };

    fn gcm_do<K, T>(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
        decrypt: bool,
    ) -> Option<Vec<u8>>
    where
        K: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit,
        T: aes_gcm::TagSize,
        AesGcm<K, U12, T>: Aead + AeadCore<NonceSize = U12>,
    {
        let cipher = AesGcm::<K, U12, T>::new_from_slice(key).ok()?;
        let nonce = aes_gcm::aead::array::Array::<u8, U12>::from_slice(nonce);
        let payload = Payload { msg, aad };
        if decrypt {
            cipher.decrypt(nonce, payload).ok()
        } else {
            cipher.encrypt(nonce, payload).ok()
        }
    }

    macro_rules! gcm_dispatch_tag {
        ($K:ty) => {
            match tag_len {
                96 => gcm_do::<$K, U12>(key, nonce, aad, msg, decrypt),
                104 => gcm_do::<$K, U13>(key, nonce, aad, msg, decrypt),
                112 => gcm_do::<$K, U14>(key, nonce, aad, msg, decrypt),
                120 => gcm_do::<$K, U15>(key, nonce, aad, msg, decrypt),
                128 => gcm_do::<$K, U16>(key, nonce, aad, msg, decrypt),
                _ => None,
            }
        };
    }

    match key.len() {
        16 => gcm_dispatch_tag!(aes_gcm::aes::Aes128),
        24 => gcm_dispatch_tag!(aes_gcm::aes::Aes192),
        32 => gcm_dispatch_tag!(aes_gcm::aes::Aes256),
        _ => None,
    }
}

fn subtle_encrypt(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() < 3 {
        return Err(ctx.throw_type_error("encrypt() requires 3 arguments"));
    }
    let alg_val = cc.arg(0);
    let data = get_buffer_source_bytes(ctx, &cc.arg(2))?;
    let name = algorithm_name(ctx, &alg_val)?;
    if name != "AES-GCM" {
        return Err(throw_dom_exception(
            ctx,
            "NotSupportedError",
            &format!("Unrecognized algorithm '{name}'"),
        ));
    }
    let key = get_aes_key(ctx, &cc.arg(1), "encrypt")?;
    let params = parse_gcm_params(ctx, &alg_val)?;
    let ct = gcm_crypt(
        &key.raw,
        &params.iv,
        &params.aad,
        &data,
        params.tag_len,
        false,
    )
    .ok_or_else(|| throw_dom_exception(ctx, "OperationError", "AES-GCM encryption failed"))?;
    let ab = ArrayBuffer::from_bytes(
        ctx,
        JSValue::UNDEFINED,
        ct.into_boxed_slice(),
        ptr::null_mut(),
    )?;

    Promise::from_resolve_value(ctx, ab.into()).map(JSValue::from)
}

async_op!(subtle_encrypt, js_subtle_encrypt);

fn subtle_decrypt(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() < 3 {
        return Err(ctx.throw_type_error("decrypt() requires 3 arguments"));
    }
    let alg_val = cc.arg(0);
    let data = get_buffer_source_bytes(ctx, &cc.arg(2))?;
    let name = algorithm_name(ctx, &alg_val)?;
    if name != "AES-GCM" {
        return Err(throw_dom_exception(
            ctx,
            "NotSupportedError",
            &format!("Unrecognized algorithm '{name}'"),
        ));
    }
    let key = get_aes_key(ctx, &cc.arg(1), "decrypt")?;
    let params = parse_gcm_params(ctx, &alg_val)?;
    let pt = gcm_crypt(
        &key.raw,
        &params.iv,
        &params.aad,
        &data,
        params.tag_len,
        true,
    )
    .ok_or_else(|| throw_dom_exception(ctx, "OperationError", "AES-GCM decryption failed"))?;
    let ab = ArrayBuffer::from_bytes(
        ctx,
        JSValue::UNDEFINED,
        pt.into_boxed_slice(),
        ptr::null_mut(),
    )?;
    Promise::from_resolve_value(ctx, ab.into()).map(JSValue::from)
}

async_op!(subtle_decrypt, js_subtle_decrypt);

// ---------------------------------------------------------------------------
// importKey / exportKey
// ---------------------------------------------------------------------------

/// Base64url without padding (JWK encoding), with lenient `=` handling.
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let stripped: String = s.trim_end_matches('=').to_string();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&stripped)
        .ok()
}

fn base64url_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Read an optional string member of a JsonWebKey dictionary.
fn jwk_member(ctx: &mut ScopedContext, jwk: &Object, name: &str) -> Result<Option<String>, i32> {
    let v = jwk.get_property_str(ctx, name)?;
    if v.is_undefined() {
        Ok(None)
    } else {
        Ok(Some(
            v.to_string(ctx)?.content().encode_utf8(false).to_string(),
        ))
    }
}

/// JWK consistency checks shared by HMAC and AES imports: `ext` must match the
/// `extractable` parameter and `key_ops`, when present, must equal `usages`.
fn check_ext_and_key_ops(
    ctx: &mut ScopedContext,
    jwk: &Object,
    usages: &[String],
    extractable: bool,
) -> Result<(), i32> {
    if let Some(ext) = jwk_member(ctx, jwk, "ext")?
        && (ext == "true") != extractable
    {
        return Err(throw_dom_exception(
            ctx,
            "DataError",
            "JWK ext does not match the extractable parameter",
        ));
    }

    let kop_val = jwk.get_property_str(ctx, "key_ops")?;
    if !kop_val.is_undefined() {
        let mut kop = get_key_usages(ctx, &kop_val)?;
        kop.sort();
        let mut u = usages.to_vec();
        u.sort();
        if kop != u {
            return Err(throw_dom_exception(
                ctx,
                "DataError",
                "JWK key_ops does not match the keyUsages parameter",
            ));
        }
    }
    Ok(())
}

/// Import an HMAC key from a JsonWebKey dictionary. Returns the raw key bytes.
fn import_hmac_jwk(
    ctx: &mut ScopedContext,
    jwk: &Object,
    hash: &str,
    usages: &[String],
    extractable: bool,
) -> Result<Vec<u8>, i32> {
    if jwk_member(ctx, jwk, "kty")?.as_deref() != Some("oct") {
        return Err(throw_dom_exception(
            ctx,
            "DataError",
            "JWK kty must be 'oct' for symmetric keys",
        ));
    }
    let expected_alg = match hash {
        "SHA-256" => Some("HS256"),
        "SHA-384" => Some("HS384"),
        "SHA-512" => Some("HS512"),
        _ => None, // SHA-1 HMAC has no JWK alg representation
    };
    if let Some(alg) = jwk_member(ctx, jwk, "alg")? {
        match (expected_alg, alg.as_str()) {
            (Some(expected), a) if a == expected => {}
            _ => {
                return Err(throw_dom_exception(
                    ctx,
                    "DataError",
                    "JWK alg does not match the HMAC hash",
                ));
            }
        }
    }
    if let Some(u) = jwk_member(ctx, jwk, "use")?
        && u != "sig"
    {
        return Err(throw_dom_exception(
            ctx,
            "DataError",
            "JWK use must be 'sig' for HMAC keys",
        ));
    }
    check_ext_and_key_ops(ctx, jwk, usages, extractable)?;
    let k = jwk_member(ctx, jwk, "k")?
        .ok_or_else(|| throw_dom_exception(ctx, "DataError", "JWK is missing the k member"))?;
    let bytes = base64url_decode(&k)
        .ok_or_else(|| throw_dom_exception(ctx, "DataError", "JWK k is not valid base64url"))?;
    if bytes.is_empty() {
        return Err(throw_dom_exception(
            ctx,
            "DataError",
            "JWK k must not be empty",
        ));
    }
    Ok(bytes)
}

/// Import an AES-GCM key from a JsonWebKey dictionary. Returns the raw bytes.
fn import_aes_jwk(
    ctx: &mut ScopedContext,
    jwk: &Object,
    usages: &[String],
    extractable: bool,
) -> Result<Vec<u8>, i32> {
    if jwk_member(ctx, jwk, "kty")?.as_deref() != Some("oct") {
        return Err(throw_dom_exception(
            ctx,
            "DataError",
            "JWK kty must be 'oct' for symmetric keys",
        ));
    }
    let k = jwk_member(ctx, jwk, "k")?
        .ok_or_else(|| throw_dom_exception(ctx, "DataError", "JWK is missing the k member"))?;
    let bytes = base64url_decode(&k)
        .ok_or_else(|| throw_dom_exception(ctx, "DataError", "JWK k is not valid base64url"))?;
    if !matches!(bytes.len(), 16 | 24 | 32) {
        return Err(throw_dom_exception(
            ctx,
            "DataError",
            "AES-GCM JWK key length must be 128, 192 or 256 bits",
        ));
    }
    let expected_alg = match bytes.len() {
        16 => "A128GCM",
        24 => "A192GCM",
        32 => "A256GCM",
        _ => unreachable!(),
    };
    if let Some(alg) = jwk_member(ctx, jwk, "alg")?
        && alg != expected_alg
    {
        return Err(throw_dom_exception(
            ctx,
            "DataError",
            "JWK alg does not match the key length",
        ));
    }
    if let Some(u) = jwk_member(ctx, jwk, "use")?
        && u != "enc"
    {
        return Err(throw_dom_exception(
            ctx,
            "DataError",
            "JWK use must be 'enc' for AES keys",
        ));
    }
    check_ext_and_key_ops(ctx, jwk, usages, extractable)?;
    Ok(bytes)
}

fn subtle_import_key(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() < 5 {
        return Err(ctx.throw_type_error("importKey() requires 5 arguments"));
    }
    let format = cc
        .arg(0)
        .to_string(ctx)?
        .content()
        .encode_utf8(false)
        .to_string();
    if format != "raw" && format != "jwk" {
        return Err(throw_dom_exception(
            ctx,
            "NotSupportedError",
            &format!("Unrecognized key format '{format}'"),
        ));
    }
    let algorithm = cc.arg(2);
    let extractable = cc.arg(3).to_bool()?;
    let usages = get_key_usages(ctx, &cc.arg(4))?;

    let name = algorithm_name(ctx, &algorithm)?;
    let (raw, hash_name) = match name.as_str() {
        "HMAC" => {
            validate_key_usages(ctx, &usages, &["sign", "verify"])?;
            // The `hash` member is required for HMAC imports (spec: SyntaxError).
            let obj = algorithm.as_object().ok_or_else(|| {
                throw_dom_exception(
                    ctx,
                    "SyntaxError",
                    "HMAC import requires an object algorithm with a hash member",
                )
            })?;
            let hash_val = obj.get_property_str(ctx, "hash")?;
            if hash_val.is_undefined() {
                return Err(throw_dom_exception(
                    ctx,
                    "SyntaxError",
                    "HMAC import requires a hash member",
                ));
            }
            let hash = algorithm_name(ctx, &hash_val)?;
            if !matches!(hash.as_str(), "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512") {
                return Err(throw_dom_exception(
                    ctx,
                    "NotSupportedError",
                    &format!("Unsupported hash '{hash}'"),
                ));
            }
            let bytes = match format.as_str() {
                "raw" => {
                    let b = get_buffer_source_bytes(ctx, &cc.arg(1))?;
                    if b.is_empty() {
                        return Err(throw_dom_exception(
                            ctx,
                            "DataError",
                            "HMAC raw key must not be empty",
                        ));
                    }
                    b
                }
                _ => {
                    let jwk = cc.arg(1).as_object().ok_or_else(|| {
                        ctx.throw_type_error("keyData must be an object for JWK import")
                    })?;
                    import_hmac_jwk(ctx, &jwk, &hash, &usages, extractable)?
                }
            };
            (bytes, Some(hash))
        }
        "AES-GCM" => {
            validate_key_usages(ctx, &usages, &["encrypt", "decrypt"])?;
            let bytes = match format.as_str() {
                "raw" => {
                    let b = get_buffer_source_bytes(ctx, &cc.arg(1))?;
                    if !matches!(b.len(), 16 | 24 | 32) {
                        return Err(throw_dom_exception(
                            ctx,
                            "DataError",
                            "AES-GCM raw key length must be 128, 192 or 256 bits",
                        ));
                    }
                    b
                }
                _ => {
                    let jwk = cc.arg(1).as_object().ok_or_else(|| {
                        ctx.throw_type_error("keyData must be an object for JWK import")
                    })?;
                    import_aes_jwk(ctx, &jwk, &usages, extractable)?
                }
            };
            (bytes, None)
        }
        _ => {
            return Err(throw_dom_exception(
                ctx,
                "NotSupportedError",
                &format!("Unrecognized algorithm '{name}'"),
            ));
        }
    };

    let key = make_key(ctx, raw, name, hash_name, extractable, usages)?;
    Promise::from_resolve_value(ctx, key).map(JSValue::from)
}

async_op!(subtle_import_key, js_subtle_import_key);

/// Serialize a CryptoKey as a JsonWebKey dictionary.
fn build_jwk(ctx: &mut ScopedContext, key: &CryptoKeyPayload) -> Result<Object, i32> {
    let mut obj = ctx.create_base_object()?;
    let kty = super::make_string(ctx, "oct")?;
    let k = super::make_string(ctx, &base64url_encode(&key.raw))?;
    obj.set_property_str(ctx, "kty", kty)?;
    obj.set_property_str(ctx, "k", k)?;
    let alg = match key.alg_name.as_str() {
        "HMAC" => match key.hash_name.as_deref() {
            Some("SHA-256") => "HS256",
            Some("SHA-384") => "HS384",
            Some("SHA-512") => "HS512",
            _ => "", // SHA-1 HMAC has no JWK alg
        },
        "AES-GCM" => match key.raw.len() {
            16 => "A128GCM",
            24 => "A192GCM",
            32 => "A256GCM",
            _ => "",
        },
        _ => "",
    };
    if !alg.is_empty() {
        let alg_val = super::make_string(ctx, alg)?;
        obj.set_property_str(ctx, "alg", alg_val)?;
    }
    obj.set_property_str(ctx, "ext", JSValue::from(key.extractable))?;
    let mut vals = Vec::with_capacity(key.usages.len());
    for u in &key.usages {
        vals.push(super::make_string(ctx, u)?);
    }
    let ops = Array::from_values(ctx, vals)?;
    obj.set_property_str(ctx, "key_ops", ops.into())?;
    Ok(obj)
}

fn subtle_export_key(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() < 2 {
        return Err(ctx.throw_type_error("exportKey() requires 2 arguments"));
    }
    let format = cc
        .arg(0)
        .to_string(ctx)?
        .content()
        .encode_utf8(false)
        .to_string();
    let key_val = cc.arg(1);
    let key = JSCryptoKey::payload_of(&key_val)
        .ok_or_else(|| ctx.throw_type_error("key must be a CryptoKey"))?;
    if !key.extractable {
        return Err(throw_dom_exception(
            ctx,
            "InvalidAccessError",
            "key is not extractable",
        ));
    }
    match format.as_str() {
        "raw" => {
            let ab = ArrayBuffer::from_bytes(
                ctx,
                JSValue::UNDEFINED,
                key.raw.clone().into_boxed_slice(),
                ptr::null_mut(),
            )?;
            Promise::from_resolve_value(ctx, ab.into()).map(JSValue::from)
        }
        "jwk" => {
            let jwk = build_jwk(ctx, key)?;
            Promise::from_resolve_value(ctx, jwk.into()).map(JSValue::from)
        }
        _ => Err(throw_dom_exception(
            ctx,
            "NotSupportedError",
            &format!("Unrecognized key format '{format}'"),
        )),
    }
}

async_op!(subtle_export_key, js_subtle_export_key);

// ---------------------------------------------------------------------------
// SubtleCrypto class
// ---------------------------------------------------------------------------

/// Per WebCrypto, `SubtleCrypto` cannot be constructed from JS.
fn js_subtle_constructor(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    Err(ctx.throw_type_error("Illegal constructor: 'SubtleCrypto' is not constructable"))
}

const CLASS_SUBTLE_PROTO: &[FieldDef] = &[
    FieldDef::FUNC_ENUM("digest", 2, js_subtle_digest, 0),
    FieldDef::FUNC_ENUM("sign", 3, js_subtle_sign, 0),
    FieldDef::FUNC_ENUM("verify", 4, js_subtle_verify, 0),
    FieldDef::FUNC_ENUM("encrypt", 3, js_subtle_encrypt, 0),
    FieldDef::FUNC_ENUM("decrypt", 3, js_subtle_decrypt, 0),
    FieldDef::FUNC_ENUM("importKey", 5, js_subtle_import_key, 0),
    FieldDef::FUNC_ENUM("exportKey", 2, js_subtle_export_key, 0),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "SubtleCrypto",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "SubtleCrypto",
    JSCryptoSubtle,
    (),
    CLASS_SUBTLE_PROTO,
    Some(ClassCtorDef::new(js_subtle_constructor, 0, true).expose_to_global())
);
