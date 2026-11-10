// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! Binary↔text encoding global functions.
//!
//! `btoa`/`atob` follow the WHATWG "base64" section (Latin-1 string code
//! points only, ASCII whitespace stripped on decode). `bytesToBase64` /
//! `base64ToBytes` are the byte-oriented base64 variants; `bytesToHex` /
//! `hexToBytes` are the lowercase-hex equivalents. aike has no `Buffer`,
//! so these are the built-in byte-to-text encoders scripts actually use.

use base64::{Engine, engine::general_purpose::STANDARD};

use zuqe::{
    CallContext, Callback, Exception, JSResult, JSValue, Object, ScopedContext,
    builtins::typed_array::TypedArray,
};

use super::crypto::hex_encode;
use super::dom::make_dom_exception;

/// Throw a DOMException synchronously. `make_dom_exception` builds the value;
/// `Exception::Error` + `ctx.throw` turns it into the pending exception.
fn throw_dom_exception(ctx: &mut ScopedContext, name: &str, message: &str) -> i32 {
    let exc = match make_dom_exception(ctx, name, message) {
        Ok(v) => v,
        Err(code) => return code,
    };
    ctx.throw(Exception::Error(exc));
    -1
}

/// Extract bytes from a JS value: supports ArrayBuffer & TypedArray (Uint8Array).
/// Mirrors the `fs` module's arg extractor without widening its visibility.
fn get_bytes_from_arg(ctx: &mut ScopedContext, arg: &mut JSValue) -> Result<Vec<u8>, i32> {
    if let Some(mut ab) = arg.as_object_ArrayBuffer() {
        let mut bytes = Vec::new();
        ab.payload_mut().with_bytes_mut(|b| {
            bytes = b.to_vec();
        });
        return Ok(bytes);
    }
    if arg.as_object_TypedArray().is_some() {
        let buf_val = arg.get_property_str(ctx, "buffer")?;
        if let Some(mut ab) = buf_val.as_object_ArrayBuffer() {
            let mut bytes = Vec::new();
            ab.payload_mut().with_bytes_mut(|b| {
                bytes = b.to_vec();
            });
            return Ok(bytes);
        }
    }
    Err(ctx.throw_type_error("expect Uint8Array or ArrayBuffer"))
}

/// `btoa(data: string) -> string`: encode a Latin-1 string as base64.
/// Throws `InvalidCharacterError` on code points > 0xFF.
fn js_btoa(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let s = cc.arg(0).to_string(ctx)?;
    let s = s.content().encode_utf8(false).to_string();
    let mut bytes = Vec::with_capacity(s.len());
    for ch in s.chars() {
        let c = ch as u32;
        if c > 0xFF {
            return Err(throw_dom_exception(
                ctx,
                "InvalidCharacterError",
                "The string to be encoded contains characters outside of the Latin1 range.",
            ));
        }
        bytes.push(c as u8);
    }
    let encoded = STANDARD.encode(&bytes);
    ctx.create_string_from_utf8(encoded.into_bytes())
        .map(JSValue::make_string)
}

/// WHATWG "forgiving-base64 decode" (HTML Standard §4.4.7): strips ASCII
/// whitespace, rejects lengths ≡ 1 (mod 4), and decodes 6-bit groups with
/// `=` padding counted separately. Unlike a strict decoder this accepts
/// unpadded input (e.g. `atob("aGVsbG8")` → "hello"), matching browsers.
fn forgiving_base64_decode(data: &str) -> Option<Vec<u8>> {
    let clean: String = data.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if clean.is_empty() {
        return Some(Vec::new());
    }
    if clean.len() % 4 == 1 {
        return None;
    }

    let value = |c: char| match c {
        'A'..='Z' => Some(c as u32 - 'A' as u32),
        'a'..='z' => Some(c as u32 - 'a' as u32 + 26),
        '0'..='9' => Some(c as u32 - '0' as u32 + 52),
        '+' => Some(62),
        '/' => Some(63),
        _ => None,
    };

    let mut output = Vec::with_capacity(clean.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut accumulated: u32 = 0;
    let mut padding: u32 = 0;
    for ch in clean.chars() {
        if ch == '=' {
            padding += 1;
        } else {
            buffer = (buffer << 6) | value(ch)?;
            accumulated += 6;
        }
        if accumulated >= 8 {
            accumulated -= 8;
            output.push((buffer >> accumulated) as u8);
            buffer &= (1u32 << accumulated) - 1;
        }
    }
    // Padding is valid only as `x=` (2 leftover bits) or `xx==` (4 leftover).
    let padding_ok = match padding {
        0 => true,
        1 => accumulated == 2,
        2 => accumulated == 4,
        _ => false,
    };
    if padding_ok { Some(output) } else { None }
}

/// `atob(data: string) -> string`: decode a base64 string back to Latin-1.
/// Uses WHATWG forgiving-base64 (whitespace ignored, unpadded accepted);
/// malformed input throws `InvalidCharacterError`.
fn js_atob(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let s = cc.arg(0).to_string(ctx)?;
    let s = s.content().encode_utf8(false).to_string();
    match forgiving_base64_decode(&s) {
        Some(bytes) => {
            let mut out = String::with_capacity(bytes.len());
            for b in bytes {
                out.push(b as char);
            }
            ctx.create_string_from_utf8(out.into_bytes())
                .map(JSValue::make_string)
        }
        None => Err(throw_dom_exception(
            ctx,
            "InvalidCharacterError",
            "The string to be decoded is not correctly encoded.",
        )),
    }
}

/// `bytesToBase64(bytes: Uint8Array) -> string`: base64-encode raw bytes.
fn js_bytes_to_base64(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let bytes = get_bytes_from_arg(ctx, &mut cc.arg(0))?;
    let encoded = STANDARD.encode(&bytes);
    ctx.create_string_from_utf8(encoded.into_bytes())
        .map(JSValue::make_string)
}

/// `base64ToBytes(str: string) -> Uint8Array`: decode base64 to raw bytes.
/// Uses WHATWG forgiving-base64; throws `InvalidCharacterError` on malformed input.
fn js_base64_to_bytes(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let s = cc.arg(0).to_string(ctx)?;
    let s = s.content().encode_utf8(false).to_string();
    let bytes = forgiving_base64_decode(&s).ok_or_else(|| {
        throw_dom_exception(ctx, "InvalidCharacterError", "Invalid base64 string")
    })?;
    TypedArray::create_from_vec_u8(ctx, bytes).map(JSValue::from)
}

/// `bytesToHex(bytes: Uint8Array | ArrayBuffer) -> string`: lowercase hex.
fn js_bytes_to_hex(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let bytes = get_bytes_from_arg(ctx, &mut cc.arg(0))?;
    ctx.create_string_from_utf8(hex_encode(&bytes).into_bytes())
        .map(JSValue::make_string)
}

/// `hexToBytes(str: string) -> Uint8Array`: decode a lowercase or uppercase
/// hex string to bytes. Strict: non-string throws TypeError; odd length or a
/// non-hex character throws RangeError.
fn js_hex_to_bytes(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let s = cc
        .arg(0)
        .as_string(false)
        .ok_or_else(|| ctx.throw_type_error("`data` must be a string"))?
        .content()
        .encode_utf8(false)
        .to_string();

    if s.len() % 2 != 0 {
        return Err(ctx.throw_range_error("`data` must have an even number of hex digits"));
    }

    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };

    let mut bytes = Vec::with_capacity(s.len() / 2);
    let raw = s.as_bytes();
    for i in (0..raw.len()).step_by(2) {
        let hi = nibble(raw[i])
            .ok_or_else(|| ctx.throw_range_error("`data` must be a hexadecimal string"))?;
        let lo = nibble(raw[i + 1])
            .ok_or_else(|| ctx.throw_range_error("`data` must be a hexadecimal string"))?;
        bytes.push((hi << 4) | lo);
    }
    TypedArray::create_from_vec_u8(ctx, bytes).map(JSValue::from)
}

/// Install the encoding globals: `btoa`, `atob`, `bytesToBase64`,
/// `base64ToBytes`, `bytesToHex`, `hexToBytes`.
pub(crate) fn init_encoding(ctx: &mut ScopedContext, mut global: Object) -> Result<(), i32> {
    let btoa = ctx.create_native_function(Callback::Func(js_btoa), "btoa", 1, 0)?;
    global.define_property_value_str(ctx, "btoa", btoa.into(), zuqe::JS_PROP_C_W_E)?;
    let atob = ctx.create_native_function(Callback::Func(js_atob), "atob", 1, 0)?;
    global.define_property_value_str(ctx, "atob", atob.into(), zuqe::JS_PROP_C_W_E)?;
    let enc =
        ctx.create_native_function(Callback::Func(js_bytes_to_base64), "bytesToBase64", 1, 0)?;
    global.define_property_value_str(ctx, "bytesToBase64", enc.into(), zuqe::JS_PROP_C_W_E)?;
    let dec =
        ctx.create_native_function(Callback::Func(js_base64_to_bytes), "base64ToBytes", 1, 0)?;
    global.define_property_value_str(ctx, "base64ToBytes", dec.into(), zuqe::JS_PROP_C_W_E)?;
    let hex = ctx.create_native_function(Callback::Func(js_bytes_to_hex), "bytesToHex", 1, 0)?;
    global.define_property_value_str(ctx, "bytesToHex", hex.into(), zuqe::JS_PROP_C_W_E)?;
    let unhex = ctx.create_native_function(Callback::Func(js_hex_to_bytes), "hexToBytes", 1, 0)?;
    global.define_property_value_str(ctx, "hexToBytes", unhex.into(), zuqe::JS_PROP_C_W_E)?;
    Ok(())
}
