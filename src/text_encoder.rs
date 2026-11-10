// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WHATWG Encoding Standard — TextEncoder implementation.
//!
//! TextEncoder always encodes to UTF-8.
//! Per spec: encoding is always "utf-8", no options, no BOM, no streaming.

use zuqe::{
    CallContext, ClassCtorDef, FieldDef, JSResult, JSValue, ScopedContext,
    builtins::typed_array::TypedArray,
    def_native_object,
};

fn js_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let new_target = cc.this();

    JSTextEncoder::new_instance(ctx, new_target).map(JSValue::from)
}

fn js_encode(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let input = if cc.length() > 0 {
        let s = cc.arg(0).to_string(ctx)?;
        s.content().encode_utf8(false).to_string()
    } else {
        String::new()
    };

    let bytes = input.into_bytes();
    let ta = TypedArray::create_from_vec_u8(ctx, bytes)
        .map_err(|_| ctx.throw_internal_error("Failed to create Uint8Array"))?;
    Ok(ta.into())
}

fn js_encode_into(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() < 2 {
        return Err(ctx.throw_type_error("encodeInto requires 2 arguments"));
    }

    let source = cc.arg(0).to_string(ctx)?;
    let utf8 = source.content().encode_utf8(false);

    let dest_val = cc.arg(1);
    let dest_obj = dest_val
        .as_object()
        .ok_or_else(|| ctx.throw_type_error("destination must be a Uint8Array"))?;
    let mut ta = TypedArray::try_from(dest_obj)
        .map_err(|_| ctx.throw_type_error("destination must be a Uint8Array"))?;

    let src = utf8.as_bytes();
    let written = ta.with_bytes_mut(|dest_bytes| {
        let w = src.len().min(dest_bytes.len());
        dest_bytes[..w].copy_from_slice(&src[..w]);
        w
    });

    let mut result = ctx.create_base_object()?;
    result.set_property_str(ctx, "read", (written as f64).into())?;
    result.set_property_str(ctx, "written", (written as f64).into())?;

    Ok(result.into())
}

fn js_encoding_getter(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    ctx.create_string_from_utf8(b"utf-8".to_vec())
        .map(JSValue::make_string)
}

const CLASS_TEXT_ENCODER_PROTO: &[FieldDef] = &[
    FieldDef::GETSET_ENUM("encoding", Some(js_encoding_getter), None, 0),
    FieldDef::FUNC_ENUM("encode", 1, js_encode, 0),
    FieldDef::FUNC_ENUM("encodeInto", 2, js_encode_into, 0),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "TextEncoder",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "TextEncoder",
    JSTextEncoder,
    (),
    CLASS_TEXT_ENCODER_PROTO,
    Some(ClassCtorDef::new(js_constructor, 0, true).expose_to_global())
);
