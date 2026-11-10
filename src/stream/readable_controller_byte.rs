// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

use zuqe::{
    CallContext, ClassCtorDef, FieldDef, JSResult, JSValue, ScopedContext, def_native_object,
};

use super::{ReadableControllerPayload, readable_controller::get_readable_controller};

const BYTE_CONTROLLER_PROTO: &[FieldDef] = &[
    FieldDef::FUNC_ENUM("enqueue", 1, js_byte_controller_enqueue, 0),
    FieldDef::FUNC_ENUM("close", 0, js_byte_controller_close, 0),
    FieldDef::FUNC_ENUM("error", 1, js_byte_controller_error, 0),
    FieldDef::GETSET_ENUM(
        "desiredSize",
        Some(js_byte_controller_desired_size),
        None,
        0,
    ),
    FieldDef::GETSET_ENUM(
        "byobRequest",
        Some(js_byte_controller_byob_request),
        None,
        0,
    ),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "ReadableByteStreamController",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

fn js_byte_controller_constructor(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    Err(ctx.throw_type_error("ReadableByteStreamController cannot be constructed directly"))
}

fn js_byte_controller_desired_size(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = get_readable_controller(ctx, &this)?;
    let size = p.desired_size(ctx)?;
    if size.is_nan() {
        Ok(JSValue::NULL)
    } else {
        Ok(JSValue::from(size))
    }
}

fn js_byte_controller_byob_request(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = get_readable_controller(ctx, &this)?;
    p.byob_request(ctx)
}

fn js_byte_controller_enqueue(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let chunk = cc.arg(0);
    let p = get_readable_controller(ctx, &this)?;
    let owner = Some(this);
    p.enqueue(ctx, owner, chunk, JSValue::UNDEFINED)
}

fn js_byte_controller_close(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = get_readable_controller(ctx, &this)?;
    p.close(ctx)?;
    Ok(JSValue::UNDEFINED)
}

fn js_byte_controller_error(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let e = cc.arg(0);
    let p = get_readable_controller(ctx, &this)?;
    p.error(ctx, e)?;
    Ok(JSValue::UNDEFINED)
}

def_native_object!(
    "ReadableByteStreamController",
    JSReadableByteStreamController,
    ReadableControllerPayload,
    BYTE_CONTROLLER_PROTO,
    Some(ClassCtorDef::new(js_byte_controller_constructor, 0, false).expose_to_global())
);
