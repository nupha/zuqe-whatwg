// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

use zuqe::{
    CallContext, ClassCtorDef, FieldDef, GcBind, JSResult, JSValue, ScopedContext,
    def_native_object,
};

use super::{ReadableControllerPayload, readable_controller::get_readable_controller};

const CONTROLLER_PROTO: &[FieldDef] = &[
    FieldDef::FUNC_ENUM("enqueue", 1, js_controller_enqueue, 0),
    FieldDef::FUNC_ENUM("close", 0, js_controller_close, 0),
    FieldDef::FUNC_ENUM("error", 1, js_controller_error, 0),
    FieldDef::GETSET_ENUM("desiredSize", Some(js_controller_desired_size), None, 0),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "ReadableStreamDefaultController",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

fn js_controller_constructor(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    Err(ctx.throw_type_error("ReadableStreamDefaultController cannot be constructed directly"))
}

def_native_object!(
    "ReadableStreamDefaultController",
    JSReadableStreamDefaultController,
    ReadableControllerPayload,
    CONTROLLER_PROTO,
    Some(ClassCtorDef::new(js_controller_constructor, 0, false).expose_to_global())
);

/// `def_native_object!` generates no `GcBind`, but the controller payload's
/// `WriteBarrier<Option<…>>` self-handle slot needs one.
impl GcBind for JSReadableStreamDefaultController {
    fn bind_node(&self, ctx: &ScopedContext, owner: std::ptr::NonNull<zuqe::gc_lite::GcHead>) {
        GcBind::bind_node(self.as_object(), ctx, owner)
    }
}

fn js_controller_enqueue(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let chunk = cc.arg(0);
    let options = cc.arg(1);
    let p = get_readable_controller(ctx, &this)?;
    // Spec `enqueue(chunk) method steps`: if CanCloseOrEnqueue is false, throw a
    // TypeError (stream closed/errored or close requested).
    if !p.can_close_or_enqueue() {
        return Err(ctx.throw_type_error(
            "Cannot enqueue on a ReadableStreamDefaultController whose stream is not readable",
        ));
    }
    let owner = Some(this);
    p.enqueue(ctx, owner, chunk, options)
}

fn js_controller_close(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = get_readable_controller(ctx, &this)?;
    p.close(ctx)?;
    Ok(JSValue::UNDEFINED)
}

fn js_controller_error(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let e = cc.arg(0);
    let p = get_readable_controller(ctx, &this)?;
    p.error(ctx, e)?;
    Ok(JSValue::UNDEFINED)
}

fn js_controller_desired_size(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = get_readable_controller(ctx, &this)?;

    // Spec: errored -> null, closed -> 0, else highWaterMark - queueTotalSize
    // (can be negative when the queue is over-full).
    let size = p.desired_size(ctx)?;
    if size.is_nan() {
        Ok(JSValue::NULL)
    } else {
        Ok(JSValue::from(size))
    }
}
