// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! `ReadableStreamBYOBRequest` — internal-only class used by byte-stream
//! controllers to surface pending BYOB pull-into descriptors to user code.
//!
//! Per WHATWG Streams §4.8, the constructor is **not** publicly invocable;
//! instances are created only by the engine via
//! `ReadableByteStreamControllerGetBYOBRequest`.

use zuqe::{
    CallContext, ClassCtorDef, FieldDef, JSResult, JSValue, ScopedContext, def_native_object,
    gc_lite::GcTrace,
};

use super::readable_controller::get_readable_controller;

/// Payload stored on each `ReadableStreamBYOBRequest` instance.
#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct ByobRequestPayload {
    /// Back-reference to the owning `ReadableByteStreamController`.
    controller: JSValue,
    /// The destination view the pull-into descriptor refers to.
    view: JSValue,
}

impl ByobRequestPayload {
    pub(crate) fn new(controller: JSValue, view: JSValue) -> Self {
        Self { controller, view }
    }

    pub(crate) fn controller(&self) -> JSValue {
        self.controller
    }

    pub(crate) fn view(&self) -> JSValue {
        self.view
    }
}

// ---------------------------------------------------------------------------
// Prototype methods / getters
// ---------------------------------------------------------------------------

fn js_byob_request_constructor(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    // Per WHATWG Streams §4.8: the constructor is internal-only.
    // The WPT test `construct-byob-request.any.js` asserts that `new
    // ReadableStreamBYOBRequest(controller, view)` always throws TypeError.
    Err(ctx.throw_type_error("ReadableStreamBYOBRequest cannot be constructed directly"))
}

/// `ReadableStreamBYOBRequest.prototype.view` — readonly getter.
fn js_byob_request_view(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let payload = JSReadableStreamBYOBRequest::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("not a ReadableStreamBYOBRequest"))?;
    Ok(payload.view())
}

/// `ReadableStreamBYOBRequest.prototype.respond(bytesWritten)`.
fn js_byob_request_respond(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let payload = JSReadableStreamBYOBRequest::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("not a ReadableStreamBYOBRequest"))?;

    // Step 1: If [[controller]] is undefined, throw TypeError.
    if payload.controller().is_undefined() {
        return Err(ctx.throw_type_error("ReadableStreamBYOBRequest has an invalid controller"));
    }

    let bytes_written = cc.arg(0);
    let controller = payload.controller();
    let cp = get_readable_controller(ctx, &controller)?;
    cp.respond(ctx, bytes_written)?;
    Ok(JSValue::UNDEFINED)
}

/// `ReadableStreamBYOBRequest.prototype.respondWithNewView(view)`.
fn js_byob_request_respond_with_new_view(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let payload = JSReadableStreamBYOBRequest::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("not a ReadableStreamBYOBRequest"))?;

    // Step 1: If [[controller]] is undefined, throw TypeError.
    if payload.controller().is_undefined() {
        return Err(ctx.throw_type_error("ReadableStreamBYOBRequest has an invalid controller"));
    }

    let new_view = cc.arg(0);
    let controller = payload.controller();
    let cp = get_readable_controller(ctx, &controller)?;
    cp.respond_with_new_view(ctx, new_view)?;
    Ok(JSValue::UNDEFINED)
}

// ---------------------------------------------------------------------------
// Class definition
// ---------------------------------------------------------------------------

const BYOB_REQUEST_PROTO: &[FieldDef] = &[
    FieldDef::GETSET_ENUM("view", Some(js_byob_request_view), None, 0),
    FieldDef::FUNC_ENUM("respond", 1, js_byob_request_respond, 0),
    FieldDef::FUNC_ENUM(
        "respondWithNewView",
        1,
        js_byob_request_respond_with_new_view,
        0,
    ),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "ReadableStreamBYOBRequest",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "ReadableStreamBYOBRequest",
    JSReadableStreamBYOBRequest,
    ByobRequestPayload,
    BYOB_REQUEST_PROTO,
    Some(ClassCtorDef::new(js_byob_request_constructor, 2, false).expose_to_global())
);
