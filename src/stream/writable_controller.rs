// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WritableStreamDefaultController: the controller handed to an underlying
//! sink's `start()`/`write()` callbacks.

use zuqe::{
    CallContext, ClassCtorDef, FieldDef, GcBind, JSResult, JSValue, ScopedContext, WriteBarrier,
    def_native_object,
    gc_lite::GcTrace,
};

use crate::{
    abort::make_default_signal,
    stream::{
        transform_controller::JSTransformStreamDefaultController, writable::JSWritableStream,
    },
};

#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct WritableControllerPayload {
    pub(crate) stream: Option<JSWritableStream>,
    /// Guarded: TransformStream construction replaces it with a wrapper after
    /// the controller instance already exists.
    pub(crate) underlying_sink: WriteBarrier<JSValue>,
    /// Guarded: wired after the controller instance exists.
    pub(crate) transform_controller: WriteBarrier<Option<JSTransformStreamDefaultController>>,
    pub(crate) high_water_mark: f64,
    /// The `AbortSignal` exposed as `controller.signal`. Aborted synchronously
    /// when the stream is aborted (per the Streams spec). Created lazily via
    /// `ensure_signal`.
    pub(crate) signal: WriteBarrier<Option<JSValue>>,
    /// The queuing strategy's `size` algorithm (a JS function), or `undefined`
    /// when no strategy was supplied (default chunk size is 1.0).
    pub(crate) size_algorithm: JSValue,
}

impl WritableControllerPayload {
    pub(crate) fn new(
        underlying_sink: JSValue,
        stream: Option<JSWritableStream>,
        high_water_mark: f64,
        size_algorithm: JSValue,
    ) -> Self {
        Self {
            stream,
            underlying_sink: WriteBarrier::new(underlying_sink),
            transform_controller: WriteBarrier::new(None),
            high_water_mark,
            signal: WriteBarrier::new(None),
            size_algorithm,
        }
    }

    /// Store + bind the sink wrapper. Owner is the controller node.
    pub(crate) fn set_underlying_sink(
        &mut self,
        ctx: &ScopedContext,
        owner: JSValue,
        sink: JSValue,
    ) {
        self.underlying_sink.set(ctx, owner, sink);
    }

    /// Store + bind the transform controller back-pointer.
    pub(crate) fn set_transform_controller(
        &mut self,
        ctx: &ScopedContext,
        owner: JSValue,
        tc: JSTransformStreamDefaultController,
    ) {
        self.transform_controller.set(ctx, owner, Some(tc));
    }

    /// The controller object's own handle, resolved through the stream's
    /// `controller` back-pointer (set during stream setup).
    fn owner_value(&self) -> Option<JSValue> {
        self.stream.and_then(|s| {
            let sv = JSValue::from(s);
            JSWritableStream::payload_of(&sv).and_then(|sp| sp.controller.get())
        }).map(JSValue::from)
    }

    /// Lazily create (once) and return this controller's `AbortSignal`.
    pub(crate) fn ensure_signal(&mut self, ctx: &mut ScopedContext) -> Result<JSValue, i32> {
        if self.signal.get().is_none() {
            let s = make_default_signal(ctx)?;
            // The guard slot records the barrier (the controller may already be old).
            let owner = self.owner_value().unwrap_or(JSValue::UNDEFINED);
            self.signal.set(ctx, owner, Some(s));
        }
        Ok(self.signal.get().unwrap())
    }
}

const WRITABLE_CONTROLLER_PROTO: &[FieldDef] = &[
    FieldDef::FUNC_ENUM("error", 1, js_writable_controller_error, 0),
    FieldDef::GETSET_ENUM("signal", Some(js_writable_controller_signal), None, 0),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "WritableStreamDefaultController",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

fn js_writable_controller_constructor(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    Err(ctx.throw_type_error("WritableStreamDefaultController cannot be constructed directly"))
}

def_native_object!(
    "WritableStreamDefaultController",
    JSWritableStreamDefaultController,
    WritableControllerPayload,
    WRITABLE_CONTROLLER_PROTO,
    Some(ClassCtorDef::new(js_writable_controller_constructor, 0, false).expose_to_global())
);

/// `def_native_object!` generates no `GcBind`, but the payload's guard slots
/// need one: the edge is owner → this object node, identical to `Object`'s.
impl GcBind for JSWritableStreamDefaultController {
    fn bind_node(&self, ctx: &ScopedContext, owner: std::ptr::NonNull<zuqe::gc_lite::GcHead>) {
        GcBind::bind_node(self.as_object(), ctx, owner)
    }
}

fn js_writable_controller_error(_ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let e = cc.arg(0);
    let this = cc.this();

    // Per spec `WritableStreamDefaultControllerError`: error the stream,
    // rejecting the writer's `ready`/`closed`, queued writes, and a pending
    // close request. An in-flight write keeps running and settles on its own.
    if let Some(p) = JSWritableStreamDefaultController::payload_of(&this)
        && let Some(mut stream_val) = p.stream
        && let Some(sp) = stream_val.payload_mut()
    {
        sp.start_erroring(_ctx, e)?;
    }

    Ok(JSValue::UNDEFINED)
}

fn js_writable_controller_signal(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut this = cc.this();
    let p = JSWritableStreamDefaultController::payload_mut_of(&mut this)
        .ok_or_else(|| ctx.throw_type_error("not a WritableStreamDefaultController"))?;
    p.ensure_signal(ctx)
}
