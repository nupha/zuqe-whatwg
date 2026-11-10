// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! TransformStreamDefaultController: the controller handed to a transformer's
//! `start()`/`transform()`/`flush()` callbacks.

use std::cell::Cell;

use zuqe::{
    CallContext, ClassCtorDef, Exception, FieldDef, GcBind, JSResult, JSValue, ScopedContext,
    WriteBarrier, builtins::promise::Promise, def_native_object, gc_lite::GcTrace,
};

use crate::stream::{
    readable_controller_default::JSReadableStreamDefaultController, transform::JSTransformStream,
    writable::JSWritableStream,
};

use super::RsState;

#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct TransformControllerPayload {
    /// Back-reference to the controlling TransformStream (spec `[[stream]]`).
    pub(crate) stream: WriteBarrier<Option<JSTransformStream>>,
    pub(crate) readable_controller: WriteBarrier<JSReadableStreamDefaultController>,
    pub(crate) writable_stream: WriteBarrier<JSWritableStream>,
    pub(crate) transformer: WriteBarrier<JSValue>,
    /// Set once cancel/flush is invoked; subsequent calls return this promise
    /// (spec `[[finishPromise]]`).
    pub(crate) finish_promise: WriteBarrier<Option<Promise>>,
    /// WHATWG `[[backpressure]]` flag (the promise itself is the stream
    /// payload's guard slot).
    pub(crate) backpressure: Cell<bool>,
    // No controller-side `[[backpressureChangePromise]]`: the single guard slot
    // lives on `TransformStreamPayload` (see `set_backpressure_change_promise`),
    // which is the owner that traces and binds it.
}

impl TransformControllerPayload {
    pub(super) fn new(
        readable_controller: JSReadableStreamDefaultController,
        writable_stream: JSWritableStream,
        transformer: JSValue,
    ) -> Self {
        Self {
            stream: WriteBarrier::new(None),
            readable_controller: WriteBarrier::new(readable_controller),
            writable_stream: WriteBarrier::new(writable_stream),
            transformer: WriteBarrier::new(transformer),
            finish_promise: WriteBarrier::new(None),
            backpressure: Cell::new(true),
        }
    }

    /// The only write path for `finish_promise`: store and barrier stay in one
    /// `WriteBarrier::set` call, so no GC point can observe the unbarriered edge.
    pub(crate) fn set_finish_promise(&mut self, ctx: &ScopedContext, owner: JSValue, p: Promise) {
        self.finish_promise.set(ctx, owner, Some(p));
    }

    pub(crate) fn finish_promise(&self) -> Option<Promise> {
        self.finish_promise.get()
    }
}

/// Post-construction write path on the native wrapper: the owner is derived
/// from `self`, so callers cannot bind the edge to the wrong object.
impl JSTransformStreamDefaultController {
    pub(crate) fn set_stream(&mut self, ctx: &ScopedContext, s: JSTransformStream) {
        let owner = JSValue::from(*self);
        if let Some(p) = self.payload_mut() {
            p.stream.set(ctx, owner, Some(s));
        }
    }
}

const TRANSFORM_CONTROLLER_PROTO: &[FieldDef] = &[
    FieldDef::FUNC_ENUM("enqueue", 1, js_transform_controller_enqueue, 0),
    FieldDef::FUNC_ENUM("error", 1, js_transform_controller_error, 0),
    FieldDef::FUNC_ENUM("terminate", 0, js_transform_controller_terminate, 0),
    FieldDef::GETSET_ENUM(
        "desiredSize",
        Some(js_transform_controller_desired_size),
        None,
        0,
    ),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "TransformStreamDefaultController",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

fn js_transform_controller_constructor(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    Err(ctx.throw_type_error("TransformStreamDefaultController cannot be constructed directly"))
}

def_native_object!(
    "TransformStreamDefaultController",
    JSTransformStreamDefaultController,
    TransformControllerPayload,
    TRANSFORM_CONTROLLER_PROTO,
    Some(ClassCtorDef::new(js_transform_controller_constructor, 0, false).expose_to_global())
);

/// `def_native_object!` generates no `GcBind`, but the payload's guard slots
/// need one: the edge is owner → this object node, identical to `Object`'s.
impl GcBind for JSTransformStreamDefaultController {
    fn bind_node(&self, ctx: &ScopedContext, owner: std::ptr::NonNull<zuqe::gc_lite::GcHead>) {
        GcBind::bind_node(self.as_object(), ctx, owner)
    }
}

fn js_transform_controller_enqueue(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let chunk = cc.arg(0);
    let p = JSTransformStreamDefaultController::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("not a TransformStreamDefaultController"))?;

    let rc = p.readable_controller.get();
    let rcp = rc
        .payload()
        .ok_or_else(|| ctx.throw_internal_error("invalid readable controller"))?;

    // Spec §6.4.2 step 3: once the readable side is errored or close has been
    // requested, enqueue throws a TypeError.
    if !rcp.can_close_or_enqueue() {
        return Err(ctx.throw_type_error("cannot enqueue on a closed or errored stream"));
    }

    // Spec §6.4.2 steps 4-5: delegate to the readable controller (which runs the
    // strategy's size algorithm). When that throws, error the writable side,
    // unblock write, and re-throw the readable side's stored error — the first
    // error wins over a later one thrown by size().
    let rc_owner = Some(JSValue::from(*rc.as_object()));
    if rcp
        .enqueue(ctx, rc_owner, chunk, JSValue::UNDEFINED)
        .is_err()
    {
        let e = ctx.take_exception().to_value(ctx);
        if let Some(stream_handle) = p.stream.get() {
            let stream_val = JSValue::from(stream_handle);
            super::transform::transform_stream_error_writable_and_unblock_write(
                ctx, stream_val, e,
            )?;
        }
        let stored = match rcp.stream() {
            Some(s) => {
                let sv = JSValue::from(s);
                super::JSReadableStream::payload_of(&sv)
                    .map(|sp| sp.stored_error.get())
                    .unwrap_or(e)
            }
            None => e,
        };
        ctx.throw(Exception::Error(stored));
        return Err(-1);
    }

    // Propagate backpressure: if the readable side's desiredSize ≤ 0, the
    // TransformStream should block further writes (spec §6.4.2 step 7).
    if let Some(stream_handle) = p.stream.get() {
        let stream_val = JSValue::from(stream_handle);
        let readable_full = rcp.desired_size(ctx)? <= 0.0;
        if readable_full && !p.backpressure.get() {
            super::transform::transform_stream_set_backpressure(ctx, stream_val, true)?;
        }
    }

    Ok(JSValue::UNDEFINED)
}

fn js_transform_controller_error(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let reason = cc.arg(0);
    let p = JSTransformStreamDefaultController::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("not a TransformStreamDefaultController"))?;

    // TransformStreamDefaultControllerError(controller, e) →
    //   TransformStreamError(controller.[[stream]], e) →
    //   1. ReadableStreamDefaultControllerError(readable.[[controller]], e)
    //   2. TransformStreamErrorWritableAndUnblockWrite(stream, e)
    if let Some(rcp) = p.readable_controller.get().payload() {
        rcp.error(ctx, reason)?;
    }
    if let Some(stream_handle) = p.stream.get() {
        let stream_val = JSValue::from(stream_handle);
        super::transform::transform_stream_error_writable_and_unblock_write(
            ctx, stream_val, reason,
        )?;
    }

    Ok(JSValue::UNDEFINED)
}

fn js_transform_controller_terminate(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSTransformStreamDefaultController::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("not a TransformStreamDefaultController"))?;

    // Spec `TransformStreamDefaultControllerTerminate` step 3: close the
    // readable side.
    if let Some(rcp) = p.readable_controller.get().payload() {
        rcp.set_close_requested(true);

        rcp.resolve_pending_read(ctx, JSValue::UNDEFINED, true);

        if rcp.queue().borrow().is_empty()
            && let Some(mut stream_val) = rcp.stream()
            && let Some(sp) = stream_val.payload_mut()
        {
            sp.state = RsState::Closed;
        }
    }

    // Spec step 4-5: error the writable with a TypeError and unblock any write
    // waiting on backpressure (`TransformStreamErrorWritableAndUnblockWrite`).
    let err = ctx
        .create_error_object(zuqe::ErrorKind::Type, "TransformStream terminated", false)
        .map(JSValue::from)
        .unwrap_or(JSValue::UNDEFINED);

    if let Some(stream_handle) = p.stream.get() {
        let stream_val = JSValue::from(stream_handle);
        super::transform::transform_stream_error_writable_and_unblock_write(ctx, stream_val, err)?;
    }

    Ok(JSValue::UNDEFINED)
}

fn js_transform_controller_desired_size(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSTransformStreamDefaultController::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("not a TransformStreamDefaultController"))?;

    if let Some(rcp) = p.readable_controller.get().payload() {
        // Spec: if the readable stream is errored -> null; closed -> 0;
        // else highWaterMark - queueTotalSize.
        if let Some(s) = rcp.stream()
            && let Some(sp) = s.payload()
        {
            match sp.state {
                // Readable streams never enter the Erroring state.
                RsState::Errored | RsState::Erroring => return Ok(JSValue::NULL),
                RsState::Closed => return Ok(JSValue::ZERO),
                RsState::Readable => {}
            }
        }
        let total = rcp.queue_total_size();
        return Ok(JSValue::from(rcp.high_water_mark() - total));
    }
    Ok(JSValue::ZERO)
}

#[cfg(all(test, debug_assertions))]
mod gc_barrier_tests {
    use zuqe::{
        Context, EvalFlags, EvalName, EvalType, JSValue, NativeObject, Runtime, ScopedContext,
        builtins::promise::{Promise, PromiseState},
    };

    use super::JSTransformStreamDefaultController;

    /// The controller can outlive its young generation before cancel/flush runs.
    /// Once it is old, the post-construction `finish_promise` store must record
    /// the edge or the next minor frees a still-referenced promise.
    #[test]
    fn finish_promise_write_barrier_survives_a_minor() -> Result<(), i32> {
        let mut rt = Runtime::create()?;
        let mut ctx: Context<'static> = rt.create_context(ScopedContext::ECMA_CONTEXT_SETUP)?;

        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            let global = cx.global_obj();
            crate::init_whatwg(&mut cx, global)?;
            cx.eval(
                b"new TransformStream({ start(c) { globalThis.__controller = c; } });",
                &EvalName::Name("finish-promise-barrier-setup".to_string()),
                EvalType::Global,
                EvalFlags::empty(),
            )?;
            Ok(())
        })?;

        // Promote the controller (and its payload) to old generation.
        let _ = rt.gc_minor_now();

        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            let v = cx.eval(
                b"globalThis.__controller",
                &EvalName::Name("finish-promise-barrier-controller".to_string()),
                EvalType::Global,
                EvalFlags::empty(),
            )?;
            let mut controller = JSTransformStreamDefaultController::from_value(v).ok_or(-1)?;
            let (finish, _) = Promise::create(&mut cx)?;
            let owner = JSValue::from(controller);
            controller
                .payload_mut()
                .ok_or(-1)?
                .set_finish_promise(&mut cx, owner, finish);
            Ok(())
        })?;

        let _ = rt.gc_minor_now();

        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            let v = cx.eval(
                b"globalThis.__controller",
                &EvalName::Name("finish-promise-barrier-read".to_string()),
                EvalType::Global,
                EvalFlags::empty(),
            )?;
            let controller = JSTransformStreamDefaultController::from_value(v).ok_or(-1)?;
            let mut finish = controller
                .payload()
                .and_then(|p| p.finish_promise())
                .ok_or(-1)?;
            finish.resolve(&mut cx, JSValue::UNDEFINED);
            assert_eq!(finish.state(), PromiseState::Fulfilled);
            Ok(())
        })
    }

    /// P0-2: `set_stream` derives the owner from the native wrapper. Once the
    /// controller is old, writing a young TransformStream must record the edge
    /// or the next minor frees a stream the controller still points at.
    #[test]
    fn set_stream_write_barrier_survives_a_minor() -> Result<(), i32> {
        let mut rt = Runtime::create()?;
        let mut ctx: Context<'static> = rt.create_context(ScopedContext::ECMA_CONTEXT_SETUP)?;

        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            let global = cx.global_obj();
            crate::init_whatwg(&mut cx, global)?;
            cx.eval(
                b"new TransformStream({ start(c) { globalThis.__tc = c; } });",
                &EvalName::Name("set-stream-barrier-setup".to_string()),
                EvalType::Global,
                EvalFlags::empty(),
            )?;
            Ok(())
        })?;

        // Promote the controller (and its payload) to old generation.
        let _ = rt.gc_minor_now();

        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            let v = cx.eval(
                b"globalThis.__tc",
                &EvalName::Name("set-stream-barrier-old".to_string()),
                EvalType::Global,
                EvalFlags::empty(),
            )?;
            let mut controller = JSTransformStreamDefaultController::from_value(v).ok_or(-1)?;
            // Young stream, unrooted once this scope closes.
            let wv = cx.eval(
                b"new TransformStream()",
                &EvalName::Name("set-stream-barrier-young".to_string()),
                EvalType::Global,
                EvalFlags::empty(),
            )?;
            let young = crate::stream::JSTransformStream::from_value(wv).ok_or(-1)?;
            controller.set_stream(&mut cx, young);
            Ok(())
        })?;

        let _ = rt.gc_minor_now();

        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            let v = cx.eval(
                b"globalThis.__tc",
                &EvalName::Name("set-stream-barrier-check".to_string()),
                EvalType::Global,
                EvalFlags::empty(),
            )?;
            let controller = JSTransformStreamDefaultController::from_value(v).ok_or(-1)?;
            let p = controller.payload().ok_or(-1)?;
            let young = p.stream.get().ok_or(-1)?;
            assert!(
                young.payload().is_some(),
                "young stream was collected: the write barrier missed the owner edge"
            );
            Ok(())
        })
    }
}
