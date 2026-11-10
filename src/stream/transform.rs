// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! TransformStream, wiring a readable and a writable side together.

use zuqe::{
    CallContext, ClassCtorDef, FieldDef, GcBind, JSResult, JSValue, NativeObject, ScopedContext,
    WriteBarrier,
    builtins::promise::Promise,
    def_native_object,
    gc_lite::GcTrace,
};

use crate::stream::{
    JSReadableStreamDefaultController, ReadableControllerPayload, extract_high_water_mark,
    extract_size_algorithm,
    readable::{JSReadableStream, ReadableStreamPayload},
    readable_controller::get_readable_controller,
    transform_controller::{JSTransformStreamDefaultController, TransformControllerPayload},
    writable::{JSWritableStream, WritableStreamPayload},
    writable_controller::{JSWritableStreamDefaultController, WritableControllerPayload},
};

// ============================================================================
// TransformStream
// ============================================================================

#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct TransformStreamPayload {
    readable: Option<JSReadableStream>,
    writable: Option<JSWritableStream>,
    pub(crate) controller: Option<JSTransformStreamDefaultController>,
    /// WHATWG `[[backpressure]]` — when true, writes must wait for
    /// `[[backpressureChangePromise]]` before calling transform.
    pub(crate) backpressure: bool,
    /// WHATWG `[[backpressureChangePromise]]` — resolves when backpressure
    /// changes (set by `TransformStreamSetBackpressure`).
    pub(crate) backpressure_change_promise: WriteBarrier<Option<Promise>>,
}

impl TransformStreamPayload {
    /// Store + barrier in one `set` call so no GC point can observe an unbarriered edge.
    pub(crate) fn set_backpressure_change_promise(
        &mut self,
        ctx: &ScopedContext,
        owner: JSValue,
        p: Promise,
    ) {
        self.backpressure_change_promise.set(ctx, owner, Some(p));
    }

    pub(crate) fn backpressure_change_promise(&self) -> Option<Promise> {
        self.backpressure_change_promise.get()
    }
}

const TRANSFORM_STREAM_PROTO: &[FieldDef] = &[
    FieldDef::GETSET_ENUM("readable", Some(js_transform_stream_readable), None, 0),
    FieldDef::GETSET_ENUM("writable", Some(js_transform_stream_writable), None, 0),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "TransformStream",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "TransformStream",
    JSTransformStream,
    TransformStreamPayload,
    TRANSFORM_STREAM_PROTO,
    Some(ClassCtorDef::new(js_transform_stream_constructor, 1, false).expose_to_global())
);

/// `def_native_object!` generates no `GcBind`, but the controller payload's
/// `WriteBarrier<Option<JSTransformStream>>` slot needs one.
impl GcBind for JSTransformStream {
    fn bind_node(&self, ctx: &ScopedContext, owner: std::ptr::NonNull<zuqe::gc_lite::GcHead>) {
        GcBind::bind_node(self.as_object(), ctx, owner)
    }
}

fn js_transform_stream_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let new_target = cc.this();
    let transformer = cc.arg(0);

    // Use existing readable/writable instances, or create an empty transformer object.
    let transformer = if transformer.is_undefined_or_null() {
        ctx.create_base_object().map(JSValue::from)?
    } else {
        transformer
    };

    // Spec §6.2.4 steps 3-4: a defined readableType/writableType is rejected.
    if let Some(tobj) = transformer.as_object() {
        let readable_type = tobj.get_property_str(ctx, "readableType")?;
        if !readable_type.is_undefined() {
            return Err(ctx.throw_range_error("readableType must be undefined"));
        }
        let writable_type = tobj.get_property_str(ctx, "writableType")?;
        if !writable_type.is_undefined() {
            return Err(ctx.throw_range_error("writableType must be undefined"));
        }
    }

    // Per the WHATWG spec the second/third arguments are the writable and
    // readable queuing strategies respectively.
    let writable_strategy = cc.arg(1);
    let readable_strategy = cc.arg(2);
    // Spec §6.2.4: default writable HWM = 1, readable HWM = 0.
    let writable_hwm = extract_high_water_mark(ctx, writable_strategy, 1.0)?;
    let readable_hwm = extract_high_water_mark(ctx, readable_strategy, 0.0)?;
    // The readable side uses the readable strategy's `size` algorithm; a
    // throwing size() inside start()/transform() errors the stream (spec
    // `CreateReadableStream` -> `SetUpReadableStreamDefaultController`).
    let readable_size = extract_size_algorithm(ctx, readable_strategy)?;
    // The writable side uses the writable strategy's `size` algorithm.
    let writable_size = extract_size_algorithm(ctx, writable_strategy)?;

    // Readable side — created first so the TransformStream can reference it.
    let mut readable =
        JSReadableStream::new_instance(ctx, JSValue::UNDEFINED, ReadableStreamPayload::new())?;
    let mut rc = JSReadableStreamDefaultController::new_instance(
        ctx,
        JSValue::UNDEFINED,
        ReadableControllerPayload::new_default(JSValue::UNDEFINED, Some(readable), readable_hwm),
    )?;
    // Set the controller's self-handle so call_pull can find it.
    let rc_handle = rc;
    rc.set_controller(ctx, Some(rc_handle));
    // Save a typed copy before storing the JSValue in the stream payload.
    let mut rc_typed = rc;
    let readable_owner = JSValue::from(readable);
    readable
        .payload_mut()
        .unwrap()
        .controller
        .set(ctx, readable_owner, Some(rc.into()));

    // Writable side — use the original transformer as the underlying_sink.
    let mut writable =
        JSWritableStream::new_instance(ctx, JSValue::UNDEFINED, WritableStreamPayload::new())?;
    // Self-handle for the write barriers in the payload methods.
    let writable_val = JSValue::from(writable);
    if let Some(sp) = writable.payload_mut() {
        sp.owner = Some(writable_val);
    }
    let wc_payload =
        WritableControllerPayload::new(transformer, Some(writable), writable_hwm, writable_size);
    let wcv = JSWritableStreamDefaultController::new_instance(ctx, JSValue::UNDEFINED, wc_payload)?;
    if let Some(sp) = writable.payload_mut() {
        sp.set_controller(ctx, writable_val, wcv);
    }

    // Capture rc and writable again after mutable borrow
    let mut wc = writable.payload().unwrap().controller.get().unwrap();
    let transformer = if let Some(cp) = wc.payload() {
        cp.underlying_sink.get()
    } else {
        JSValue::UNDEFINED
    };

    // Transform controller — created before the TransformStream instance so we
    // can wire it in.
    let tc = JSTransformStreamDefaultController::new_instance(
        ctx,
        JSValue::UNDEFINED,
        TransformControllerPayload::new(rc_typed, writable, transformer),
    )?;

    // Wire the transform controller into the writable controller.
    let wc_owner = JSValue::from(wc);
    if let Some(wcp) = wc.payload_mut() {
        wcp.set_transform_controller(ctx, wc_owner, tc);
    }

    // Create the TransformStream instance with initial backpressure = true
    // (spec §6.4.1 InitializeTransformStream step 10).
    let instance = JSTransformStream::new_instance(
        ctx,
        new_target,
        TransformStreamPayload {
            readable: Some(readable),
            writable: Some(writable),
            controller: Some(tc),
            backpressure: true,
            backpressure_change_promise: WriteBarrier::new(None),
        },
    )?;

    // Initialize backpressure (spec §6.4.1 step 10). The promise guard slot
    // lives only on the stream payload; the controller keeps just the flag
    // (spec reads the promise through `[[stream]]`).
    {
        let (new_promise, _rr) = Promise::create(ctx)?;
        let mut ts_val = JSValue::from(instance);
        let owner = ts_val;
        if let Some(tsp_mut) = JSTransformStream::payload_mut_of(&mut ts_val) {
            tsp_mut.set_backpressure_change_promise(ctx, owner, new_promise);
        }
        if let Some(ctrl_handle) = instance.payload().and_then(|p| p.controller) {
            let mut ctrl = ctrl_handle;
            if let Some(tcp) = ctrl.payload_mut() {
                tcp.backpressure.set(true);
            }
        }
    }

    // Wire the [[stream]] back-reference on the controller.
    // tc was moved into the payload, so get it back from the instance.
    let mut tc_from_instance = instance.payload().unwrap().controller.unwrap();
    tc_from_instance.set_stream(ctx, instance);

    // Create a wrapper as underlying_sink with a `write` method for the
    // normal writable path (invoke_str_callable finds it).
    {
        let tc_handle = instance.payload().and_then(|p| p.controller).unwrap();
        let mut wrapper = ctx.create_base_object()?;
        let write_fn = ctx.create_native_function_with_data(
            zuqe::Callback::Func(ts_sink_write),
            "tsSinkWrite",
            1,
            0,
            [JSValue::from(tc_handle)].into(),
        )?;
        wrapper.define_property_value_str(
            ctx,
            "write",
            JSValue::from(write_fn),
            zuqe::JS_PROP_C_W_E,
        )?;
        // Copy start/close from the original transformer.
        if let Some(tobj) = transformer.as_object() {
            for method in ["start", "close"] {
                if let Ok(v) = tobj.get_property_str(ctx, method)
                    && !v.is_undefined()
                {
                    wrapper.define_property_value_str(ctx, method, v, zuqe::JS_PROP_C_W_E)?;
                }
            }
        }
        // TransformStreamDefaultSinkAbortAlgorithm (spec §6.4.3): abort
        // propagates via readable.cancel(reason) → transformer.cancel(reason),
        // NOT via transformer.abort().
        {
            let ts_val = JSValue::from(instance);
            let abort_fn = ctx.create_native_function_with_data(
                zuqe::Callback::Func(ts_sink_abort),
                "tsSinkAbort",
                1,
                0,
                [ts_val].into(),
            )?;
            wrapper.define_property_value_str(
                ctx,
                "abort",
                JSValue::from(abort_fn),
                zuqe::JS_PROP_C_W_E,
            )?;
        }
        // Update the writable controller's underlying_sink to be the wrapper.
        let ws_val = JSValue::from(writable);
        if let Some(sp) = JSWritableStream::payload_of(&ws_val)
            && let Some(mut ctrl) = sp.controller.get()
        {
            let ctrl_owner = JSValue::from(ctrl);
            if let Some(wcp) = ctrl.payload_mut() {
                wcp.set_underlying_sink(ctx, ctrl_owner, JSValue::from(wrapper));
            }
        }
    }

    // Wire pull algorithm on the readable controller: TransformStreamDefaultSourcePullAlgorithm
    // (spec §6.4.4). When the readable side needs data, relieve backpressure.
    let pull_fn = {
        let instance_val = JSValue::from(instance);
        ctx.create_native_function_with_data(
            zuqe::Callback::Func(ts_source_pull),
            "tsSourcePull",
            0,
            0,
            [instance_val].into(),
        )?
    };
    // Wire cancel algorithm: TransformStreamDefaultSourceCancelAlgorithm (spec §6.4.4).
    let cancel_fn = {
        let instance_val = JSValue::from(instance);
        ctx.create_native_function_with_data(
            zuqe::Callback::Func(ts_source_cancel),
            "tsSourceCancel",
            1,
            0,
            [instance_val].into(),
        )?
    };
    // Set pull/cancel on the readable controller so they fire on read/cancel.
    rc_typed.set_algorithms(ctx, pull_fn.into(), cancel_fn.into(), readable_size);

    // Call transformer.start(transformController) if present. A throw propagates
    // via `?` so the construction fails and the caller sees the error.
    if let Some(obj) = transformer.as_object()
        && let Ok(start_fn) = obj.get_property_str(ctx, "start")
        && start_fn.is_callable()
        && let Some(ctrl) = instance.payload().and_then(|p| p.controller)
    {
        start_fn.call(ctx, transformer, &[JSValue::from(ctrl)])?;
    }

    // Set started on both readable/writable controllers and trigger pull.
    // The streams were created outside js_readable_stream_constructor /
    // js_writable_stream_constructor so the normal start→pull microtasks
    // were never scheduled.  Use a resolved-promise .then() chain so the
    // init runs as a microtask (oneshot drain, step 1) rather than a
    // polling job (step 2).  Timer-driven tests depend on this ordering:
    // setTimeout(0) queued during construction must fire *after* the
    // constructor finishes setting up both sides.
    {
        let rc_handle = rc;
        let ws_handle = writable;
        let init_fn = ctx.create_native_function_with_data(
            zuqe::Callback::Func(|cx, cc| {
                let rc_val = cc.data(0);
                let ws_val = cc.data(1);
                // Set started on the readable controller and pull if needed.
                if let Some(rcp) = JSReadableStreamDefaultController::payload_of(&rc_val) {
                    rcp.set_started(true);
                    if rcp.should_call_pull(cx)? {
                        rcp.call_pull(cx)?;
                    }
                }
                // Set started on the writable side and advance the queue.
                let mut ws = ws_val;
                if let Some(wsp) = JSWritableStream::payload_mut_of(&mut ws) {
                    wsp.started = true;
                    wsp.advance_queue(cx)?;
                    wsp.try_close(cx)?;
                }
                Ok(JSValue::UNDEFINED)
            }),
            "tsInit",
            0,
            0,
            [JSValue::from(rc_handle), JSValue::from(ws_handle)].into(),
        )?;
        let mut resolved = Promise::from_resolve_value(ctx, JSValue::UNDEFINED)?;
        resolved.perform_then(ctx, JSValue::from(init_fn), JSValue::UNDEFINED)?;
    }

    Ok(instance.into())
}

/// TransformStreamDefaultSinkAbortAlgorithm (spec §6.4.3).
/// Abort propagates by calling transformer.cancel() directly, then
/// erroring the readable side with the cancel reason.
fn ts_sink_abort(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let reason = cc.arg(0);
    let ts_val = cc.data(0);

    let Some(tsp) = JSTransformStream::payload_of(&ts_val) else {
        return Promise::from_resolve_value(ctx, JSValue::UNDEFINED).map(JSValue::from);
    };
    let mut controller = match tsp.controller {
        Some(c) => c,
        None => return Promise::from_resolve_value(ctx, JSValue::UNDEFINED).map(JSValue::from),
    };
    let readable = match tsp.readable {
        Some(r) => r,
        None => return Promise::from_resolve_value(ctx, JSValue::UNDEFINED).map(JSValue::from),
    };

    // If finishPromise is already set, return it.
    if let Some(tcp) = controller.payload()
        && let Some(fp) = tcp.finish_promise()
    {
        return Ok(JSValue::from(fp));
    }

    // Create finishPromise.
    let (finish_promise, _finish_funcs) = Promise::create(ctx)?;
    let owner = JSValue::from(controller);
    if let Some(tcp) = controller.payload_mut() {
        tcp.set_finish_promise(ctx, owner, finish_promise);
    }

    // Call controller.[[cancelAlgorithm]](reason) — i.e. transformer.cancel(reason).
    // Per spec the cancelAlgorithm always returns a promise (a resolved one
    // when the transformer has no cancel method), so the readable side is
    // always errored asynchronously via the .then() chain.
    let cancel_result = if let Some(tcp) = controller.payload()
        && let Some(transformer_obj) = tcp.transformer.get().as_object()
        && let Ok(cancel_fn) = transformer_obj.get_property_str(ctx, "cancel")
        && cancel_fn.is_callable()
    {
        cancel_fn.call(ctx, tcp.transformer.get(), &[reason])
    } else {
        Promise::from_resolve_value(ctx, JSValue::UNDEFINED).map(JSValue::from)
    };

    // React to cancel result.
    match cancel_result {
        Ok(v) => {
            if let Ok(mut cancel_promise) = Promise::try_from(v) {
                // Async: chain .then()
                let on_ok = ctx.create_native_function_with_data(
                    zuqe::Callback::Func(ts_sink_abort_ok),
                    "tsSinkAbortOk",
                    1,
                    0,
                    [JSValue::from(controller), readable.into(), reason].into(),
                )?;
                let on_err = ctx.create_native_function_with_data(
                    zuqe::Callback::Func(ts_sink_abort_err),
                    "tsSinkAbortErr",
                    1,
                    0,
                    [JSValue::from(controller), readable.into()].into(),
                )?;
                cancel_promise.perform_then(ctx, on_ok.into(), on_err.into())?;
            } else {
                // Sync non-promise result: treat as fulfilled.
                ts_sink_abort_fulfill(ctx, &mut controller, readable, reason)?;
            }
        }
        Err(_) => {
            let e = ctx.take_exception().to_value(ctx);
            ts_sink_abort_reject(ctx, &mut controller, readable, e)?;
        }
    }

    if let Some(tcp) = controller.payload()
        && let Some(fp) = tcp.finish_promise()
    {
        return Ok(JSValue::from(fp));
    }

    Ok(JSValue::UNDEFINED)
}

/// Promise reaction: async transformer.cancel() fulfilled (sink abort path).
fn ts_sink_abort_ok(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut controller = JSTransformStreamDefaultController::from_value(cc.data(0))
        .ok_or_else(|| ctx.throw_internal_error("invalid controller"))?;
    let readable = JSReadableStream::from_value(cc.data(1))
        .ok_or_else(|| ctx.throw_internal_error("invalid readable"))?;
    let reason = cc.data(2);
    ts_sink_abort_fulfill(ctx, &mut controller, readable, reason)
}

/// Promise reaction: async transformer.cancel() rejected (sink abort path).
fn ts_sink_abort_err(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut controller = JSTransformStreamDefaultController::from_value(cc.data(0))
        .ok_or_else(|| ctx.throw_internal_error("invalid controller"))?;
    let readable = JSReadableStream::from_value(cc.data(1))
        .ok_or_else(|| ctx.throw_internal_error("invalid readable"))?;
    let error = cc.arg(0);
    ts_sink_abort_reject(ctx, &mut controller, readable, error)
}

/// Fulfilled branch of sink abort: if readable errored → reject
/// finishPromise; otherwise error readable with cancel reason and
/// resolve finishPromise.
fn ts_sink_abort_fulfill(
    ctx: &mut ScopedContext,
    controller: &mut JSTransformStreamDefaultController,
    readable: JSReadableStream,
    reason: JSValue,
) -> JSResult {
    // If readable is errored, reject finishPromise with its storedError.
    if let Some(rp) = readable.payload()
        && rp.state == crate::stream::RsState::Errored
    {
        let error = rp.stored_error.get();
        if let Some(tcp) = controller.payload_mut()
            && let Some(mut fp) = tcp.finish_promise()
        {
            fp.reject(ctx, error);
        }
        return Ok(JSValue::UNDEFINED);
    }

    // Error readable with the cancel reason.
    if let Some(tcp) = controller.payload() {
        let rcv = JSValue::from(tcp.readable_controller.get());
        if let Ok(rcp) = get_readable_controller(ctx, &rcv) {
            rcp.error(ctx, reason)?;
        }
    }
    // Resolve finishPromise.
    if let Some(tcp) = controller.payload_mut()
        && let Some(mut fp) = tcp.finish_promise()
    {
        fp.resolve(ctx, JSValue::UNDEFINED);
    }
    Ok(JSValue::UNDEFINED)
}

/// Rejected branch of sink abort: error readable with rejection reason,
/// reject finishPromise.
fn ts_sink_abort_reject(
    ctx: &mut ScopedContext,
    controller: &mut JSTransformStreamDefaultController,
    readable: JSReadableStream,
    error: JSValue,
) -> JSResult {
    if let Some(tcp) = controller.payload() {
        let rcv = JSValue::from(tcp.readable_controller.get());
        if let Ok(rcp) = get_readable_controller(ctx, &rcv) {
            rcp.error(ctx, error)?;
        }
    }
    if let Some(tcp) = controller.payload_mut()
        && let Some(mut fp) = tcp.finish_promise()
    {
        fp.reject(ctx, error);
    }
    Ok(JSValue::UNDEFINED)
}

/// TransformStreamDefaultSinkWriteAlgorithm (spec §6.4.3).
/// Called by the normal writable path's chain_write_result → sink.write().
fn ts_sink_write(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let chunk = cc.arg(0);
    let tc_handle_val = cc.data(0);

    let Some(tc_handle) = JSTransformStreamDefaultController::try_from(tc_handle_val).ok() else {
        return Ok(JSValue::UNDEFINED);
    };
    let Some(tcp) = tc_handle.payload() else {
        return Ok(JSValue::UNDEFINED);
    };
    let Some(transformer_obj) = tcp.transformer.get().as_object() else {
        return Ok(JSValue::UNDEFINED);
    };

    let has_transform = transformer_obj
        .get_property_str(ctx, "transform")
        .map(|v| v.is_callable())
        .unwrap_or(false);

    // Spec `TransformStreamDefaultSinkWriteAlgorithm` step 3: while backpressured,
    // the transform (identity or explicit) waits for the backpressure change
    // promise before running.
    let backpressured = tcp
        .stream
        .get()
        .and_then(|h| {
            let sv = JSValue::from(h);
            super::transform::JSTransformStream::payload_of(&sv).map(|tsp| tsp.backpressure)
        })
        .unwrap_or(false);

    if backpressured {
        let bp = tcp.stream.get().and_then(|h| {
            let sv = JSValue::from(h);
            super::transform::JSTransformStream::payload_of(&sv)
                .and_then(|tsp| tsp.backpressure_change_promise())
        });
        if let Some(mut bp) = bp {
            let tc_val = JSValue::from(tc_handle);
            let transformer_val = tcp.transformer.get();
            let data: Vec<JSValue> = [transformer_val, tc_val, chunk].into();
            let data_ok = data.clone();
            let data_err = data;
            let on_ok = ctx.create_native_function_with_data(
                zuqe::Callback::Func(ts_perform_transform_cb),
                "tsSinkWriteAfterBP",
                0,
                0,
                data_ok.into(),
            )?;
            let on_err = ctx.create_native_function_with_data(
                zuqe::Callback::Func(|_ctx, _cc| Ok(JSValue::UNDEFINED)),
                "tsSinkWriteAfterBPErr",
                1,
                0,
                data_err.into(),
            )?;
            // The write settles with the transform's own outcome: the wrapper
            // promise rejects when the transform (or a terminated writable)
            // fails, not merely when backpressure clears.
            let wrapper = bp.perform_then(ctx, on_ok.into(), on_err.into())?;
            return Ok(wrapper.into());
        }
    }

    // Not backpressured: perform the transform now.
    let data: Vec<JSValue> = [tcp.transformer.get(), JSValue::from(tc_handle), chunk].into();
    ts_perform_transform_values(ctx, data[0], data[1], data[2])
}

/// `TransformStreamDefaultControllerPerformTransform` (spec §6.4.3): for an
/// identity transformer enqueue the chunk on the readable controller; otherwise
/// invoke `transformer.transform(chunk, controller)`.
fn ts_perform_transform_values(
    ctx: &mut ScopedContext,
    transformer_val: JSValue,
    tc_val: JSValue,
    chunk: JSValue,
) -> JSResult {
    let Some(obj) = transformer_val.as_object() else {
        return Ok(JSValue::UNDEFINED);
    };
    let transform_fn = obj.get_property_str(ctx, "transform")?;
    if transform_fn.is_callable() {
        return transform_fn.call(ctx, transformer_val, &[chunk, tc_val]);
    }
    // Identity transform: forward the chunk to the readable side.
    let enqueue_fn = tc_val.get_property_str(ctx, "enqueue")?;
    enqueue_fn.call(ctx, tc_val, &[chunk])
}

// Backpressure-gated write reaction: run the pending transform.
// `cc.data`: [0] = transformer, [1] = transform controller, [2] = chunk.
fn ts_perform_transform_cb(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let tc_val = cc.data(1);
    // Spec `TransformStreamDefaultSinkWriteAlgorithm` step 3.1.3: once
    // backpressure clears, an erroring writable rejects the pending write with
    // its stored error (e.g. after `controller.terminate()`).
    if let Some(tc_handle) = JSTransformStreamDefaultController::try_from(tc_val).ok()
        && let Some(tcp) = tc_handle.payload()
        && let Some(wsp) = tcp.writable_stream.get().payload()
        && (wsp.state == crate::stream::RsState::Erroring
            || wsp.state == crate::stream::RsState::Errored)
    {
        let e = wsp.stored_error.get();
        ctx.throw(zuqe::Exception::Error(e));
        return Err(-1);
    }
    ts_perform_transform_values(ctx, cc.data(0), cc.data(1), cc.data(2))
}

/// TransformStreamDefaultSourcePullAlgorithm (spec §6.4.4).
/// When the readable side needs data (consumer reads), relieve backpressure.
fn ts_source_pull(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let stream_val = cc.data(0);
    // The stream parameter here is the TransformStream (we passed it as data).
    if JSTransformStream::payload_of(&stream_val).is_some() {
        // Backpressure should be true when pull is called.
        // TransformStreamSetBackpressure(stream, false).
        transform_stream_set_backpressure(ctx, stream_val, false)?;
    }

    // Return the backpressureChangePromise per spec step 3.
    if let Some(tsp) = JSTransformStream::payload_of(&stream_val)
        && let Some(p) = tsp.backpressure_change_promise()
    {
        return Ok(JSValue::from(p));
    }

    Ok(JSValue::UNDEFINED)
}

/// TransformStreamDefaultSourceCancelAlgorithm (spec §6.4.4).
/// When the readable side is cancelled, call transformer.cancel(reason),
/// then error the writable side and unblock any pending write.
fn ts_source_cancel(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let stream_val = cc.data(0);
    let reason = cc.arg(0);

    let Some(tsp) = JSTransformStream::payload_of(&stream_val) else {
        return Ok(JSValue::UNDEFINED);
    };
    let mut controller = match tsp.controller {
        Some(c) => c,
        None => return Ok(JSValue::UNDEFINED),
    };
    let writable = match tsp.writable {
        Some(w) => w,
        None => return Ok(JSValue::UNDEFINED),
    };

    // If finishPromise is already set, return it (idempotent cancel).
    if let Some(tcp) = controller.payload()
        && let Some(fp) = tcp.finish_promise()
    {
        return Ok(JSValue::from(fp));
    }

    // Create finishPromise (spec step 4).
    let (finish_promise, _finish_funcs) = Promise::create(ctx)?;

    // Store finishPromise on the controller.
    let owner = JSValue::from(controller);
    if let Some(tcp) = controller.payload_mut() {
        tcp.set_finish_promise(ctx, owner, finish_promise);
    }

    // Call transformer.cancel(reason) (spec step 5).
    let cancel_result = if let Some(tcp) = controller.payload()
        && let Some(transformer_obj) = tcp.transformer.get().as_object()
        && let Ok(cancel_fn) = transformer_obj.get_property_str(ctx, "cancel")
        && cancel_fn.is_callable()
    {
        cancel_fn.call(ctx, tcp.transformer.get(), &[reason])
    } else {
        Ok(JSValue::UNDEFINED)
    };

    // React to cancel result (spec step 7).
    match cancel_result {
        Ok(v) => {
            // Check if the result is a promise (async cancel).
            if let Ok(mut cancel_promise) = Promise::try_from(v) {
                // Async cancel: chain .then() to react on settlement.
                let on_ok = ctx.create_native_function_with_data(
                    zuqe::Callback::Func(ts_source_cancel_settle),
                    "tsSourceCancelOk",
                    1,
                    0,
                    [stream_val, JSValue::from(controller), reason].into(),
                )?;
                let on_err = ctx.create_native_function_with_data(
                    zuqe::Callback::Func(ts_source_cancel_settle),
                    "tsSourceCancelErr",
                    1,
                    1,
                    [stream_val, JSValue::from(controller), reason].into(),
                )?;
                cancel_promise.perform_then(ctx, on_ok.into(), on_err.into())?;
            } else {
                // Sync cancel (non-promise result): treat as fulfilled.
                ts_cancel_fulfill(ctx, stream_val, &mut controller, writable, reason)?;
            }
        }
        Err(_) => {
            let e = ctx.take_exception().to_value(ctx);
            // Sync throw: reject finishPromise.
            ts_cancel_reject(ctx, stream_val, &mut controller, writable, e)?;
        }
    }

    if let Some(tcp) = controller.payload()
        && let Some(fp) = tcp.finish_promise()
    {
        return Ok(JSValue::from(fp));
    }

    Ok(JSValue::UNDEFINED)
}

/// Fulfilled branch of transformer.cancel() (source cancel path):
/// if writable is errored, reject finishPromise with its stored error;
/// otherwise error writable with the cancel reason, unblock write,
/// and resolve finishPromise.
fn ts_cancel_fulfill(
    ctx: &mut ScopedContext,
    stream_val: JSValue,
    controller: &mut JSTransformStreamDefaultController,
    writable: JSWritableStream,
    reason: JSValue,
) -> JSResult {
    // If writable is already errored, reject finishPromise with its storedError.
    if let Some(wsp) = writable.payload()
        && wsp.state == crate::stream::RsState::Errored
    {
        let error = wsp.stored_error.get();
        if let Some(tcp) = controller.payload_mut()
            && let Some(mut fp) = tcp.finish_promise()
        {
            fp.reject(ctx, error);
        }
        return Ok(JSValue::UNDEFINED);
    }

    // Error the writable with the cancel reason.
    if let Some(wsp) = writable.payload()
        && let Some(mut wc) = wsp.controller.get()
        && let Some(wcp) = wc.payload_mut()
        && let Some(mut ws) = wcp.stream
        && let Some(ws_payload) = ws.payload_mut()
        && ws_payload.state == crate::stream::RsState::Readable
    {
        ws_payload.start_erroring(ctx, reason)?;
    }
    transform_stream_unblock_write(ctx, stream_val)?;
    if let Some(tcp) = controller.payload_mut()
        && let Some(mut fp) = tcp.finish_promise()
    {
        fp.resolve(ctx, JSValue::UNDEFINED);
    }
    Ok(JSValue::UNDEFINED)
}

/// Rejected branch of transformer.cancel(): error writable with the
/// rejection reason, unblock write, reject finishPromise.
fn ts_cancel_reject(
    ctx: &mut ScopedContext,
    stream_val: JSValue,
    controller: &mut JSTransformStreamDefaultController,
    writable: JSWritableStream,
    error: JSValue,
) -> JSResult {
    if let Some(wsp) = writable.payload()
        && let Some(mut wc) = wsp.controller.get()
        && let Some(wcp) = wc.payload_mut()
        && let Some(mut ws) = wcp.stream
        && let Some(ws_payload) = ws.payload_mut()
        && ws_payload.state == crate::stream::RsState::Readable
    {
        ws_payload.start_erroring(ctx, error)?;
    }
    transform_stream_unblock_write(ctx, stream_val)?;
    if let Some(tcp) = controller.payload_mut()
        && let Some(mut fp) = tcp.finish_promise()
    {
        fp.reject(ctx, error);
    }
    Ok(JSValue::UNDEFINED)
}

/// Promise reaction for an async transformer.cancel() result.
/// magic 0 = fulfilled, 1 = rejected (the callback is shared by both paths).
fn ts_source_cancel_settle(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut controller = JSTransformStreamDefaultController::from_value(cc.data(1))
        .ok_or_else(|| ctx.throw_internal_error("invalid controller"))?;

    let writable = if let Some(tcp) = controller.payload() {
        tcp.writable_stream.get()
    } else {
        return Ok(JSValue::UNDEFINED);
    };

    let stream_val = cc.data(0);

    if cc.magic() == 1 {
        let error = cc.arg(0);
        ts_cancel_reject(ctx, stream_val, &mut controller, writable, error)
    } else {
        let reason = cc.data(2);
        ts_cancel_fulfill(ctx, stream_val, &mut controller, writable, reason)
    }
}

/// TransformStreamSetBackpressure (spec §6.4.1).
/// Resolve the old backpressureChangePromise, create a new one, set the flag.
/// Also mirrors the state on the TransformControllerPayload for fast access
/// from the write path.
pub(super) fn transform_stream_set_backpressure(
    ctx: &mut ScopedContext,
    stream_val: JSValue,
    backpressure: bool,
) -> JSResult {
    let Some(tsp) = JSTransformStream::payload_of(&stream_val) else {
        return Ok(JSValue::UNDEFINED);
    };

    // Resolve the OLD promise on the stream payload's guard slot (this is what
    // the fast path in js_writer_write is waiting on).
    let ctrl_handle = tsp.controller;
    if let Some(mut old_bp) = tsp.backpressure_change_promise() {
        old_bp.resolve(ctx, JSValue::UNDEFINED);
    }

    // Create new promise and set it everywhere.
    let (new_promise, _rr) = Promise::create(ctx)?;

    // Set on the TransformStream payload (the single guard slot).
    let Some(ts_handle) = JSTransformStream::from_value(stream_val) else {
        return Ok(JSValue::UNDEFINED);
    };
    let mut ts_val = JSValue::from(ts_handle);

    let owner = ts_val;
    if let Some(tsp_mut) = JSTransformStream::payload_mut_of(&mut ts_val) {
        tsp_mut.backpressure = backpressure;
        tsp_mut.set_backpressure_change_promise(ctx, owner, new_promise);
    }
    // Mirror only the flag on the controller.
    if let Some(mut ctrl) = ctrl_handle
        && let Some(tcp) = ctrl.payload_mut()
    {
        tcp.backpressure.set(backpressure);
    }
    Ok(JSValue::UNDEFINED)
}

/// TransformStreamUnblockWrite (spec §6.4.1).
/// If backpressure is true, set it to false.
pub(super) fn transform_stream_unblock_write(
    ctx: &mut ScopedContext,
    stream_val: JSValue,
) -> JSResult {
    let needs_unblock = JSTransformStream::payload_of(&stream_val)
        .map(|p| p.backpressure)
        .unwrap_or(false);
    if needs_unblock {
        transform_stream_set_backpressure(ctx, stream_val, false)?;
    }
    Ok(JSValue::UNDEFINED)
}

/// TransformStreamErrorWritableAndUnblockWrite (spec §6.4.2).
/// Error the writable side with `e` and relieve backpressure — the step
/// `TransformStreamDefaultControllerEnqueue` runs when the readable side's
/// enqueue (including the strategy's `size` algorithm) throws.
pub(super) fn transform_stream_error_writable_and_unblock_write(
    ctx: &mut ScopedContext,
    stream_val: JSValue,
    e: JSValue,
) -> JSResult {
    if let Some(tsp) = JSTransformStream::payload_of(&stream_val)
        && let Some(w) = tsp.writable
        && let Some(wsp) = w.payload()
        && wsp.state == crate::stream::RsState::Readable
        && let Some(wc) = wsp.controller.get()
        && let Some(wcp) = wc.payload()
        && let Some(mut ws) = wcp.stream
        && let Some(ws_payload) = ws.payload_mut()
    {
        ws_payload.start_erroring(ctx, e)?;
    }
    transform_stream_unblock_write(ctx, stream_val)?;
    Ok(JSValue::UNDEFINED)
}

fn js_transform_stream_readable(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSTransformStream::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("not a TransformStream"))?;
    Ok(p.readable.map_or(JSValue::UNDEFINED, JSValue::from))
}

fn js_transform_stream_writable(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSTransformStream::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("not a TransformStream"))?;
    Ok(p.writable.map_or(JSValue::UNDEFINED, JSValue::from))
}

#[cfg(all(test, debug_assertions))]
mod gc_barrier_tests {
    use zuqe::{
        Context, EvalFlags, EvalName, EvalType, JSValue, NativeObject, Runtime, ScopedContext,
    };

    use super::JSTransformStream;

    #[test]
    fn backpressure_change_promise_write_barrier_survives_a_minor() -> Result<(), i32> {
        let mut rt = Runtime::create()?;
        let mut ctx: Context<'static> = rt.create_context(ScopedContext::ECMA_CONTEXT_SETUP)?;

        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            let global = cx.global_obj();
            crate::init_whatwg(&mut cx, global)?;
            // Writable HWM 1 + chunk size 1 => desiredSize becomes 0 on write, triggering backpressure.
            cx.eval(
                b"globalThis.__ts = new TransformStream({}, {}, { highWaterMark: 1, size: () => 1 });\n\
                  globalThis.__writer = globalThis.__ts.writable.getWriter();",
                &EvalName::Name("ts-bp-barrier-setup".to_string()),
                EvalType::Global,
                EvalFlags::empty(),
            )?;
            Ok(())
        })?;

        // Promote the stream (and controller copies) to old generation.
        let _ = rt.gc_minor_now();

        // Trigger backpressure change after the stream is old: stores a young promise.
        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            cx.eval(
                b"globalThis.__writer.write('x');",
                &EvalName::Name("ts-bp-barrier-write".to_string()),
                EvalType::Global,
                EvalFlags::empty(),
            )?;
            Ok(())
        })?;

        // A minor GC must not reclaim the young backpressure promise still referenced by the old stream.
        let _ = rt.gc_minor_now();

        // Stream/controller-side promise slots must remain consistent and usable.
        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            let ts_v = cx.eval(
                b"globalThis.__ts",
                &EvalName::Name("ts-bp-barrier-read".to_string()),
                EvalType::Global,
                EvalFlags::empty(),
            )?;
            let ts = JSTransformStream::from_value(ts_v).ok_or(-1)?;
            let tsp = ts.payload().ok_or(-1)?;
            let stream_p = tsp.backpressure_change_promise().ok_or(-1)?;
            // The controller holds no separate slot: it reads the promise
            // through `[[stream]]`. Just assert the stream slot still holds the
            // young promise after the minor.
            assert!(!JSValue::from(stream_p).is_undefined());

            // writer.ready must still be usable (resolves once backpressure clears).
            cx.eval(
                b"globalThis.__reader = globalThis.__ts.readable.getReader();\n\
                  globalThis.__reader.read();",
                &EvalName::Name("ts-bp-barrier-drain".to_string()),
                EvalType::Global,
                EvalFlags::empty(),
            )?;
            Ok(())
        })?;

        rt.tick();
        let _ = rt.gc_minor_now();
        Ok(())
    }
}
