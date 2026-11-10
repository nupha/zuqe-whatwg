// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WHATWG Streams standard implementation.
//!
//! Implements ReadableStream, WritableStream, TransformStream and related
//! classes per the [WHATWG Streams specification](https://streams.spec.whatwg.org/).
//!
//! Split one class per file, named after the class in snake case. Shared items
//! (stream state, queue entry, pending-read slot, queuing strategies) live here.

mod pipe;
mod readable;
mod readable_byob_request;
mod readable_controller;
mod readable_controller_byte;
mod readable_controller_default;
mod readable_tee;
mod reader;
mod transform;
mod transform_controller;
mod writable;
mod writable_controller;
mod writer;

pub(crate) use {
    readable::{
        ChannelStreamState, JSReadableStream, ReadableStreamPayload, init_readable_stream_statics,
    },
    readable_byob_request::JSReadableStreamBYOBRequest,
    readable_controller::ReadableControllerPayload,
    readable_controller_byte::JSReadableByteStreamController,
    readable_controller_default::JSReadableStreamDefaultController,
    readable_tee::TeeStreamState,
    reader::JSReadableStreamDefaultReader,
    transform::JSTransformStream,
    transform_controller::JSTransformStreamDefaultController,
    writable::JSWritableStream,
    writable_controller::JSWritableStreamDefaultController,
    writer::JSWritableStreamDefaultWriter,
};

use zuqe::{
    CallContext, ClassCtorDef, FieldDef, GcBind, IntOrFloat, JSResult, JSValue, ScopedContext,
    builtins::promise::{Promise, PromiseState},
    def_native_object,
    gc_lite::GcTrace,
};

#[derive(Clone, Copy, PartialEq, GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) enum RsState {
    Readable,
    /// The stream is erroring (per the Streams spec): `stored_error` is set and
    /// the writer's `ready` has been rejected, but queued writes/close are only
    /// settled once the in-flight operation finishes (`finish_erroring`).
    Erroring,
    Closed,
    Errored,
}

#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct QueueEntry {
    pub(crate) chunk: JSValue,
    /// Strategy `size` of the chunk (default 1); can be fractional or large, so
    /// stored as f64.
    pub(crate) size: f64,
}

/// Bind only `chunk`: `size` is an `f64`, not a GC leaf.
impl GcBind for QueueEntry {
    fn bind_node(&self, ctx: &ScopedContext, owner: std::ptr::NonNull<zuqe::gc_lite::GcHead>) {
        self.chunk.bind_node(ctx, owner);
    }
}

// ============================================================================
// ByteLengthQueuingStrategy
// ============================================================================

const BYTE_LENGTH_QUEUING_STRATEGY_PROTO: &[FieldDef] = &[
    FieldDef::FUNC_ENUM("size", 1, js_byte_length_size, 0),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "ByteLengthQueuingStrategy",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "ByteLengthQueuingStrategy",
    JSByteLengthQueuingStrategy,
    (),
    BYTE_LENGTH_QUEUING_STRATEGY_PROTO,
    Some(ClassCtorDef::new(js_byte_length_constructor, 1, false).expose_to_global())
);

fn js_byte_length_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let new_target = cc.this();
    let init_val = cc.arg(0);

    let mut instance = JSByteLengthQueuingStrategy::new_instance(ctx, new_target)?;
    let obj = queuing_strategy_init(ctx, init_val)?;

    let hwm = obj.get_property_str(ctx, "highWaterMark")?;
    if hwm.is_undefined() {
        return Err(ctx.throw_type_error("highWaterMark is required"));
    }
    let num = hwm.to_number(ctx)?.to_f64();
    instance.define_property_value_str(
        ctx,
        "highWaterMark",
        JSValue::from(num),
        zuqe::JS_PROP_C_W_E,
    )?;
    Ok(instance.into())
}

/// WebIDL `QueuingStrategy` dict init: must be a (non-null) object.
/// Returns the init object, or throws TypeError for undefined/null/non-object.
fn queuing_strategy_init(ctx: &mut ScopedContext, init_val: JSValue) -> Result<zuqe::Object, i32> {
    if init_val.is_undefined() || init_val.is_null() || init_val.as_object().is_none() {
        return Err(ctx.throw_type_error("QueuingStrategy requires an object init"));
    }
    init_val
        .as_object()
        .ok_or_else(|| ctx.throw_type_error("QueuingStrategy requires an object init"))
}

/// Extract `highWaterMark` from a `QueuingStrategy`-like init object.
/// Per the WHATWG Streams spec the default value is 1 when the field is
/// missing or the strategy is undefined, so callers that pass `undefined`
/// get `Ok(1.0)`. A non-object strategy still throws TypeError via
/// `queuing_strategy_init`.
///
/// Validates the strategy as the spec requires:
/// - `size`, when present, must be a callable; otherwise a TypeError is thrown.
/// - `highWaterMark`, when present, must be a non-NaN, non-negative number;
///   otherwise a RangeError is thrown. Infinity and fractional values are
///   legal (`ExtractHighWaterMark` only rejects NaN and negatives).
pub(crate) fn extract_high_water_mark(
    ctx: &mut ScopedContext,
    strategy: JSValue,
    default_hwm: f64,
) -> Result<f64, i32> {
    if strategy.is_undefined() || strategy.is_null() {
        return Ok(default_hwm);
    }
    let obj = queuing_strategy_init(ctx, strategy)?;
    // `size` must be a function when provided.
    let size = obj.get_property_str(ctx, "size")?;
    if !size.is_undefined() && !size.is_callable() {
        return Err(ctx.throw_type_error("QueuingStrategy.size must be a function"));
    }
    let hwm = obj.get_property_str(ctx, "highWaterMark")?;
    if hwm.is_undefined() {
        return Ok(default_hwm);
    }
    let hwm = match hwm.to_number(ctx)? {
        IntOrFloat::Int64(i) => i as f64,
        IntOrFloat::Float64(f) => f,
    };
    if hwm.is_nan() || hwm < 0.0 {
        return Err(ctx.throw_range_error("highWaterMark must be a non-negative number"));
    }
    Ok(hwm)
}

/// Extract the `size` algorithm from a `QueuingStrategy`-like init object.
/// Returns `undefined` when the strategy is null/undefined or has no `size`
/// member (the default chunk size is then 1.0). A present but non-callable
/// `size` throws TypeError. This mirrors `ExtractSizeAlgorithm` in the spec.
pub(crate) fn extract_size_algorithm(
    ctx: &mut ScopedContext,
    strategy: JSValue,
) -> Result<JSValue, i32> {
    if strategy.is_undefined() || strategy.is_null() {
        return Ok(JSValue::UNDEFINED);
    }
    let obj = queuing_strategy_init(ctx, strategy)?;
    let size = obj.get_property_str(ctx, "size")?;
    if size.is_undefined() {
        return Ok(JSValue::UNDEFINED);
    }
    if size.is_callable() {
        Ok(size)
    } else {
        Err(ctx.throw_type_error("QueuingStrategy.size must be a function"))
    }
}

// ============================================================================
// CountQueuingStrategy
// ============================================================================

const COUNT_QUEUING_STRATEGY_PROTO: &[FieldDef] = &[
    FieldDef::FUNC_ENUM("size", 0, js_count_size, 0),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "CountQueuingStrategy",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "CountQueuingStrategy",
    JSCountQueuingStrategy,
    (),
    COUNT_QUEUING_STRATEGY_PROTO,
    Some(ClassCtorDef::new(js_count_constructor, 1, false).expose_to_global())
);

fn js_count_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let new_target = cc.this();
    let init_val = cc.arg(0);
    let mut instance = JSCountQueuingStrategy::new_instance(ctx, new_target)?;
    let obj = queuing_strategy_init(ctx, init_val)?;
    let hwm = obj.get_property_str(ctx, "highWaterMark")?;
    if hwm.is_undefined() {
        return Err(ctx.throw_type_error("highWaterMark is required"));
    }
    let num = hwm.to_number(ctx)?.to_f64();
    instance.define_property_value_str(
        ctx,
        "highWaterMark",
        JSValue::from(num),
        zuqe::JS_PROP_C_W_E,
    )?;
    Ok(instance.into())
}

fn js_byte_length_size(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let chunk = cc.arg(0);
    if chunk.is_undefined() || chunk.is_null() {
        return Err(ctx.throw_type_error("chunk is required"));
    }
    let Some(obj) = chunk.as_object() else {
        return Ok(JSValue::UNDEFINED);
    };
    let atom = zuqe::Atom::intern_static(ctx, "byteLength")?;
    if !obj.has_property(ctx, atom)? {
        return Ok(JSValue::UNDEFINED);
    }
    obj.get_property(ctx, atom)
}

fn js_count_size(_ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    Ok(JSValue::from(1))
}

pub(crate) fn make_iterator_result(
    ctx: &mut ScopedContext,
    value: JSValue,
    done: bool,
) -> Result<JSValue, i32> {
    let mut obj = ctx.create_base_object()?;
    obj.define_property_value_str(ctx, "value", value, zuqe::JS_PROP_C_W_E)?;
    obj.define_property_value_str(ctx, "done", JSValue::from(done), zuqe::JS_PROP_C_W_E)?;
    Ok(JSValue::from(obj))
}

/// Build a fresh promise settled directly with an iterator result `{value, done}`.
///
/// Settles without thenable assimilation so an injected `Object.prototype.then`
/// cannot intercept the read result (WPT `then-interception`), while keeping the
/// result object structurally clean (`Object.getOwnPropertyNames` == `[done, value]`).
pub(crate) fn iterator_result_promise(
    ctx: &mut ScopedContext,
    value: JSValue,
    done: bool,
) -> Result<Promise, i32> {
    let result = make_iterator_result(ctx, value, done)?;
    let (mut promise, _rr) = Promise::create(ctx)?;
    promise.resolve(ctx, result);
    Ok(promise)
}

/// Resolve or reject the peer (reader/writer) `closed_promise` if present.
///
/// The `closed_promise` is kept in place so `reader.closed` / `writer.closed`
/// keeps returning a valid promise; it is settled only while still Pending.
/// `Promise::settle` must not run on an already-settled promise (debug_assert),
/// and fetch body teardown can call `settle_state` repeatedly (error then
/// cancel) against the same reader.
///
/// Per WHATWG, the reader/writer's `closed` promise must have
/// `[[PromiseIsHandled]] = true` set after rejection to avoid unhandled
/// rejection reports. We mark it handled by attaching a no-op `.catch()`.
pub(super) fn notify_peer_closed(
    ctx: &mut ScopedContext,
    peer: Option<JSValue>,
    reason: Option<JSValue>,
) {
    let Some(mut pv) = peer else {
        return;
    };

    let noop = ctx
        .create_native_function(
            zuqe::Callback::Func(|_, _| Ok(JSValue::UNDEFINED)),
            "closedPromiseNoop",
            0,
            0,
        )
        .map(JSValue::from)
        .unwrap_or(JSValue::UNDEFINED);

    let mut settle = |cp: &mut Promise| {
        // Only settle a still-pending promise; repeated teardown calls no-op.
        if cp.state() != PromiseState::Pending {
            return;
        }
        if let Some(r) = reason {
            cp.reject(ctx, r);
            // Mark `[[PromiseIsHandled]] = true` so the host rejection
            // tracker does not flag this as an unhandled rejection.
            let _ = cp.perform_then(ctx, noop, noop);
        } else {
            cp.resolve(ctx, JSValue::UNDEFINED);
        }
    };

    if let Some(rp) = JSReadableStreamDefaultReader::payload_mut_of(&mut pv) {
        // The guard slot holds the promise; settle a `get()` copy (settle
        // mutates through the handle, so the copy is equivalent).
        if let Some(mut cp) = rp.closed_promise.get() {
            settle(&mut cp);
        }
    } else if let Some(wp) = JSWritableStreamDefaultWriter::payload_mut_of(&mut pv) {
        if let Some(mut cp) = wp.closed_promise.get() {
            settle(&mut cp);
        }

        // When the stream is errored/aborted (a `reason` is present), any
        // outstanding `write()` promise must also reject with that reason
        // (spec: outstanding write() promises reject). The writer's `ready` is
        // handled by `WritableStreamPayload::start_erroring` instead.
        if reason.is_some()
            && let Some(mut wp_promise) = wp.write_promise.get()
            && wp_promise.state() == PromiseState::Pending
        {
            wp_promise.reject(ctx, reason.unwrap());
        }
    }
}
