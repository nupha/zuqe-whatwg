// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! ReadableStream `tee()`: split one source into two branches that both receive
//! every chunk. Shared on-demand pull state and the pump callbacks live here.

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
};

use zuqe::{
    Array, CallContext, Callback, JSResult, JSValue, NativeObject, ScopedContext,
    builtins::{promise::Promise, typed_array::TypedArray},
    gc_lite::{GcTrace, GcTraceCtx},
};

use crate::aike::AikeRuntimeState;

use super::{
    JSReadableByteStreamController, JSReadableStream, JSReadableStreamDefaultController,
    ReadableControllerPayload, ReadableStreamPayload, RsState,
    reader::JSReadableStreamDefaultReader,
};

/// Shared state for a `tee()` split: one source reader feeding two branch
/// controllers on demand. `pulling` guards against concurrent pulls from both
/// branches; `done` stops pulling once the source finishes.
/// This struct lives in `AikeRuntimeState::tee_streams` (root container);
/// writes to `cancel_reason1/2`/`cancel_promise` do not require a write barrier
/// as long as it remains rooted there. If moved out of the runtime root in the
/// future, add barriers/guards accordingly.
#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct TeeShared {
    reader: JSReadableStreamDefaultReader,
    c1: JSValue,
    c2: JSValue,
    is_byte_stream: bool,
    pulling: Cell<bool>,
    done: Cell<bool>,
    /// Branch cancel tracking (per spec the source is only cancelled once both
    /// branches are cancelled). Every branch cancel returns the shared
    /// `cancel_promise`, which settles only when the underlying source cancel
    /// completes — so a pipeTo abort on one branch waits for the other branch.
    cancel1: Cell<bool>,
    cancel2: Cell<bool>,
    cancel_started: Cell<bool>,
    /// Per-branch cancel reasons (indexed by branch). The composite reason is
    /// `[reason1, reason2]` in branch order (a single reason if both agree).
    cancel_reason1: RefCell<Option<JSValue>>,
    cancel_reason2: RefCell<Option<JSValue>>,
    cancel_promise: RefCell<Option<Promise>>,
}

/// Per-runtime active `tee()` splits, stored on `AikeRuntimeState`.
#[derive(Default, GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct TeeStreamState {
    pub(crate) streams: HashMap<u32, Rc<TeeShared>>,
    /// Ids start at 1 (0 is not a valid tee id).
    pub(crate) next_id: u32,
}

impl TeeStreamState {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

impl JSReadableStreamDefaultReader {
    /// Tee this reader's stream into two branches.
    ///
    /// Consumes the source reader's `closed` rejection (created by getReader)
    /// so an errored source does not leak an unhandled rejection from this
    /// internal reader, then builds two branch streams each driven by the
    /// shared on-demand tee pull, registers the shared state, and returns the
    /// two branch streams.
    pub(crate) fn tee(&mut self, ctx: &mut ScopedContext) -> Result<[JSReadableStream; 2], i32> {
        // Consume the source reader's `closed` rejection (created by getReader) so an
        // errored source does not leak an unhandled rejection from this internal reader.
        if let Some(mut closed_p) = self.payload_mut().and_then(|p| p.closed_promise.get()) {
            let noop = ctx
                .create_native_function(
                    zuqe::Callback::Func(|_, _| Ok(JSValue::UNDEFINED)),
                    "teeIgnore",
                    0,
                    0,
                )?
                .into();
            closed_p.perform_then(ctx, noop, noop)?;
        }

        // Each branch's underlying source `pull` is the shared on-demand tee pull,
        // keyed by a tee id that resolves to the shared state (source reader + both
        // branch controllers). Pull only fires when a branch actually needs data, so
        // an infinite source is never drained unless a branch asks for it.
        let tee_id = {
            let st = AikeRuntimeState::of(ctx);
            let id = st.tee_streams.next_id;
            st.tee_streams.next_id = id + 1;
            id
        };

        // Check if the source stream is a byte stream so branches use
        // byte controllers when needed (WHATWG: tee branches mirror source type).
        let is_byte_stream = self
            .payload()
            .and_then(|p| {
                let s = p.stream?;
                let sp = s.payload()?;
                Some(sp.is_byte_stream)
            })
            .unwrap_or(false);

        // Create two branch streams, each with its own controller whose
        // underlying-source pull drives the shared tee pull.
        let make_branch =
            |ctx: &mut ScopedContext, branch: u32| -> Result<(JSReadableStream, JSValue), i32> {
                let pull_fn = ctx
                    .create_native_function_with_data(
                        Callback::Func(tee_pull),
                        "teePull",
                        1,
                        0,
                        [JSValue::from(tee_id)].into(),
                    )?
                    .into();
                let cancel_fn = ctx
                    .create_native_function_with_data(
                        Callback::Func(tee_cancel),
                        "teeCancel",
                        1,
                        0,
                        [JSValue::from(tee_id), JSValue::from(branch)].into(),
                    )?
                    .into();
                let mut source = ctx.create_base_object()?;
                source.define_property_value_str(ctx, "pull", pull_fn, zuqe::JS_PROP_C_W_E)?;
                source.define_property_value_str(ctx, "cancel", cancel_fn, zuqe::JS_PROP_C_W_E)?;

                let mut stream2 = JSReadableStream::new_instance(
                    ctx,
                    JSValue::UNDEFINED,
                    ReadableStreamPayload::new(),
                )?;

                let controller_js: JSValue = if is_byte_stream {
                    stream2.payload_mut().unwrap().is_byte_stream = true;
                    let mut bc = JSReadableByteStreamController::new_instance(
                        ctx,
                        JSValue::UNDEFINED,
                        ReadableControllerPayload::new_byte(
                            JSValue::from(source),
                            Some(stream2),
                            1.0,
                            0,
                        ),
                    )?;
                    bc.set_algorithms(ctx, pull_fn, cancel_fn, JSValue::UNDEFINED);
                    let bc_val: JSValue = bc.into();
                    let stream2_owner = JSValue::from(stream2);
                    stream2
                        .payload_mut()
                        .unwrap()
                        .controller
                        .set(ctx, stream2_owner, Some(bc_val));
                    // Set byte self-handle for call_pull.
                    bc.set_byte_self_handle(ctx);
                    bc_val
                } else {
                    let mut controller = JSReadableStreamDefaultController::new_instance(
                        ctx,
                        JSValue::UNDEFINED,
                        ReadableControllerPayload::new_default(
                            JSValue::from(source),
                            Some(stream2),
                            1.0,
                        ),
                    )?;
                    let handle = controller;
                    controller.set_controller(ctx, Some(handle));
                    controller.set_algorithms(ctx, pull_fn, cancel_fn, JSValue::UNDEFINED);
                    controller
                        .payload_mut()
                        .ok_or_else(|| ctx.throw_internal_error("invalid controller"))?
                        .set_in_tee(true);
                    let cv: JSValue = controller.into();
                    let stream2_owner = JSValue::from(stream2);
                    stream2
                        .payload_mut()
                        .unwrap()
                        .controller
                        .set(ctx, stream2_owner, Some(cv));
                    cv
                };

                Ok((stream2, controller_js))
            };

        let (b1, c1) = make_branch(ctx, 0)?;
        let (b2, c2) = make_branch(ctx, 1)?;

        let cancel_promise = Promise::create(ctx)?.0;
        let shared = Rc::new(TeeShared {
            reader: *self,
            c1,
            c2,
            is_byte_stream,
            pulling: Cell::new(false),
            done: Cell::new(false),
            cancel1: Cell::new(false),
            cancel2: Cell::new(false),
            cancel_started: Cell::new(false),
            cancel_reason1: RefCell::new(None),
            cancel_reason2: RefCell::new(None),
            cancel_promise: RefCell::new(Some(cancel_promise)),
        });
        AikeRuntimeState::of(ctx)
            .tee_streams
            .streams
            .insert(tee_id, shared);

        Ok([b1, b2])
    }
}

// Branch cancel: per the spec, cancelling one tee branch must not cancel the
// underlying source (or settle the cancel promise) until the *other* branch is
// also cancelled. Both branches return the same shared promise, which resolves
// once the real source cancel completes. This is what makes a pipeTo abort on
// one branch wait for the sibling branch.
fn tee_cancel(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let tee_id = cc.data(0).to_number(ctx)?.to_u32();
    let branch = cc.data(1).to_number(ctx)?.to_u32();
    let reason = cc.arg(0);
    let shared = AikeRuntimeState::of(ctx)
        .tee_streams
        .streams
        .get(&tee_id)
        .cloned();
    let Some(shared) = shared else {
        return Ok(JSValue::UNDEFINED);
    };

    if branch == 0 {
        shared.cancel1.set(true);
        *shared.cancel_reason1.borrow_mut() = Some(reason);
    } else {
        shared.cancel2.set(true);
        *shared.cancel_reason2.borrow_mut() = Some(reason);
    }

    if shared.cancel1.get() && shared.cancel2.get() && !shared.cancel_started.get() {
        shared.cancel_started.set(true);
        let r1 = shared.cancel_reason1.borrow().unwrap();
        let r2 = shared.cancel_reason2.borrow().unwrap();
        // Composite reason: the single reason if both branches agree
        // (SameValue), else [reason1, reason2] in branch order (spec: the
        // composite reason is an array, in this case of the two cancel reasons).
        let composite = if r1 == r2 {
            r1
        } else {
            let arr = Array::from_values(ctx, vec![r1, r2])?;
            JSValue::from(arr)
        };
        // Cancel the real source (via the tee reader); mirror its settlement
        // into the shared cancel promise both branches already returned.
        let reader = shared.reader;
        let mut src_cancel = reader
            .payload()
            .ok_or_else(|| ctx.throw_internal_error("tee reader released"))?
            .cancel(ctx, composite)?;
        let promise_val = JSValue::from(shared.cancel_promise.borrow().unwrap());
        let ok_fn = ctx
            .create_native_function_with_data(
                Callback::Func(tee_cancel_settle),
                "teeCancelOk",
                0,
                0,
                [promise_val].into(),
            )?
            .into();
        let err_fn = ctx
            .create_native_function_with_data(
                Callback::Func(tee_cancel_settle),
                "teeCancelErr",
                1,
                1,
                [promise_val].into(),
            )?
            .into();
        src_cancel.perform_then(ctx, ok_fn, err_fn)?;
    }

    match shared.cancel_promise.borrow().as_ref() {
        Some(p) => Ok(JSValue::from(*p)),
        None => Ok(JSValue::UNDEFINED),
    }
}

// Mirror the source-cancel settlement into the shared branch cancel promise.
// magic 0 = fulfillment, 1 = rejection (the callback is shared by both paths).
fn tee_cancel_settle(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut p = match Promise::try_from(cc.data(0)) {
        Ok(p) => p,
        Err(_) => return Ok(JSValue::UNDEFINED),
    };
    if cc.magic() == 1 {
        p.reject(ctx, cc.arg(0));
    } else {
        p.resolve(ctx, JSValue::UNDEFINED);
    }
    Ok(JSValue::UNDEFINED)
}

// ReadableStream.prototype.tee()
// ============================================================================
// Returns [branch1, branch2], two ReadableStreams that both receive every chunk
// of `this`. The source is locked with a default reader, and a read-ahead pump
// pulls chunks and enqueues them into both branches; source error propagates to
// both; source close closes both.
//
// Callback `data` layout for the tee pump:
//   [0] = source reader, [1] = reader.read(), [2] = branch1 controller,
//   [3] = branch2 controller
pub(crate) fn js_readable_stream_tee(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let mut stream = JSReadableStream::from_value(this)
        .ok_or_else(|| ctx.throw_type_error("not a ReadableStream"))?;

    let mut reader = stream.acquire_reader(ctx, false)?;

    // `tee` returns the two branch streams directly.
    let branches = reader.tee(ctx)?;

    // The branches are exposed in a new array.
    Array::from_values(ctx, vec![branches[0].into(), branches[1].into()]).map(JSValue::from)
}

// On-demand tee pull: driven by a branch controller's `pull` (fired only when a
// branch read needs data). Fetches at most one source chunk and enqueues it into
// both live branches. A shared `pulling` guard prevents concurrent pulls from
// both branches; a shared `done` stops pulling after the source finishes.
fn tee_pull(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let tee_id = cc.data(0).to_number(ctx)?.to_u32();
    let shared = AikeRuntimeState::of(ctx)
        .tee_streams
        .streams
        .get(&tee_id)
        .cloned();
    let Some(shared) = shared else {
        return Ok(JSValue::UNDEFINED);
    };
    tee_do_pull(ctx, tee_id, &shared)
}

// Source read -> {done, value}: enqueue into both live branches and clear the
// pulling guard. Close both when the source is done.
fn tee_pull_fulfilled(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let tee_id = cc.data(0).to_number(ctx)?.to_u32();
    let shared = AikeRuntimeState::of(ctx)
        .tee_streams
        .streams
        .get(&tee_id)
        .cloned();
    let Some(shared) = shared else {
        return Ok(JSValue::UNDEFINED);
    };
    shared.pulling.set(false);
    let result = cc.arg(0);
    let done = result
        .get_property_str(ctx, "done")?
        .to_bool()
        .unwrap_or(false);
    if done {
        shared.done.set(true);
        for c in [shared.c1, shared.c2] {
            if !tee_branch_is_final(ctx, c)
                && let Some(cp) = get_controller_payload_from_val(&c)
            {
                cp.close(ctx)?;
            }
        }
        AikeRuntimeState::of(ctx)
            .tee_streams
            .streams
            .remove(&tee_id);
        return Ok(JSValue::UNDEFINED);
    }

    let value = result.get_property_str(ctx, "value")?;
    for (i, c) in [shared.c1, shared.c2].into_iter().enumerate() {
        if !tee_branch_is_final(ctx, c) {
            // WHATWG: branch1 receives the original chunk and branch2 a
            // structured clone of it. For byte streams the copy is a fresh
            // buffer because each `enqueue` transfers (detaches) the chunk it
            // is given, so handing the same view to both branches would leave
            // the second one empty.
            let v = if shared.is_byte_stream {
                clone_byte_chunk(ctx, value)?
            } else if i == 1 {
                structured_clone(ctx, value)?
            } else {
                value
            };
            c.invoke_str(ctx, "enqueue", &[v])?;
        }
    }

    // If a branch still wants data (a pending read, or an empty queue below the
    // high water mark per `ShouldCallPull`), keep pulling the source — this is
    // what surfaces a source error after the buffered chunks are consumed.
    let need_more = [shared.c1, shared.c2].iter().any(|&c| {
        if tee_branch_is_final(ctx, c) {
            return false;
        }
        match get_controller_payload_from_val(&c) {
            Some(cp) if !cp.pending_read().borrow().is_empty() => true,
            Some(cp) => cp.should_call_pull(ctx).unwrap_or(false),
            None => false,
        }
    });

    if need_more {
        let id = tee_id;
        // Follow up as a promise reaction (not a polling job, which runs after
        // later await continuations): the source error must surface and error
        // the branches *before* a branch can drain a buffered chunk.
        let (mut ready, _rr) = Promise::create(ctx)?;
        let data = [JSValue::from(id)].into();
        let follow = ctx
            .create_native_function_with_data(
                Callback::Func(tee_pull_continue),
                "teePullMore",
                0,
                0,
                data,
            )?
            .into();
        ready.resolve(ctx, JSValue::UNDEFINED);
        ready.perform_then(ctx, follow, follow)?;
    }

    Ok(JSValue::UNDEFINED)
}

// Continue the shared tee pull (scheduled as a promise reaction after a chunk
// was fanned out, when a branch still wants data).
fn tee_pull_continue(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let tee_id = cc.data(0).to_number(ctx)?.to_u32();
    if let Some(shared) = AikeRuntimeState::of(ctx)
        .tee_streams
        .streams
        .get(&tee_id)
        .cloned()
    {
        tee_do_pull(ctx, tee_id, &shared)?;
    }
    Ok(JSValue::UNDEFINED)
}

// Perform the shared pull: read one source chunk and fan it out to both branches.
fn tee_do_pull(ctx: &mut ScopedContext, tee_id: u32, shared: &TeeShared) -> JSResult {
    if shared.pulling.get() || shared.done.get() {
        return Ok(JSValue::UNDEFINED);
    }
    // If the source is already errored, error both branches
    // immediately (synchronously) so pending reads reject before
    // any data can be dequeued.
    {
        let reader = shared.reader;
        if let Some(p) = reader.payload()
            && let Some(stream) = p.stream
            && let Some(sp) = stream.payload()
            && sp.state == RsState::Errored
        {
            shared.done.set(true);
            let reason = sp.stored_error.get();
            for c in [shared.c1, shared.c2] {
                if !tee_branch_is_final(ctx, c) {
                    c.invoke_str(ctx, "error", &[reason])?;
                }
            }
            AikeRuntimeState::of(ctx)
                .tee_streams
                .streams
                .remove(&tee_id);
            return Ok(JSValue::UNDEFINED);
        }
    }
    shared.pulling.set(true);

    let p = shared.reader.payload().unwrap();
    let mut promise = p.read(ctx, None, 1)?;

    let step = ctx
        .create_native_function_with_data(
            Callback::Func(tee_pull_fulfilled),
            "teePullOk",
            1,
            0,
            [JSValue::from(tee_id)].into(),
        )?
        .into();
    let fail = ctx
        .create_native_function_with_data(
            Callback::Func(tee_pull_rejected),
            "teePullErr",
            1,
            0,
            [JSValue::from(tee_id)].into(),
        )?
        .into();
    promise.perform_then(ctx, step, fail)?;

    Ok(JSValue::UNDEFINED)
}

// Source read rejected: error both branches and clear the pulling guard.
fn tee_pull_rejected(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let tee_id = cc.data(0).to_number(ctx)?.to_u32();
    let shared = AikeRuntimeState::of(ctx)
        .tee_streams
        .streams
        .get(&tee_id)
        .cloned();
    let Some(shared) = shared else {
        return Ok(JSValue::UNDEFINED);
    };
    shared.pulling.set(false);
    shared.done.set(true);
    let reason = cc.arg(0);
    for c in [shared.c1, shared.c2] {
        if !tee_branch_is_final(ctx, c) {
            c.invoke_str(ctx, "error", &[reason])?;
        }
    }
    AikeRuntimeState::of(ctx)
        .tee_streams
        .streams
        .remove(&tee_id);
    Ok(JSValue::UNDEFINED)
}

// A branch controller is "final" (errored or closed): skip enqueue/close/error.
pub(crate) fn tee_branch_is_final(_ctx: &mut ScopedContext, c: JSValue) -> bool {
    let Some(cp) = get_controller_payload_from_val(&c) else {
        return true;
    };
    let Some(s) = cp.stream() else {
        return true;
    };
    let Some(sp) = s.payload() else {
        return true;
    };
    matches!(sp.state, RsState::Errored | RsState::Closed)
}

/// Extract the shared `ReadableControllerPayload` from a controller JSValue
/// regardless of whether it's a default or byte controller.
fn get_controller_payload_from_val(c: &JSValue) -> Option<&ReadableControllerPayload> {
    if let Some(cp) = JSReadableStreamDefaultController::payload_of(c) {
        return Some(cp);
    }
    JSReadableByteStreamController::payload_of(c)
}

/// Clone a byte chunk so each tee branch gets its own buffer copy — a byte
/// controller's `enqueue` transfers (detaches) the chunk it is given, so
/// handing the same value to both branches would break the second one.
///
/// A byte controller only ever holds `Uint8Array` chunks (it validates and
/// converts on enqueue), so copying the bytes into a fresh view is enough and
/// avoids routing through JS constructors.
fn clone_byte_chunk(ctx: &mut ScopedContext, chunk: JSValue) -> Result<JSValue, i32> {
    let ta = TypedArray::try_from(chunk)
        .map_err(|_| ctx.throw_type_error("tee: byte stream chunk is not a TypedArray"))?;
    let bytes = ta.with_bytes(|b| b.to_vec());
    Ok(JSValue::from(TypedArray::create_from_vec_u8(ctx, bytes)?))
}

/// `StructuredClone(value)` for the tee's second branch.
fn structured_clone(ctx: &mut ScopedContext, value: JSValue) -> Result<JSValue, i32> {
    let f = ctx.global_obj().get_property_str(ctx, "structuredClone")?;
    if !f.is_callable() {
        return Err(ctx.throw_type_error("structuredClone is not callable"));
    }
    f.call(ctx, JSValue::UNDEFINED, &[value])
}
