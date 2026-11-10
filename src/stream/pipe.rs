// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! ReadableStream `pipeTo()` / `pipeThrough()`: copy a readable's chunks into a
//! writable (or through a transform) with backpressure, abort and shutdown
//! handling. pipeTo locks the source synchronously (disturbing it per WHATWG
//! spec) and copies data to `dest` asynchronously. The WPT tests only require
//! that locking/disturbing happens synchronously; the transfer runs as a
//! microtask chain via reader.read()/writer.write() promises.
//!
//! Callback `data` layout shared across the async driver:
//!   [0] result resolve fn, [1] result reject fn, [2] reader,
//!   [3] writer, [4] signal (UNDEFINED if none)

use zuqe::{
    CallContext, Callback, Exception, JSResult, JSValue, NativeObject, ScopedContext,
    builtins::promise::Promise,
};

use crate::{
    abort::{JSAbortSignal, signal_is_aborted, signal_reason},
    stream::{
        JSReadableStream, JSReadableStreamDefaultReader, JSWritableStream,
        JSWritableStreamDefaultWriter, RsState,
    },
};

pub(super) fn js_readable_stream_pipe_to(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    // Spec: pipeTo always returns a promise; brand/validation failures reject it
    // (never throw synchronously), so `promise_rejects_js` gets a promise.
    let bad_this = JSReadableStream::payload_of(&this).is_none();
    let dest = cc.arg(0);
    let bad_dest = JSWritableStream::payload_of(&dest).is_none();
    let options = cc.arg(1);
    // Extract and validate `signal`: it must be undefined or an AbortSignal.
    let signal = if options.is_undefined_or_null() {
        JSValue::UNDEFINED
    } else if let Some(obj) = options.as_object() {
        obj.get_property_str(ctx, "signal")?
    } else {
        JSValue::UNDEFINED
    };
    let bad_signal = !signal.is_undefined() && JSAbortSignal::payload_of(&signal).is_none();

    if bad_this || bad_dest || bad_signal {
        let msg = if bad_this {
            "pipeTo: this must be a ReadableStream"
        } else if bad_dest {
            "pipeTo: dest must be a WritableStream"
        } else {
            "options.signal must be an AbortSignal"
        };
        let _ = ctx.throw_type_error(msg);
        let e = ctx.take_exception().to_value(ctx);
        return Promise::from_reject_value(ctx, e).map(JSValue::from);
    }

    // Spec: a locked source or destination rejects the pipe promise (never
    // throws synchronously) and must not lock the other stream. Check both
    // before acquiring the writer/reader below.
    let src_locked = JSReadableStream::payload_of(&this).map(|p| p.reader.get().is_some());
    let dest_locked = JSWritableStream::payload_of(&dest).map(|p| p.writer.get().is_some());
    if src_locked == Some(true) || dest_locked == Some(true) {
        let msg = if src_locked == Some(true) {
            "ReadableStream is already locked"
        } else {
            "WritableStream is already locked"
        };
        let _ = ctx.throw_type_error(msg);
        let e = ctx.take_exception().to_value(ctx);
        return Promise::from_reject_value(ctx, e).map(JSValue::from);
    }

    // Lock the destination synchronously via the native API (like the reader
    // below) instead of calling the JS-layer `getWriter`, which a monkey-patched
    // prototype could redirect. `dest` is already a WritableStream (checked
    // above), and the locked check above guarantees acquire_writer succeeds.
    let writer = JSWritableStream::from_value(dest)
        .ok_or_else(|| ctx.throw_type_error("pipeTo: dest must be a WritableStream"))?
        .acquire_writer(ctx)?;

    // Acquire a reader on the source synchronously: this locks (disturbs) the
    // stream immediately so `locked` is true and a later getReader() throws.
    // `this` is already a ReadableStream (checked above): acquire its reader via
    // the native API instead of the JS-layer `getReader`.
    let mut this_stream = JSReadableStream::from_value(this)
        .ok_or_else(|| ctx.throw_type_error("pipeTo: this must be a ReadableStream"))?;
    let reader = this_stream.acquire_reader(ctx, false)?;

    // `signal` is undefined (no signal) or a validated AbortSignal (checked
    // above); hand the driver the native handle.
    run_pipe_driver(
        ctx,
        reader,
        writer,
        JSAbortSignal::from_value(signal),
        options,
    )
}

// Shared pipe driver: drives `reader` -> `writer` microtask-by-microtask.
// Called by both pipeTo (after brand checks + signal validation) and pipeThrough
// (with duck-typed transform's reader/writer). `signal` is None (no signal) or
// a validated AbortSignal. `options` drives the abort reaction flags.
//
// Coordination: all state that async pipe callbacks need (resolve/reject fns,
// reader/writer/signal/options, and the `settled` / `shutting_down` / abort
// aggregation flags) lives on a JS `state` object threaded through the callback
// `data` arrays. JS objects and the `data` arrays are both traced by the GC, so
// the JSValues they hold stay rooted for the transfer's lifetime.
//
// `state` fields:
//   settled: bool          - pipe promise settled exactly once (prevents the
//                            normal error path and the abort path from both
//                            rejecting the same promise).
//   shuttingDown: bool     - shutdown began; the read/write loop stops pulling
//                            and stops closing the destination.
//   remainingActions: int  - abort/error cleanup actions still settling.
//   abortErr, cancelErr    - first error from the abort/cancel cleanup action.
//   fallbackReason         - rejection reason when cleanup settles cleanly.
fn run_pipe_driver(
    ctx: &mut ScopedContext,
    reader: JSReadableStreamDefaultReader,
    writer: JSWritableStreamDefaultWriter,
    signal: Option<JSAbortSignal>,
    options: JSValue,
) -> JSResult {
    let (promise, rr) = Promise::create(ctx)?;

    let mut state = ctx.create_base_object()?;
    state.set_property_str(ctx, "settled", false.into())?;
    state.set_property_str(ctx, "shuttingDown", false.into())?;
    state.set_property_str(ctx, "remainingActions", 0.into())?;
    state.set_property_str(ctx, "abortErr", JSValue::UNDEFINED)?;
    state.set_property_str(ctx, "cancelErr", JSValue::UNDEFINED)?;
    state.set_property_str(ctx, "fallbackReason", JSValue::UNDEFINED)?;
    // Backpressure-aware loop state: writes in flight and whether the source
    // has been fully read (so the destination is closed once writes drain).
    state.set_property_str(ctx, "pendingWrites", 0.into())?;
    state.set_property_str(ctx, "readDone", false.into())?;
    // The spec's first `reader.read()` is issued unconditionally during setup,
    // before any backpressure check — so the source is disturbed synchronously
    // even when the destination's desiredSize is not positive (WPT
    // `response-stream-disturbed-by-pipe` reads with `highWaterMark: 0`).
    state.set_property_str(ctx, "issuedFirstRead", false.into())?;

    // Uniform data layout threaded through every async pipe callback:
    //   [0] state, [1] resolve, [2] reject, [3] reader, [4] writer,
    //   [5] signal, [6] options
    let signal_val = signal.map(JSValue::from).unwrap_or(JSValue::UNDEFINED);
    let data = [
        state.into(),
        rr[0],
        rr[1],
        JSValue::from(reader),
        JSValue::from(writer),
        signal_val,
        options,
    ];

    // Synchronous abort check: a signal already aborted must reject the pipe
    // promise without doing any reads.
    if signal.is_some() && signal_is_aborted(&signal_val) {
        pipe_to_perform_abort(ctx, &data)?;
        return Ok(JSValue::from(promise));
    }

    // Register an abort listener when a live signal is present.
    if signal.is_some() {
        let abort_handler = ctx
            .create_native_function_with_data(
                Callback::Func(pipe_to_on_abort),
                "pipeToOnAbort",
                1,
                0,
                data.into(),
            )?
            .into();
        let abort_name = JSValue::make_string(ctx.create_string_from_utf8(b"abort".to_vec())?);
        let add_listener = signal_val.get_property_str(ctx, "addEventListener")?;

        // The signal is already brand-checked by pipeTo, so addEventListener
        // won't throw here; if it somehow does, ignore it rather than turn the
        // pipeTo call into a synchronous throw (it must return a promise).
        //
        // NOTE: if the signal was aborted between the check above and here,
        // addEventListener fires the handler synchronously; its Err is swallowed
        // by addEventListener (which returns Ok), so clean cur_exception
        // unconditionally rather than only on is_err().
        add_listener.call(ctx, signal_val, &[abort_name, abort_handler])?;
        if ctx.rt().exception() != Exception::No {
            ctx.take_exception();
        }
    }

    // Already-errored source *and* a still-writable destination: shut the pipe
    // down synchronously (before any read microtask). This honors the spec rule
    // that a destination `close()` requested before `start()` finished is
    // superseded by the abort the errored source triggers: the destination's
    // `close_requested` is cleared here, so its start-completion close never
    // runs. A non-writable destination is left to the normal path (which must
    // not reject a closed→closed pipe), so the synchronous check is gated on
    // `dest_writable`.
    if pipe_dest_is_writable(&data[4])
        && let Some(err) = pipe_source_errored(&data[3])
    {
        set_state_bool(ctx, &data[0], "shuttingDown", true)?;
        pipe_shutdown_with_error(ctx, &data, err)?;
        return Ok(JSValue::from(promise));
    }

    // Keep watching the destination's `closed` promise: an errored destination
    // must reject the pipe even when the source read is still pending (no
    // write has been issued yet, so the read/write error paths cannot observe
    // it). This is the empty-source `pipeTo` cancellation case.
    let mut closed_promise = Promise::try_from(data[4].get_property_str(ctx, "closed")?)?;
    let dest_closed_ok = ctx
        .create_native_function_with_data(
            Callback::Func(pipe_to_on_dest_closed_ok),
            "pipeToDestClosedOk",
            1,
            0,
            data.into(),
        )?
        .into();
    let dest_closed_err = ctx
        .create_native_function_with_data(
            Callback::Func(pipe_to_on_dest_closed_err),
            "pipeToDestClosedErr",
            1,
            0,
            data.into(),
        )?
        .into();
    closed_promise.perform_then(ctx, dest_closed_ok, dest_closed_err)?;

    pipe_to_read(ctx, &data)?;

    Ok(JSValue::from(promise))
}

// True if the pipe has already settled (promise settled) or begun shutting down;
// used by the read/write loop and the abort handler to stop doing work.
fn pipe_is_shutting_down(ctx: &mut ScopedContext, state: &JSValue) -> Result<bool, i32> {
    let obj = state.as_object().unwrap();
    let settled = obj.get_property_str(ctx, "settled")?.to_bool()?;
    let shutting = obj.get_property_str(ctx, "shuttingDown")?.to_bool()?;
    Ok(settled || shutting)
}

// Mark the pipe as settled; returns true if this call claimed the settlement
// (i.e. it was not already settled). Guards all resolve/reject paths.
fn pipe_mark_settled(ctx: &mut ScopedContext, state: &JSValue) -> Result<bool, i32> {
    let mut obj = state.as_object().unwrap();
    if obj.get_property_str(ctx, "settled")?.to_bool()? {
        return Ok(false);
    }
    obj.set_property_str(ctx, "settled", true.into())?;
    Ok(true)
}

fn pipe_option_bool(ctx: &mut ScopedContext, options: &JSValue, key: &str) -> Result<bool, i32> {
    if let Some(obj) = options.as_object() {
        let b = obj.get_property_str(ctx, key)?.to_bool().unwrap_or(false);
        Ok(b)
    } else {
        Ok(false)
    }
}

// Kick off the read loop: read one chunk and chain the next step. Called both
// for the initial read and after each write resolves (loop continuation).
// `data` layout: [0] state, [1] resolve, [2] reject, [3] reader, [4] writer,
// [5] signal.
fn pipe_to_read(ctx: &mut ScopedContext, data: &[JSValue]) -> JSResult {
    // Once shutdown begins (abort or error), stop reading new data.
    if pipe_is_shutting_down(ctx, &data[0])? {
        return Ok(JSValue::UNDEFINED);
    }
    let mut state_obj = data[0].as_object().unwrap();
    if state_obj.get_property_str(ctx, "readDone")?.to_bool()? {
        return Ok(JSValue::UNDEFINED);
    }
    // The first read is unconditional (see `issuedFirstRead`); afterwards apply
    // backpressure — do not read while the destination does not desire chunks.
    // The destination's queue may hold writes from this pipe, so desiredSize
    // is writable hwm minus the writes this pipe still has in flight.
    let first_read = !state_obj
        .get_property_str(ctx, "issuedFirstRead")?
        .to_bool()?;
    if first_read {
        state_obj.set_property_str(ctx, "issuedFirstRead", true.into())?;
    } else if !pipe_wants_read(ctx, data)? {
        return Ok(JSValue::UNDEFINED);
    }
    let reader = data[3];
    let p = JSReadableStreamDefaultReader::payload_of(&reader)
        .ok_or_else(|| ctx.throw_type_error("not a ReadableStreamDefaultReader"))?;
    let mut read_promise = p.read(ctx, None, 1)?;

    let step = ctx
        .create_native_function_with_data(
            Callback::Func(pipe_to_on_read),
            "pipeToOnRead",
            1,
            0,
            data.into(),
        )?
        .into();
    let step_fail = ctx
        .create_native_function_with_data(
            Callback::Func(pipe_to_on_read_error),
            "pipeToOnReadErr",
            1,
            0,
            data.into(),
        )?
        .into();
    read_promise.perform_then(ctx, step, step_fail)?;
    Ok(JSValue::UNDEFINED)
}

// True if the destination currently desires another chunk: its highWaterMark
// minus the writes this pipe has in flight is positive. An errored destination
// reports `null` desiredSize but the pipe still performs one read first (aike
// has no creation-time pull, so the read is what surfaces the source's pull);
// the errored destination then rejects the write and shuts the pipe down.
fn pipe_wants_read(ctx: &mut ScopedContext, data: &[JSValue]) -> Result<bool, i32> {
    let state_obj = data[0].as_object().unwrap();
    let pending = state_obj
        .get_property_str(ctx, "pendingWrites")?
        .to_number(ctx)?
        .to_f64() as i32;
    let writer = data[4];
    let ds = writer.get_property_str(ctx, "desiredSize")?;
    if ds.is_null() {
        return Ok(true);
    }
    if ds.is_undefined() {
        return Ok(false);
    }
    let desired = ds.to_number(ctx)?.to_f64() - pending as f64;
    Ok(desired > 0.0)
}

fn pipe_source_errored(reader: &JSValue) -> Option<JSValue> {
    let r = JSReadableStreamDefaultReader::payload_of(reader)?;
    let stream = r.stream?;
    let sp = stream.payload()?;
    if sp.state == RsState::Errored {
        Some(sp.stored_error.get())
    } else {
        None
    }
}

fn pipe_dest_errored(writer: &JSValue) -> Option<JSValue> {
    let wp = JSWritableStreamDefaultWriter::payload_of(writer)?;
    let stream = wp.stream?;
    let sp = stream.payload()?;
    if sp.state == RsState::Errored {
        Some(sp.stored_error.get())
    } else {
        None
    }
}

fn pipe_set_state_num(
    ctx: &mut ScopedContext,
    state: &JSValue,
    key: &str,
    n: f64,
) -> Result<(), i32> {
    state
        .as_object()
        .unwrap()
        .set_property_str(ctx, key, JSValue::from(n))?;
    Ok(())
}

// Add `delta` to a numeric state field.
fn pipe_bump_state_num(
    ctx: &mut ScopedContext,
    state: &JSValue,
    key: &str,
    delta: i32,
) -> Result<(), i32> {
    let mut state_obj = state.as_object().unwrap();
    let n = state_obj
        .get_property_str(ctx, key)?
        .to_number(ctx)?
        .to_f64();
    state_obj.set_property_str(ctx, key, JSValue::from(n + delta as f64))?;
    Ok(())
}

// Close the destination (unless preventClose), settling the pipe when done.
// Called once the source is fully read and all writes have drained.
fn pipe_close_dest(ctx: &mut ScopedContext, data: &[JSValue]) -> JSResult {
    if pipe_is_shutting_down(ctx, &data[0])? {
        return Ok(JSValue::UNDEFINED);
    }
    let prevent_close = pipe_option_bool(ctx, &data[6], "preventClose")?;
    let writer = data[4];
    if prevent_close {
        return pipe_resolve(ctx, data);
    }
    // Close the destination; resolve the pipe promise when done. A close
    // that throws synchronously (e.g. destination already errored) must
    // not crash the driver — reject the pipe promise instead.
    let close_fn = writer.get_property_str(ctx, "close")?;
    let close_js = match close_fn.call(ctx, writer, &[]) {
        Ok(v) => v,
        Err(_) => {
            let err = ctx.take_exception().to_value(ctx);
            return pipe_reject(ctx, data, err);
        }
    };
    let mut close_promise: Promise = Promise::try_from(close_js)?;
    let settle_ok = ctx
        .create_native_function_with_data(
            Callback::Func(pipe_to_settle_ok),
            "pipeToSettleOk",
            0,
            0,
            data.into(),
        )?
        .into();
    let settle_err = ctx
        .create_native_function_with_data(
            Callback::Func(pipe_to_settle_err),
            "pipeToSettleErr",
            1,
            0,
            data.into(),
        )?
        .into();
    close_promise.perform_then(ctx, settle_ok, settle_err)?;
    Ok(JSValue::UNDEFINED)
}

// Release the reader/writer locks acquired by pipeTo/pipeThrough once the pipe
// ends. Spec: pipeTo releases both locks when it settles, so a later
// getReader()/getWriter() on the same streams succeeds. A releaseLock() that
// throws (e.g. the reader is already released) must not abort the pipe: drop
// the exception (take_exception) so it doesn't pollute cur_exception.
fn release_pipe_locks(ctx: &mut ScopedContext, reader: JSValue, writer: JSValue) {
    for target in [reader, writer] {
        if let Ok(rel) = target.get_property_str(ctx, "releaseLock")
            && rel.call(ctx, target, &[]).is_err()
        {
            let _exc = ctx.take_exception();
            #[cfg(debug_assertions)]
            crate::helpers::print_exc(ctx, _exc);
        }
    }
}

// Abort signal fired mid-pipe: shut the pipe down with the abort reason. This
// is a no-op if the pipe has already settled or begun shutting down (e.g. the
// readable/writable already errored) — "abort should do nothing after the
// stream is closed/errored".
fn pipe_to_on_abort(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let data = [
        cc.data(0),
        cc.data(1),
        cc.data(2),
        cc.data(3),
        cc.data(4),
        cc.data(5),
        cc.data(6),
    ];
    if pipe_is_shutting_down(ctx, &data[0])? {
        return Ok(JSValue::UNDEFINED);
    }
    // An already-errored source/destination takes precedence over the abort
    // ("abort should do nothing after the readable/writable is errored"): the
    // existing error must be the pipe's rejection, not the abort reason.
    if let Some(err) = pipe_source_errored(&data[3]) {
        set_state_bool(ctx, &data[0], "shuttingDown", true)?;
        return pipe_shutdown_with_error(ctx, &data, err).map(|_| JSValue::UNDEFINED);
    }
    if let Some(err) = pipe_dest_errored(&data[4]) {
        set_state_bool(ctx, &data[0], "shuttingDown", true)?;
        return pipe_shutdown_with_error(ctx, &data, err).map(|_| JSValue::UNDEFINED);
    }
    set_state_bool(ctx, &data[0], "shuttingDown", true)?;
    pipe_to_perform_abort(ctx, &data).map(|_| JSValue::UNDEFINED)
}

fn set_state_bool(ctx: &mut ScopedContext, state: &JSValue, key: &str, v: bool) -> Result<(), i32> {
    state
        .as_object()
        .unwrap()
        .set_property_str(ctx, key, v.into())?;
    Ok(())
}

// Read the abort reason off the signal (or undefined if no signal).
fn pipe_signal_reason(_ctx: &mut ScopedContext, signal: &JSValue) -> JSValue {
    if !signal.is_undefined() {
        signal_reason(signal).unwrap_or(JSValue::UNDEFINED)
    } else {
        JSValue::UNDEFINED
    }
}

// Perform the abort-triggered shutdown of a pipe: abort the destination writer
// and cancel the source reader, then reject the pipe promise with the most
// appropriate error. Per the streams spec, preference order is:
//   1. the error from `writer.abort()` (sink),
//   2. the error from `reader.cancel()` (source), unless the source is already
//      in a final state (in which case cancel only returns its stale stored
//      error and must not override the abort reason),
//   3. the signal's abort reason.
// Both cleanup calls use the same `reason` object so the writer's `closed` and
// the reader's `closed` reject with the same object the pipe promise rejects
// with (WPT: "all the error objects should be the same object").
fn pipe_to_perform_abort(ctx: &mut ScopedContext, data: &[JSValue]) -> Result<(), i32> {
    let state = data[0];
    let reader = data[3];
    let options = data[6];
    let reason = pipe_signal_reason(ctx, &data[5]);
    let prevent_cancel = pipe_option_bool(ctx, &options, "preventCancel")?;
    let prevent_abort = pipe_option_bool(ctx, &options, "preventAbort")?;

    // The abort shutdown only waits for cleanup actions that must run. If both
    // are prevented (or both already moot), reject directly with the reason.
    // Per the spec abortAlgorithm, the abort action is only meaningful when the
    // destination is still writable (an errored/closed destination yields a
    // resolved action, i.e. nothing to wait for).
    let dest_writable = pipe_dest_is_writable(&data[4]);
    let mut pending = 0;
    if !prevent_abort && dest_writable {
        pending += 1;
    }
    if !prevent_cancel && !pipe_source_is_final(&reader) {
        pending += 1;
    }
    if pending == 0 {
        pipe_reject(ctx, data, reason)?;
        return Ok(());
    }

    // Aggregation state across the action settle callbacks: remaining actions
    // + the first error each action reports (sink abort error > source cancel
    // error) + the fallback reason (the abort reason).
    set_state_num(ctx, &state, "remainingActions", pending)?;
    state
        .as_object()
        .unwrap()
        .set_property_str(ctx, "abortErr", JSValue::UNDEFINED)?;
    state
        .as_object()
        .unwrap()
        .set_property_str(ctx, "cancelErr", JSValue::UNDEFINED)?;
    state
        .as_object()
        .unwrap()
        .set_property_str(ctx, "fallbackReason", reason)?;

    if !prevent_abort && dest_writable {
        pipe_run_shutdown_action(ctx, data, ShutdownAction::Abort, reason)?;
    }
    if !prevent_cancel && !pipe_source_is_final(&reader) {
        pipe_run_shutdown_action(ctx, data, ShutdownAction::Cancel, reason)?;
    }

    Ok(())
}

// True if the stream behind this pipe's writer is still writable.
fn pipe_dest_is_writable(writer: &JSValue) -> bool {
    let Some(wp) = JSWritableStreamDefaultWriter::payload_of(writer) else {
        return false;
    };
    let Some(stream) = wp.stream else {
        return false;
    };
    let Some(sp) = stream.payload() else {
        return false;
    };
    sp.state == RsState::Readable
}

fn set_state_num(ctx: &mut ScopedContext, state: &JSValue, key: &str, n: u32) -> Result<(), i32> {
    state
        .as_object()
        .unwrap()
        .set_property_str(ctx, key, (n as f64).into())?;
    Ok(())
}

#[derive(Clone, Copy, PartialEq)]
enum ShutdownAction {
    Abort,
    Cancel,
}

// Run one abort cleanup action (`writer.abort(reason)` or `reader.cancel(reason)`)
// and register a settle callback that records its outcome and finalizes.
// `data` layout for the settle callback: [0] state, [1] resolve, [2] reject,
// [3] reader, [4] writer, [5] signal, [6] actionTag.
fn pipe_run_shutdown_action(
    ctx: &mut ScopedContext,
    data: &[JSValue],
    action: ShutdownAction,
    reason: JSValue,
) -> JSResult {
    let (method, target): (&'static str, JSValue) = match action {
        ShutdownAction::Abort => ("abort", data[4]),
        ShutdownAction::Cancel => ("cancel", data[3]),
    };
    let mut action_promise = if let Ok(f) = target.get_property_str(ctx, method) {
        match f.call(ctx, target, &[reason]) {
            Ok(res) => {
                if let Ok(p) = Promise::try_from(res) {
                    p
                } else {
                    Promise::from_resolve_value(ctx, res)?
                }
            }
            Err(_) => {
                // abort()/cancel() threw synchronously: treat as a rejection
                // with the thrown error.
                let e = ctx.take_exception().to_value(ctx);
                Promise::from_reject_value(ctx, e)?
            }
        }
    } else {
        // Method missing: treat the action as a fulfilled no-op.
        Promise::from_resolve_value(ctx, JSValue::UNDEFINED)?
    };

    let action_tag = if action == ShutdownAction::Abort {
        0.0
    } else {
        1.0
    };
    let settle_data = [
        data[0],
        data[1],
        data[2],
        data[3],
        data[4],
        data[5],
        JSValue::from(action_tag),
    ];
    let settle_fn = ctx
        .create_native_function_with_data(
            Callback::Func(pipe_shutdown_action_settle),
            "pipeShutdownSettle",
            1,
            0,
            settle_data.into(),
        )?
        .into();
    action_promise.perform_then(ctx, settle_fn, settle_fn)?;
    Ok(JSValue::UNDEFINED)
}

// One abort cleanup action settled. The single callback handles both the
// fulfilled (reason arg is undefined) and rejected (reason arg is the error)
// cases, recording the outcome and finalizing the abort shutdown.
// `data`: [0] state, [1] resolve, [2] reject, [3] reader, [4] writer,
// [5] signal, [6] actionTag.
fn pipe_shutdown_action_settle(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let state = cc.data(0);
    let is_abort = cc.data(6).to_number(ctx)?.to_f64() == 0.0;
    let arg = cc.arg(0);
    // `.then(settle, settle)` passes the fulfillment value on the fulfilled
    // path and the rejection reason on the rejected path.
    let err = if cc.length() > 0 && !arg.is_undefined() {
        Some(arg)
    } else {
        None
    };
    let mut state_obj = state.as_object().unwrap();
    if let Some(e) = err {
        let field = if is_abort { "abortErr" } else { "cancelErr" };
        state_obj.set_property_str(ctx, field, e)?;
    }

    let remaining = state_obj
        .get_property_str(ctx, "remainingActions")?
        .to_number(ctx)?
        .to_f64() as u32
        - 1;
    state_obj.set_property_str(ctx, "remainingActions", (remaining as f64).into())?;
    if remaining == 0 {
        let abort_err = state_obj.get_property_str(ctx, "abortErr")?;
        let cancel_err = state_obj.get_property_str(ctx, "cancelErr")?;
        let fallback = state_obj.get_property_str(ctx, "fallbackReason")?;
        let final_err = if !abort_err.is_undefined() {
            abort_err
        } else if !cancel_err.is_undefined() {
            cancel_err
        } else {
            fallback
        };
        let data = [
            cc.data(0),
            cc.data(1),
            cc.data(2),
            cc.data(3),
            cc.data(4),
            cc.data(5),
        ];
        return pipe_reject(ctx, &data, final_err);
    }
    Ok(JSValue::UNDEFINED)
}

// Settle the pipe promise with a rejection, guarded so it happens exactly once.
// Also releases the reader/writer locks. Returns the `reject` call result so
// the caller (a promise reaction job) can propagate it; swallowing it would
// leak `cur_exception`. `data` layout: [0] state, [1] resolve, [2] reject,
// [3] reader, [4] writer, [5] signal.
fn pipe_reject(ctx: &mut ScopedContext, data: &[JSValue], reason: JSValue) -> JSResult {
    if !pipe_mark_settled(ctx, &data[0])? {
        return Ok(JSValue::UNDEFINED);
    }
    let res = data[2].call(ctx, JSValue::UNDEFINED, &[reason]);
    release_pipe_locks(ctx, data[3], data[4]);
    res
}

// Settle the pipe promise with a resolution, guarded so it happens exactly once.
fn pipe_resolve(ctx: &mut ScopedContext, data: &[JSValue]) -> JSResult {
    if !pipe_mark_settled(ctx, &data[0])? {
        return Ok(JSValue::UNDEFINED);
    }
    let res = data[1].call(ctx, JSValue::UNDEFINED, &[]);
    release_pipe_locks(ctx, data[3], data[4]);
    res
}

pub(super) fn js_readable_stream_pipe_through(
    ctx: &mut ScopedContext,
    cc: CallContext,
) -> JSResult {
    let this = cc.this();

    let mut this_stream = JSReadableStream::from_value(this)
        .ok_or_else(|| ctx.throw_type_error("pipeThrough: this must be a ReadableStream"))?;

    let transform = cc.arg(0);
    // `transform` is duck-typed: `{ readable, writable }`. Brand-check `readable`
    // first (so a bad readable does not access `writable`), then `writable`.
    let readable = transform.get_property_str(ctx, "readable")?;
    if JSReadableStream::payload_of(&readable).is_none() {
        return Err(
            ctx.throw_type_error("pipeThrough: transform.readable must be a ReadableStream")
        );
    }
    let writable = transform.get_property_str(ctx, "writable")?;
    if JSWritableStream::payload_of(&writable).is_none() {
        return Err(
            ctx.throw_type_error("pipeThrough: transform.writable must be a WritableStream")
        );
    }

    let options = cc.arg(1);
    // Spec: read every option before touching the streams, so a property
    // getter runs in order and may lock a stream (making the acquire below
    // throw). Extract and validate `signal` too.
    let mut prevent_close = false;
    let mut prevent_abort = false;
    let mut prevent_cancel = false;
    let mut signal = JSValue::UNDEFINED;
    if !options.is_undefined_or_null()
        && let Some(obj) = options.as_object()
    {
        prevent_close = obj.get_property_str(ctx, "preventClose")?.to_bool()?;
        prevent_abort = obj.get_property_str(ctx, "preventAbort")?.to_bool()?;
        prevent_cancel = obj.get_property_str(ctx, "preventCancel")?.to_bool()?;
        signal = obj.get_property_str(ctx, "signal")?;
    }
    if !signal.is_undefined() && JSAbortSignal::payload_of(&signal).is_none() {
        return Err(ctx.throw_type_error("options.signal must be an AbortSignal"));
    }
    // Option values were read for their getter side effects (they can lock a
    // stream); the driver re-reads them from `options` for its shutdown logic.
    let _ = (prevent_close, prevent_abort, prevent_cancel);

    // pipeThrough = pipe this into transform.writable, then return transform.readable.
    // Use the shared driver directly (NOT this.pipeTo) so a monkey-patched
    // pipeTo on the prototype/instance is not invoked.
    let mut writable_stream = JSWritableStream::from_value(writable).ok_or_else(|| {
        ctx.throw_type_error("pipeThrough: transform.writable must be a WritableStream")
    })?;
    let writer = writable_stream.acquire_writer(ctx)?;

    let reader = this_stream.acquire_reader(ctx, false)?;
    run_pipe_driver(
        ctx,
        reader,
        writer,
        JSAbortSignal::from_value(signal),
        options,
    )?;

    Ok(readable)
}

// A chunk was read: on done, record it and close the destination once pending
// writes drain; otherwise write the chunk and keep reading while the
// destination desires chunks (backpressure-aware read-ahead).
// `data` layout: [0] state, [1] resolve, [2] reject, [3] reader, [4] writer,
// [5] signal.
fn pipe_to_on_read(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let data = [
        cc.data(0),
        cc.data(1),
        cc.data(2),
        cc.data(3),
        cc.data(4),
        cc.data(5),
        cc.data(6),
    ];
    // Shutdown may have started while this read was in flight; stop the loop.
    if pipe_is_shutting_down(ctx, &data[0])? {
        return Ok(JSValue::UNDEFINED);
    }
    let result = cc.arg(0);
    let done = result.get_property_str(ctx, "done")?.to_bool()?;
    if done {
        // Source fully read: mark it and close the destination once every
        // already-read chunk has finished writing.
        pipe_set_state_num(ctx, &data[0], "readDone", 1.0)?;
        let pending = data[0]
            .as_object()
            .unwrap()
            .get_property_str(ctx, "pendingWrites")?
            .to_number(ctx)?
            .to_f64() as i32;
        if pending == 0 {
            return pipe_close_dest(ctx, &data);
        }
        return Ok(JSValue::UNDEFINED);
    }
    let value = result.get_property_str(ctx, "value")?;
    let writer = data[4];
    let write_js = writer
        .get_property_str(ctx, "write")?
        .call(ctx, writer, &[value])?;

    let mut write_promise: Promise = Promise::try_from(write_js)?;
    pipe_bump_state_num(ctx, &data[0], "pendingWrites", 1)?;

    let loop_fn = ctx
        .create_native_function_with_data(
            Callback::Func(pipe_to_on_write_done),
            "pipeToWriteDone",
            1,
            0,
            data.into(),
        )?
        .into();
    let write_fail = ctx
        .create_native_function_with_data(
            Callback::Func(pipe_to_on_write_error),
            "pipeToWriteErr",
            1,
            0,
            data.into(),
        )?
        .into();
    write_promise.perform_then(ctx, loop_fn, write_fail)?;

    // The write's sink may have errored the source synchronously (e.g.
    // `write()` calling `controller.error()`). Per the spec that error takes
    // precedence over any further reads — shut the pipe down with it.
    if let Some(err) = pipe_source_errored(&data[3]) {
        set_state_bool(ctx, &data[0], "shuttingDown", true)?;
        return pipe_shutdown_with_error(ctx, &data, err).map(|_| JSValue::UNDEFINED);
    }

    // Read-ahead: keep reading while the destination desires chunks. This
    // lets a high-water-mark destination receive multiple chunks in flight.
    pipe_to_read(ctx, &data)?;
    Ok(JSValue::UNDEFINED)
}

// A write fulfilled: drop it from the in-flight count, then continue reading
// if the destination still desires chunks, or close the destination once the
// source is fully read and all writes have drained.
fn pipe_to_on_write_done(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let data = [
        cc.data(0),
        cc.data(1),
        cc.data(2),
        cc.data(3),
        cc.data(4),
        cc.data(5),
        cc.data(6),
    ];
    pipe_bump_state_num(ctx, &data[0], "pendingWrites", -1)?;
    if pipe_is_shutting_down(ctx, &data[0])? {
        return Ok(JSValue::UNDEFINED);
    }
    let state_obj = data[0].as_object().unwrap();
    let pending = state_obj
        .get_property_str(ctx, "pendingWrites")?
        .to_number(ctx)?
        .to_f64() as i32;
    if state_obj.get_property_str(ctx, "readDone")?.to_bool()? && pending == 0 {
        pipe_close_dest(ctx, &data)
    } else {
        pipe_to_read(ctx, &data)
    }
}

// Source read failed: shut the pipe down with the read error. Per spec the
// source's error propagates as the pipe rejection (aborting the writer unless
// prevented, cancelling the reader unless prevented).
fn pipe_to_on_read_error(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let data = [
        cc.data(0),
        cc.data(1),
        cc.data(2),
        cc.data(3),
        cc.data(4),
        cc.data(5),
        cc.data(6),
    ];
    // If the pipe already settled (or abort already began shutting down), the
    // shutdown is handled by that path — don't run a second one.
    if pipe_is_shutting_down(ctx, &data[0])? {
        return Ok(JSValue::UNDEFINED);
    }
    set_state_bool(ctx, &data[0], "shuttingDown", true)?;
    let reason = cc.arg(0);
    pipe_shutdown_with_error(ctx, &data, reason).map(|_| JSValue::UNDEFINED)
}

// Destination `closed` fulfilled: normal pipe completion already resolves via
// the read loop; nothing to do here.
fn pipe_to_on_dest_closed_ok(_ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    Ok(JSValue::UNDEFINED)
}

// Destination errored while the source read is still pending: shut the pipe
// down with the destination's error. Without this, an empty source could leave
// `pipeTo()` pending forever after the destination side is cancelled/errored.
fn pipe_to_on_dest_closed_err(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let data = [
        cc.data(0),
        cc.data(1),
        cc.data(2),
        cc.data(3),
        cc.data(4),
        cc.data(5),
        cc.data(6),
    ];
    if pipe_is_shutting_down(ctx, &data[0])? {
        return Ok(JSValue::UNDEFINED);
    }
    set_state_bool(ctx, &data[0], "shuttingDown", true)?;
    let reason = cc.arg(0);
    pipe_shutdown_with_error(ctx, &data, reason).map(|_| JSValue::UNDEFINED)
}

// Write failed: shut the pipe down with the write error.
fn pipe_to_on_write_error(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let data = [
        cc.data(0),
        cc.data(1),
        cc.data(2),
        cc.data(3),
        cc.data(4),
        cc.data(5),
        cc.data(6),
    ];
    if pipe_is_shutting_down(ctx, &data[0])? {
        return Ok(JSValue::UNDEFINED);
    }
    set_state_bool(ctx, &data[0], "shuttingDown", true)?;
    let reason = cc.arg(0);
    pipe_shutdown_with_error(ctx, &data, reason).map(|_| JSValue::UNDEFINED)
}

// Shut a pipe down after a read/write error: abort the writer (unless
// prevented) and cancel the reader (unless prevented), then reject the pipe
// promise with the original error. Uses the abort cleanup machinery so the
// final rejection is the action error, or the original error if cleanup runs
// cleanly (per spec, the original error is preferred once cleanup succeeds).
fn pipe_shutdown_with_error(
    ctx: &mut ScopedContext,
    data: &[JSValue],
    reason: JSValue,
) -> Result<(), i32> {
    let state = data[0];
    let prevent_abort = pipe_option_bool(ctx, &data[6], "preventAbort")?;
    let prevent_cancel = pipe_option_bool(ctx, &data[6], "preventCancel")?;

    let mut pending = 0;
    if !prevent_abort {
        pending += 1;
    }
    if !prevent_cancel && !pipe_source_is_final(&data[3]) {
        pending += 1;
    }
    if pending == 0 {
        pipe_reject(ctx, data, reason)?;
        return Ok(());
    }

    // For an error shutdown the fallback reason is the original error (not the
    // abort reason); `pipe_shutdown_action_settle` rejects with it once the
    // cleanup actions settle cleanly.
    set_state_num(ctx, &state, "remainingActions", pending)?;
    state
        .as_object()
        .unwrap()
        .set_property_str(ctx, "abortErr", JSValue::UNDEFINED)?;
    state
        .as_object()
        .unwrap()
        .set_property_str(ctx, "cancelErr", JSValue::UNDEFINED)?;
    state
        .as_object()
        .unwrap()
        .set_property_str(ctx, "fallbackReason", reason)?;

    if !prevent_abort {
        pipe_run_shutdown_action(ctx, data, ShutdownAction::Abort, reason)?;
    }
    if !prevent_cancel && !pipe_source_is_final(&data[3]) {
        pipe_run_shutdown_action(ctx, data, ShutdownAction::Cancel, reason)?;
    }
    Ok(())
}

// Settle the pipe promise once the destination close finishes.
// Success path (close fulfilled): resolve the pipe promise and release locks.
fn pipe_to_settle_ok(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let data = [
        cc.data(0),
        cc.data(1),
        cc.data(2),
        cc.data(3),
        cc.data(4),
        cc.data(5),
        cc.data(6),
    ];
    pipe_resolve(ctx, &data)
}

// Failure path (close rejected): reject the pipe promise with the close error
// and release locks.
fn pipe_to_settle_err(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let data = [
        cc.data(0),
        cc.data(1),
        cc.data(2),
        cc.data(3),
        cc.data(4),
        cc.data(5),
        cc.data(6),
    ];
    pipe_reject(ctx, &data, cc.arg(0))
}

/// True if the source stream attached to this pipe's reader is already in a
/// final (errored/closed) state, in which case `reader.cancel()` would only
/// return the stored error without performing a real cancellation. The abort
/// shutdown must then fall back to the abort reason instead of surfacing that
/// stale stored error (WPT "abort signal takes priority over errored readable").
fn pipe_source_is_final(reader: &JSValue) -> bool {
    let Some(r) = JSReadableStreamDefaultReader::payload_of(reader) else {
        return true;
    };
    let Some(stream) = r.stream else {
        return true;
    };
    let Some(p) = stream.payload() else {
        return true;
    };
    p.state != RsState::Readable
}
