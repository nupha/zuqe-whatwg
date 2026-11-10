// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WritableStream.

use zuqe::{
    CallContext, Callback, ClassCtorDef, FieldDef, GcBind, JSResult, JSValue, NativeObject,
    ScopedContext, WriteBarrier, WriteBarrierVec,
    builtins::promise::{Promise, PromiseState},
    def_native_object,
    gc_lite::GcTrace,
};

use crate::stream::{
    extract_high_water_mark, extract_size_algorithm,
    writable_controller::{JSWritableStreamDefaultController, WritableControllerPayload},
    writer::{JSWritableStreamDefaultWriter, WriterPayload},
};

use super::RsState;

// ============================================================================
// WritableStream
// ============================================================================

/// A pending `abort()` request (spec `WritableStreamAbort`): the promise to
/// settle, the reason to forward to the sink's `abort()`, and whether the
/// stream was already erroring when the abort was issued.
#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct PendingAbort {
    pub(crate) promise: WriteBarrier<Promise>,
    pub(crate) reason: WriteBarrier<JSValue>,
    pub(crate) was_already_erroring: bool,
}

#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct WritableStreamPayload {
    pub(crate) state: RsState,
    pub(crate) stored_error: WriteBarrier<JSValue>,
    pub(crate) writer: WriteBarrier<Option<JSWritableStreamDefaultWriter>>,
    pub(crate) controller: WriteBarrier<Option<JSWritableStreamDefaultController>>,
    /// Mirrors WHATWG `_started`. The sink `write()` is only ever invoked once
    /// this becomes true (after the `start` algorithm runs). A `write()` issued
    /// before start is enqueued and executed later; `Abort`/`Error` before
    /// start rejects those queued writes and never calls the sink.
    pub(crate) started: bool,
    /// Chunks waiting to be written (mirrors the controller's queue). `write()`
    /// pushes a chunk here when the stream is writable but not yet started, or
    /// when the previous write is still in flight.
    pub(crate) write_queue: WriteBarrierVec<JSValue>,
    /// The `write()` promises corresponding 1:1 to `write_queue` entries.
    pub(crate) write_requests: WriteBarrierVec<Promise>,
    /// The `size` of each queued chunk (1:1 with `write_queue`), per the
    /// queuing strategy's `size` algorithm. Used to compute `desiredSize`.
    pub(crate) write_queue_sizes: Vec<f64>,
    /// Running total of queued chunk sizes; `desiredSize = highWaterMark −
    /// queue_total_size`. Mirrors the readable controller's `queue_total_size`.
    pub(crate) queue_total_size: f64,
    /// Size of the currently in-flight write; counted within `queue_total_size`
    /// until the write settles.
    pub(crate) in_flight_write_size: f64,
    /// The write promise currently in flight (sink `write()` called but not yet
    /// settled). Per spec, an in-flight write is NOT rejected by a later abort.
    pub(crate) in_flight_write_request: WriteBarrier<Option<Promise>>,
    /// Set when `writer.close()` has been requested. The underlying sink's
    /// `close()` is deferred until all queued/in-flight writes have settled.
    pub(crate) close_requested: bool,
    /// The promise returned by `writer.close()`, resolved once the sink's
    /// `close()` completes.
    pub(crate) close_promise: WriteBarrier<Option<Promise>>,
    /// Mirrors WHATWG `backpressure` (desiredSize ≤ 0). Drives the writer's
    /// `ready` promise: entering backpressure replaces it with a fresh pending
    /// promise, leaving it resolves the current one in place.
    pub(crate) backpressure: bool,
    /// A sink `close()` is currently in flight (the sink's `close()` has been
    /// invoked but not yet settled). Mirrors WHATWG `inFlightCloseRequest`.
    pub(crate) in_flight_close: bool,
    /// A pending abort request (spec `pendingAbortRequest`), settled once the
    /// stream finishes erroring and the sink's `abort()` (if any) settles.
    pub(crate) pending_abort: Option<PendingAbort>,
    /// The stream object's own handle, set right after construction. Payload
    /// methods store fresh (young) values (stored error, promises, the writer)
    /// into this possibly-already-old stream, so the write barrier needs the
    /// owner node.
    #[gc(skip)]
    pub(crate) owner: Option<JSValue>,
}

impl WritableStreamPayload {
    pub(crate) fn new() -> Self {
        Self {
            state: RsState::Readable,
            stored_error: WriteBarrier::new(JSValue::UNDEFINED),
            writer: WriteBarrier::new(None),
            controller: WriteBarrier::new(None),
            started: false,
            write_queue: WriteBarrierVec::new(),
            write_requests: WriteBarrierVec::new(),
            write_queue_sizes: Vec::new(),
            queue_total_size: 0.0,
            in_flight_write_size: 0.0,
            in_flight_write_request: WriteBarrier::new(None),
            close_requested: false,
            close_promise: WriteBarrier::new(None),
            backpressure: false,
            in_flight_close: false,
            pending_abort: None,
            owner: None,
        }
    }

    /// Store + bind the controller. Owner is the stream node itself.
    pub(crate) fn set_controller(
        &mut self,
        ctx: &ScopedContext,
        owner: JSValue,
        c: JSWritableStreamDefaultController,
    ) {
        self.controller.set(ctx, owner, Some(c));
    }

    /// Mirror of WHATWG `WritableStreamStartErroring`: transition to the
    /// Erroring state, reject the writer's `ready`, and finish erroring
    /// immediately when no operation is in flight (and the stream is started).
    /// The in-flight write, if any, is NOT rejected — it keeps running and
    /// settles with its own result.
    pub(crate) fn start_erroring(
        &mut self,
        ctx: &mut ScopedContext,
        error: JSValue,
    ) -> Result<(), i32> {
        if self.state != RsState::Readable {
            return Ok(());
        }
        self.state = RsState::Erroring;
        // The guard slot records the barrier (no handle yet: UNDEFINED = no-op bind).
        let owner = self.owner.unwrap_or(JSValue::UNDEFINED);
        self.stored_error.set(ctx, owner, error);
        // writer.ready rejects (or is replaced when already settled).
        if let Some(w) = self.writer.get() {
            let mut wv = JSValue::from(w);
            if let Some(wp) = JSWritableStreamDefaultWriter::payload_mut_of(&mut wv) {
                wp.ensure_ready_rejected(ctx, error);
            }
        }
        // Per spec `FinishErroring` step 9: only finish erroring when
        // there is no in-flight operation AND controller.[[started]] is
        // true.  Before start resolves the stream stays in "erroring"
        // state so that close() can still create a close request that
        // will be settled with the stored error once erroring finishes.
        if !self.has_operation_in_flight() && self.started {
            self.finish_erroring(ctx)?;
        }
        Ok(())
    }

    pub(crate) fn set_in_flight_write_request(&mut self, ctx: &ScopedContext, p: Promise) {
        let owner = self.owner.unwrap_or(JSValue::UNDEFINED);
        // Store + barrier in one `set` call so no GC point can observe an unbarriered edge.
        self.in_flight_write_request.set(ctx, owner, Some(p));
    }

    pub(crate) fn clear_in_flight_write_request(&mut self, ctx: &ScopedContext) {
        let owner = self.owner.unwrap_or(JSValue::UNDEFINED);
        self.in_flight_write_request.set(ctx, owner, None);
    }

    fn has_operation_in_flight(&self) -> bool {
        self.in_flight_write_request.get().is_some() || self.in_flight_close
    }

    /// Mirror of WHATWG `WritableStreamFinishErroring`: transition to the
    /// Errored state, reject queued writes, settle the pending abort request
    /// (invoking the sink's `abort()` as needed) and reject the writer's
    /// `closed` / pending close request with the stored error.
    pub(crate) fn finish_erroring(&mut self, ctx: &mut ScopedContext) -> Result<(), i32> {
        if self.state != RsState::Erroring {
            return Ok(());
        }
        self.state = RsState::Errored;
        let stored = self.stored_error.get();
        // Queued (not in-flight) writes reject with the stored error.
        let queued = std::mem::take(&mut self.write_requests).into_vec();
        for mut req in queued {
            req.reject(ctx, stored);
        }
        self.write_queue.clear();
        self.write_queue_sizes.clear();
        self.queue_total_size = 0.0;
        self.in_flight_write_size = 0.0;

        // Pending abort request (spec WritableStreamFinishErroring).
        if let Some(req) = self.pending_abort.take() {
            if req.was_already_erroring {
                let mut p = req.promise.get();
                p.reject(ctx, stored);
                self.reject_close_and_closed(ctx);
            } else {
                // AbortSteps: invoke the sink's `abort()`, then settle the abort
                // promise and reject `closed` once that settles.
                let abort_result = self.abort_steps(ctx, req.reason.get())?;
                let stream_val = self.stream_value();
                let on_ok = ctx.create_native_function_with_data(
                    Callback::Func(|ctx, cc| {
                        let mut sv = cc.data(0);
                        if let Ok(mut p) = Promise::try_from(cc.data(1)) {
                            p.resolve(ctx, JSValue::UNDEFINED);
                        }
                        if let Some(sp) = JSWritableStream::payload_mut_of(&mut sv) {
                            sp.reject_close_and_closed(ctx);
                        }
                        Ok(JSValue::UNDEFINED)
                    }),
                    "abortStepsOk",
                    0,
                    0,
                    [stream_val, JSValue::from(req.promise.get())].into(),
                )?;
                let on_err = ctx.create_native_function_with_data(
                    Callback::Func(|ctx, cc| {
                        let mut sv = cc.data(0);
                        if let Ok(mut p) = Promise::try_from(cc.data(1)) {
                            p.reject(ctx, cc.arg(0));
                        }
                        if let Some(sp) = JSWritableStream::payload_mut_of(&mut sv) {
                            sp.reject_close_and_closed(ctx);
                        }
                        Ok(JSValue::UNDEFINED)
                    }),
                    "abortStepsErr",
                    1,
                    0,
                    [stream_val, JSValue::from(req.promise.get())].into(),
                )?;
                let mut abort_result = abort_result;
                abort_result.perform_then(ctx, on_ok.into(), on_err.into())?;
            }
        } else {
            self.reject_close_and_closed(ctx);
        }
        Ok(())
    }

    /// Invoke the underlying sink's `abort(reason)` and return its result as a
    /// promise (a resolved promise when the sink has no `abort` method). Per
    /// spec `WritableStreamDefaultController[[AbortSteps]]`.
    fn abort_steps(&self, ctx: &mut ScopedContext, reason: JSValue) -> Result<Promise, i32> {
        if let Some(controller) = self.controller.get()
            && let Some(cp) = controller.payload()
            && let Some(sink) = cp.underlying_sink.get().as_object()
        {
            match sink.invoke_str_defined(ctx, "abort", &[reason]) {
                Ok(Some(Ok(v))) => {
                    if let Ok(p) = Promise::try_from(v) {
                        Ok(p)
                    } else {
                        Promise::from_resolve_value(ctx, v)
                    }
                }
                Ok(None) => Promise::from_resolve_value(ctx, JSValue::UNDEFINED),
                Ok(Some(Err(_))) | Err(_) => {
                    let e = ctx.take_exception().to_value(ctx);
                    Promise::from_reject_value(ctx, e)
                }
            }
        } else {
            Promise::from_resolve_value(ctx, JSValue::UNDEFINED)
        }
    }

    /// Mirror of `WritableStreamRejectCloseAndClosedPromiseIfNeeded`: reject the
    /// pending close request and the writer's `closed` promise with the stored
    /// error. Only meaningful once the stream is Errored.
    pub(crate) fn reject_close_and_closed(&mut self, ctx: &mut ScopedContext) {
        let stored = self.stored_error.get();
        if self.close_requested {
            self.close_requested = false;
            if let Some(mut cp) = self.close_promise.take() {
                cp.reject(ctx, stored);
            }
        }
        if let Some(w) = self.writer.get() {
            let mut wv = JSValue::from(w);
            if let Some(wp) = JSWritableStreamDefaultWriter::payload_mut_of(&mut wv) {
                wp.ensure_closed_rejected(ctx, stored);
            }
        }
    }

    /// The stream handle (as a JSValue), recovered via the controller's
    /// back-reference; `undefined` when unavailable.
    fn stream_value(&self) -> JSValue {
        match self.controller.get() {
            Some(c) => {
                let cv = JSValue::from(c);
                match JSWritableStreamDefaultController::payload_of(&cv) {
                    Some(cp) => match cp.stream {
                        Some(s) => JSValue::from(s),
                        None => JSValue::UNDEFINED,
                    },
                    None => JSValue::UNDEFINED,
                }
            }
            None => JSValue::UNDEFINED,
        }
    }

    /// Current backpressure: `desiredSize = highWaterMark − queue_total_size`
    /// is ≤ 0. Mirrors `WritableStreamDefaultControllerGetBackpressure`.
    pub(crate) fn current_backpressure(&self) -> bool {
        let Some(controller) = self.controller.get() else {
            return false;
        };
        controller
            .payload()
            .map(|cp| cp.high_water_mark - self.queue_total_size <= 0.0)
            .unwrap_or(false)
    }

    /// Mirror of `WritableStreamUpdateBackpressure`: when backpressure changes,
    /// entering it replaces the writer's `ready` promise with a fresh pending
    /// promise, leaving it resolves the current one in place.
    pub(crate) fn update_backpressure(&mut self, ctx: &mut ScopedContext) {
        let bp = self.current_backpressure();
        if bp == self.backpressure {
            return;
        }
        if let Some(w) = self.writer.get() {
            let mut wv = JSValue::from(w);
            if let Some(wp) = JSWritableStreamDefaultWriter::payload_mut_of(&mut wv) {
                if bp {
                    if let Ok((ready, _)) = Promise::create(ctx) {
                        // The guard slot records the barrier (no handle yet: UNDEFINED = no-op bind).
                        let owner = wp.owner.unwrap_or(JSValue::UNDEFINED);
                        wp.ready_promise.set(ctx, owner, Some(ready));
                    }
                } else if let Some(mut rp) = wp.ready_promise.get()
                    && rp.state() == PromiseState::Pending
                {
                    rp.resolve(ctx, JSValue::UNDEFINED);
                }
            }
        }
        self.backpressure = bp;
    }

    /// Mirror of WHATWG `WritableStreamDefaultControllerAdvanceQueueIfNeeded`.
    /// If the stream is writable & started and no write is in flight, pop the
    /// first queued chunk and invoke the sink `write()` (the in-flight write).
    pub(crate) fn advance_queue(&mut self, ctx: &mut ScopedContext) -> Result<(), i32> {
        if self.in_flight_write_request.get().is_some() {
            return Ok(());
        }
        if !self.started {
            return Ok(());
        }
        match self.state {
            RsState::Erroring => {
                // Per spec: an erroring stream with no in-flight op finishes
                // erroring here (rejects queued writes, close and closed).
                self.finish_erroring(ctx)?;
                return Ok(());
            }
            RsState::Closed | RsState::Errored => return Ok(()),
            RsState::Readable => {}
        }
        if self.write_queue.is_empty() {
            // No more writes: if a close was requested, perform it now (the sink's
            // `close()` runs once the queue has fully drained).
            if self.close_requested {
                self.try_close(ctx)?;
            }
            return Ok(());
        }
        let chunk = self.write_queue.remove(0);
        let write_promise = self.write_requests.remove(0);
        // The dequeued chunk becomes the in-flight write: its size stays counted
        // toward `queue_total_size` (mirrors the spec, where desiredSize includes
        // the in-flight write) until the write settles in `finish_in_flight_write`.
        let size = self.write_queue_sizes.remove(0);
        self.in_flight_write_size = size;
        // `process_write` creates a new in-flight promise that settles when the
        // sink write completes. The original `write_promise` returned to JS by
        // `writer.write()` is settled directly (before `ready`) so its reactions
        // run before the writer's `ready` reactions, per the spec ordering.
        self.process_write(ctx, chunk, write_promise)?;
        Ok(())
    }

    /// Settle the stream's deferred close promise. On success resolve it (and
    /// the writer's `closed`); on failure error the stream, reject the close
    /// promise, and settle the writer's `ready`/`closed`.
    fn finish_close(
        ctx: &mut ScopedContext,
        stream_val: &mut JSValue,
        ok: bool,
        value: JSValue,
    ) -> JSResult {
        if let Some(sp) = JSWritableStream::payload_mut_of(stream_val) {
            sp.in_flight_close = false;
            if ok {
                // Per spec `WritableStreamFinishInFlightClose`: resolve the close
                // request first, then (when the stream was erroring, e.g. aborted
                // during the close) discard the error and resolve a pending abort
                // request, then close the stream.
                if let Some(mut cp) = sp.close_promise.take() {
                    cp.resolve(ctx, JSValue::UNDEFINED);
                }
                if sp.state == RsState::Erroring {
                    // Clearing to UNDEFINED records no edge (no-op bind).
                    let owner = sp.owner.unwrap_or(JSValue::UNDEFINED);
                    sp.stored_error.set(ctx, owner, JSValue::UNDEFINED);
                    if let Some(req) = sp.pending_abort.take() {
                        let mut p = req.promise.get();
                        p.resolve(ctx, JSValue::UNDEFINED);
                    }
                }
                sp.state = RsState::Closed;
                // The writer's `closed` promise resolves once the stream closes.
                if let Some(w) = sp.writer.get() {
                    let mut wv = JSValue::from(w);
                    if let Some(wp) = JSWritableStreamDefaultWriter::payload_mut_of(&mut wv)
                        && let Some(mut cp) = wp.closed_promise.get()
                        && cp.state() == PromiseState::Pending
                    {
                        cp.resolve(ctx, JSValue::UNDEFINED);
                    }
                }
            } else {
                // Per spec `WritableStreamFinishInFlightCloseWithError`: reject the
                // close request, reject a pending abort request with the same error,
                // then `DealWithRejection` (writable -> start erroring, erroring ->
                // finish erroring with the existing stored error).
                if let Some(mut cp) = sp.close_promise.take() {
                    cp.reject(ctx, value);
                }
                if let Some(req) = sp.pending_abort.take() {
                    let mut p = req.promise.get();
                    p.reject(ctx, value);
                }
                match sp.state {
                    RsState::Readable => sp.start_erroring(ctx, value)?,
                    RsState::Erroring => sp.finish_erroring(ctx)?,
                    _ => {}
                }
            }
        }
        Ok(JSValue::UNDEFINED)
    }

    /// Perform the underlying sink `close()` now (all writes have drained), and
    /// settle the close promise. Per spec `WritableStreamClose`, `close()` is
    /// only invoked once the stream is no longer writable/backpressured. The
    /// stream transitions to Closed only once the sink `close()` settles
    /// (`finish_close`).
    fn perform_close(&mut self, ctx: &mut ScopedContext) -> Result<(), i32> {
        self.close_requested = false;
        // `stream_val` is needed by the async close handlers; recover it via the
        // controller's back-reference.
        let stream_val = match self.controller.get() {
            Some(c) => {
                let cv = JSValue::from(c);
                match JSWritableStreamDefaultController::payload_of(&cv) {
                    Some(cp) => match cp.stream {
                        Some(s) => JSValue::from(s),
                        None => JSValue::UNDEFINED,
                    },
                    None => JSValue::UNDEFINED,
                }
            }
            None => JSValue::UNDEFINED,
        };
        let sink_close = match self.controller.get() {
            Some(c) => {
                let cv = JSValue::from(c);
                match JSWritableStreamDefaultController::payload_of(&cv) {
                    Some(cp) => cp.underlying_sink.get().as_object(),
                    None => None,
                }
            }
            None => None,
        };
        // The sink's `close()` result is always treated as a promise (spec
        // `uponPromise`), so even a synchronous/non-thenable return (or a missing
        // sink close) settles the close on a microtask and a thenable is
        // assimilated.
        let mut close_result = match sink_close {
            Some(s) => match s.invoke_str_callable(ctx, "close", &[]) {
                Ok(Some(Ok(v))) => {
                    if let Ok(p) = Promise::try_from(v) {
                        p
                    } else {
                        Promise::from_resolve_value(ctx, v)?
                    }
                }
                Ok(Some(Err(_))) | Err(_) => {
                    let e = ctx.take_exception().to_value(ctx);
                    Promise::from_reject_value(ctx, e)?
                }
                _ => Promise::from_resolve_value(ctx, JSValue::UNDEFINED)?,
            },
            None => Promise::from_resolve_value(ctx, JSValue::UNDEFINED)?,
        };
        let on_ok = ctx.create_native_function_with_data(
            Callback::Func(|ctx, cc| {
                let mut sv = cc.data(0);
                Self::finish_close(ctx, &mut sv, true, JSValue::UNDEFINED)
            }),
            "closeOk",
            0,
            0,
            [stream_val].into(),
        )?;
        let on_err = ctx.create_native_function_with_data(
            Callback::Func(|ctx, cc| {
                let mut sv = cc.data(0);
                Self::finish_close(ctx, &mut sv, false, cc.arg(0))
            }),
            "closeErr",
            0,
            0,
            [stream_val].into(),
        )?;
        close_result.perform_then(ctx, on_ok.into(), on_err.into())?;
        Ok(())
    }

    /// If a `close()` was requested and there are no pending/in-flight writes,
    /// perform it now; otherwise it will run once the last write settles. An
    /// erroring stream with no in-flight operation finishes erroring here (per
    /// spec `WritableStreamDefaultControllerAdvanceQueueIfNeeded`).
    pub(crate) fn try_close(&mut self, ctx: &mut ScopedContext) -> Result<(), i32> {
        if self.state == RsState::Erroring && !self.has_operation_in_flight() {
            self.finish_erroring(ctx)?;
            return Ok(());
        }

        if self.state == RsState::Readable
            && self.started
            && self.close_requested
            && self.write_queue.is_empty()
            && self.in_flight_write_request.get().is_none()
            && !self.in_flight_close
        {
            self.close_requested = false;
            self.in_flight_close = true;
            // A TransformStream closes by running the transformer's `flush()`
            // (then closing the readable side) once writes have drained; a plain
            // stream closes by invoking the sink's `close()`.
            let is_transform = match self.controller.get() {
                Some(controller) => controller
                    .payload()
                    .map(|cp| cp.transform_controller.get().is_some())
                    .unwrap_or(false),
                None => false,
            };
            if is_transform {
                self.perform_transform_flush(ctx)?;
            } else {
                self.perform_close(ctx)?;
            }
        }
        Ok(())
    }

    /// Run a TransformStream's close algorithm (spec
    /// `TransformStreamDefaultSinkCloseAlgorithm`): invoke the transformer's
    /// `flush()`, then close the readable side and the writable. Called from
    /// `try_close` once all queued/in-flight writes have drained.
    fn perform_transform_flush(&mut self, ctx: &mut ScopedContext) -> Result<(), i32> {
        let Some(controller) = self.controller.get() else {
            return self.finish_transform_close(ctx, JSValue::UNDEFINED, false);
        };
        let cp = match controller.payload() {
            Some(p) => p,
            None => return self.finish_transform_close(ctx, JSValue::UNDEFINED, false),
        };
        let Some(mut tc) = cp.transform_controller.get() else {
            return self.finish_transform_close(ctx, JSValue::UNDEFINED, false);
        };

        // Spec step 3: if [[finishPromise]] already exists (e.g. a concurrent
        // readable.cancel()), return it — do not call flush().
        if let Some(tcp) = tc.payload()
            && let Some(fp) = tcp.finish_promise()
        {
            let stream_val = self.stream_value();
            let ok = ctx
                .create_native_function_with_data(
                    Callback::Func(flush_close_ok),
                    "flushCloseOk",
                    0,
                    0,
                    [stream_val].into(),
                )?
                .into();
            let err = ctx
                .create_native_function_with_data(
                    Callback::Func(flush_close_err),
                    "flushCloseErr",
                    1,
                    0,
                    [stream_val].into(),
                )?
                .into();
            let mut fp = fp;
            fp.perform_then(ctx, ok, err)?;
            return Ok(());
        }

        // Spec step 4: create [[finishPromise]] before calling flush.
        {
            let (fp, _) = Promise::create(ctx)?;
            let owner = JSValue::from(tc);
            if let Some(tcp) = tc.payload_mut() {
                tcp.set_finish_promise(ctx, owner, fp);
            }
        }

        let tcp = match tc.payload() {
            Some(p) => p,
            None => return self.finish_transform_close(ctx, JSValue::UNDEFINED, false),
        };
        let Some(tr) = tcp.transformer.get().as_object() else {
            return self.finish_transform_close(ctx, JSValue::UNDEFINED, false);
        };

        // flush() may throw synchronously: error the stream and reject the close.
        let mut flush_promise = match tr.invoke_str_callable(ctx, "flush", &[tc.into()]) {
            Ok(Some(Err(_))) | Err(_) => {
                let e = ctx.take_exception().to_value(ctx);
                return self.finish_transform_close(ctx, e, true);
            }
            Ok(Some(Ok(v))) => match Promise::try_from(v) {
                Ok(p) => p,
                Err(_) => Promise::from_resolve_value(ctx, v)?,
            },
            _ => Promise::from_resolve_value(ctx, JSValue::UNDEFINED)?,
        };

        // The readable side is closed only once flush settles (spec:
        // TransformStreamDefaultSinkCloseAlgorithm step 7 reacts to the flush
        // promise), so an enqueue whose size() triggered this close can still
        // push its chunk into the readable queue.
        let stream_val = self.stream_value();
        let ok = ctx
            .create_native_function_with_data(
                Callback::Func(flush_close_ok),
                "flushCloseOk",
                0,
                0,
                [stream_val].into(),
            )?
            .into();
        let err = ctx
            .create_native_function_with_data(
                Callback::Func(flush_close_err),
                "flushCloseErr",
                1,
                0,
                [stream_val].into(),
            )?
            .into();
        flush_promise.perform_then(ctx, ok, err)?;
        Ok(())
    }

    /// Settle a TransformStream close: on success close the writable and resolve
    /// the close promise; on `err` error the writable and reject it.
    fn finish_transform_close(
        &mut self,
        ctx: &mut ScopedContext,
        err: JSValue,
        is_err: bool,
    ) -> Result<(), i32> {
        self.in_flight_close = false;
        if is_err {
            if let Some(mut cp) = self.close_promise.take() {
                cp.reject(ctx, err);
            }
            if self.state == RsState::Readable {
                self.start_erroring(ctx, err)?;
            }
            return Ok(());
        }
        if let Some(mut cp) = self.close_promise.take() {
            cp.resolve(ctx, JSValue::UNDEFINED);
        }
        self.state = RsState::Closed;
        if let Some(w) = self.writer.get() {
            let mut wv = JSValue::from(w);
            if let Some(wp) = JSWritableStreamDefaultWriter::payload_mut_of(&mut wv)
                && let Some(mut c) = wp.closed_promise.get()
                && c.state() == PromiseState::Pending
            {
                c.resolve(ctx, JSValue::UNDEFINED);
            }
        }
        Ok(())
    }

    /// Mirror of WHATWG `WritableStreamDefaultControllerProcessWrite`: invoke the
    /// sink's `write(chunk)` synchronously and chain its result onto the
    /// in-flight write promise. `original_promise` is the promise returned to JS
    /// by `writer.write()`; it is settled directly (before `ready`) when the
    /// sink write completes.
    fn process_write(
        &mut self,
        ctx: &mut ScopedContext,
        chunk: JSValue,
        original_promise: Promise,
    ) -> Result<(), i32> {
        let controller_val = match self.controller.get() {
            Some(c) => JSValue::from(c),
            None => {
                if let Some(mut p) = self.in_flight_write_request.take() {
                    p.reject(ctx, JSValue::UNDEFINED);
                }
                return Ok(());
            }
        };
        let stream_val = match JSWritableStreamDefaultController::payload_of(&controller_val)
            .and_then(|cp| cp.stream)
        {
            Some(s) => JSValue::from(s),
            None => {
                if let Some(mut p) = self.in_flight_write_request.take() {
                    p.reject(ctx, JSValue::UNDEFINED);
                }
                return Ok(());
            }
        };
        let sink_val = match JSWritableStreamDefaultController::payload_of(&controller_val)
            .map(|cp| cp.underlying_sink.get())
        {
            Some(s) => s,
            None => {
                if let Some(mut p) = self.in_flight_write_request.take() {
                    p.reject(ctx, JSValue::UNDEFINED);
                }
                return Ok(());
            }
        };

        // Create a fresh promise + resolve/reject pair for the in-flight sink
        // write. When it settles, `finish_in_flight_write` settles this promise
        // via the resolve/reject functions embedded in its binding data, and
        // settles `original_promise` directly (before `ready`).
        let (write_p, write_funcs) = Promise::create(ctx)?;
        self.set_in_flight_write_request(ctx, write_p);
        let resolve = write_funcs[0];
        let reject = write_funcs[1];
        Self::chain_write_result(
            ctx,
            sink_val,
            chunk,
            controller_val,
            stream_val,
            resolve,
            reject,
            original_promise,
        )?;
        Ok(())
    }

    /// Settle the in-flight write and clear the in-flight slot, then error the
    /// stream on rejection or advance the queue on success.
    ///
    /// Handles `(resolve, reject, stream_val)` live in `cc.data(0..2)`;
    /// `cc.data(3)` is the ok flag (`undefined` = ok, anything else = error);
    /// `cc.data(4)` is the original `write()` promise; the value/reason is
    /// `cc.arg(0)`. On success the original write promise is resolved BEFORE the
    /// writer's `ready` (via backpressure), so its reactions run first (spec
    /// ordering). On failure the stream is errored when still writable.
    fn finish_in_flight_write(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
        let ok = cc.data(3).is_undefined();
        let value = cc.arg(0);
        let resolve = cc.data(0);
        let reject = cc.data(1);
        let mut stream_val = cc.data(2);
        let orig = cc.data(4);

        if ok {
            resolve.call(ctx, JSValue::UNDEFINED, &[JSValue::UNDEFINED])?;
            if let Ok(mut op) = Promise::try_from(orig)
                && op.state() == PromiseState::Pending
            {
                op.resolve(ctx, JSValue::UNDEFINED);
            }
        } else {
            reject.call(ctx, JSValue::UNDEFINED, &[value])?;
            if let Ok(mut op) = Promise::try_from(orig)
                && op.state() == PromiseState::Pending
            {
                op.reject(ctx, value);
            }
        }

        if let Some(sp) = JSWritableStream::payload_mut_of(&mut stream_val) {
            sp.clear_in_flight_write_request(ctx);
            // The in-flight write has settled; its size now leaves the total.
            sp.queue_total_size -= sp.in_flight_write_size;
            if sp.queue_total_size < 0.0 {
                sp.queue_total_size = 0.0;
            }
            sp.in_flight_write_size = 0.0;
            if ok {
                // Per spec `WritableStreamDefaultControllerProcessWrite` cleanup:
                // recompute backpressure (resolves `ready` when it drops) unless a
                // close is queued/in flight.
                if sp.state == RsState::Readable && !sp.close_requested {
                    sp.update_backpressure(ctx);
                }
                sp.advance_queue(ctx)?;
            } else {
                // A rejected sink write errors the stream (spec
                // `WritableStreamDealWithRejection`): a writable stream starts
                // erroring, an erroring one finishes erroring (rejecting queued
                // writes, the pending close, `ready` and `closed`). An
                // already-errored stream keeps its stored error.
                match sp.state {
                    RsState::Readable => sp.start_erroring(ctx, value)?,
                    RsState::Erroring => sp.finish_erroring(ctx)?,
                    _ => {}
                }
            }
        }
        Ok(JSValue::UNDEFINED)
    }

    /// Call `sink.write(chunk)` and chain its outcome onto the in-flight write
    /// promise (`resolve`/`reject`) and the original `write()` promise. On
    /// completion, advance the queue for the next queued chunk.
    fn chain_write_result(
        ctx: &mut ScopedContext,
        sink_val: JSValue,
        chunk: JSValue,
        controller_val: JSValue,
        stream_val: JSValue,
        resolve: JSValue,
        reject: JSValue,
        original_promise: Promise,
    ) -> Result<(), i32> {
        // `data` layout: [resolve, reject, stream_val, ok_flag, original_promise].
        // ok_flag is `undefined` for the success path (ok); a non-undefined value
        // (here 1) marks the error path, whose reason comes from `cc.arg(0)`.
        let data: Vec<JSValue> = [
            resolve,
            reject,
            stream_val,
            JSValue::UNDEFINED,
            JSValue::from(original_promise),
        ]
        .to_vec();
        let mut data_err = data.clone();
        data_err[3] = JSValue::from(1);

        if let Some(sink) = sink_val.as_object() {
            match sink.invoke_str_callable(ctx, "write", &[chunk, controller_val])? {
                Some(Ok(v)) => {
                    // Per spec `uponPromise`, the sink's return value is always
                    // treated as a promise, so the in-flight write settles on a
                    // microtask even when the sink returns synchronously. This
                    // lets a synchronous `abort()` (issued right after `write()`)
                    // take effect before the write completes, so queued writes
                    // are rejected instead of invoking the sink.
                    let mut p = if let Ok(p) = Promise::try_from(v) {
                        p
                    } else {
                        Promise::from_resolve_value(ctx, v)?
                    };
                    let on_ok = ctx.create_native_function_with_data(
                        Callback::Func(Self::finish_in_flight_write),
                        "writeOk",
                        0,
                        0,
                        data.into(),
                    )?;
                    let on_err = ctx.create_native_function_with_data(
                        Callback::Func(Self::finish_in_flight_write),
                        "writeErr",
                        0,
                        0,
                        data_err.into(),
                    )?;
                    p.perform_then(ctx, on_ok.into(), on_err.into())?;
                }
                Some(Err(_)) => {
                    let e = ctx.take_exception().to_value(ctx);
                    let on_err = ctx.create_native_function_with_data(
                        Callback::Func(Self::finish_in_flight_write),
                        "writeErr",
                        0,
                        0,
                        data_err.into(),
                    )?;
                    let noop = ctx.create_native_function_with_data(
                        Callback::Func(|_ctx, _cc| Ok(JSValue::UNDEFINED)),
                        "writeNoop",
                        0,
                        0,
                        [].into(),
                    )?;
                    // Reject via a microtask so abort can interleave.
                    let mut p = Promise::from_reject_value(ctx, e)?;
                    p.perform_then(ctx, noop.into(), on_err.into())?;
                }
                None => {
                    let mut p = Promise::from_resolve_value(ctx, JSValue::UNDEFINED)?;
                    let on_ok = ctx.create_native_function_with_data(
                        Callback::Func(Self::finish_in_flight_write),
                        "writeOk",
                        0,
                        0,
                        data.into(),
                    )?;
                    p.perform_then(ctx, on_ok.into(), on_ok.into())?;
                }
            }
        } else {
            // No underlying sink object: treat as an immediately-fulfilled write.
            let mut p = Promise::from_resolve_value(ctx, JSValue::UNDEFINED)?;
            let on_ok = ctx.create_native_function_with_data(
                Callback::Func(Self::finish_in_flight_write),
                "writeOk",
                0,
                0,
                data.into(),
            )?;
            p.perform_then(ctx, on_ok.into(), on_ok.into())?;
        }
        Ok(())
    }

    /// Abort this writable stream: settle it as Errored with `reason`, then
    /// propagate the underlying sink's `abort()` result (including a rejection)
    /// to the caller. Per spec `WritableStreamAbort`, aborting an already
    /// errored/closed stream is a no-op that resolves with undefined.
    pub(crate) fn abort(
        &mut self,
        ctx: &mut ScopedContext,
        reason: JSValue,
    ) -> Result<Promise, i32> {
        // Per spec `WritableStreamAbort`: aborting a closed/errored stream is a
        // no-op that resolves with undefined.
        if self.state == RsState::Closed || self.state == RsState::Errored {
            return Promise::from_resolve_value(ctx, JSValue::UNDEFINED);
        }
        // Signal abort synchronously on the controller's signal, before any
        // state change, so observers see a consistent state.
        if let Some(controller) = self.controller.get()
            && let Some(cp) = controller.payload()
            && let Some(signal) = cp.signal.get()
        {
            crate::abort::abort_signal(ctx, signal, reason)?;
        }
        // Re-check the state: signaling abort runs author code that may have
        // changed it.
        if self.state == RsState::Closed || self.state == RsState::Errored {
            return Promise::from_resolve_value(ctx, JSValue::UNDEFINED);
        }
        // Repeated aborts return the same pending promise.
        if let Some(req) = &self.pending_abort {
            return Ok(req.promise.get());
        }
        // When already erroring, the abort's reason is ignored.
        let was_already_erroring = self.state == RsState::Erroring;
        let reason = if was_already_erroring {
            JSValue::UNDEFINED
        } else {
            reason
        };
        let (promise, _rr) = Promise::create(ctx)?;
        // The guard slots record the stream→promise/reason barriers.
        let owner = self.owner.unwrap_or(JSValue::UNDEFINED);
        let mut req = PendingAbort {
            promise: WriteBarrier::new(promise),
            reason: WriteBarrier::new(reason),
            was_already_erroring,
        };
        req.promise.set(ctx, owner, promise);
        req.reason.set(ctx, owner, reason);
        self.pending_abort = Some(req);
        if !was_already_erroring {
            self.start_erroring(ctx, reason)?;
        }
        Ok(promise)
    }

    /// Shared close logic for `WritableStream.close()` / `writer.close()`.
    /// Per spec `WritableStreamClose`: rejects with TypeError when the stream is
    /// already closed/errored or a close is queued/in flight; otherwise requests
    /// a deferred close that runs the sink's `close()` (or a transform's
    /// `flush`) once all writes drain.
    pub(crate) fn close(&mut self, ctx: &mut ScopedContext) -> Result<Promise, i32> {
        // Spec: state "closed" or "errored" -> rejected TypeError.
        if self.state == RsState::Closed || self.state == RsState::Errored {
            let err = ctx
                .create_error_object(
                    zuqe::ErrorKind::Type,
                    "Cannot close a WritableStream that is already closed or errored",
                    false,
                )
                .map(JSValue::from)
                .unwrap_or(JSValue::UNDEFINED);
            return Promise::from_reject_value(ctx, err);
        }
        // Spec: CloseQueuedOrInFlight -> rejected TypeError.
        if self.close_requested || self.in_flight_close {
            let err = ctx
                .create_error_object(
                    zuqe::ErrorKind::Type,
                    "Cannot close a WritableStream while a close is already pending",
                    false,
                )
                .map(JSValue::from)
                .unwrap_or(JSValue::UNDEFINED);
            return Promise::from_reject_value(ctx, err);
        }

        // Request a deferred close. For a TransformStream the transformer's
        // `flush()` (then the readable close) runs from `try_close` once all
        // queued/in-flight writes have drained; for a plain stream the sink's
        // `close()` runs there. `try_close` performs it now if already drained.
        let (close_p, _close_funcs) = Promise::create(ctx)?;
        self.close_requested = true;
        // The guard slot records the barrier (no handle yet: UNDEFINED = no-op bind).
        let owner = self.owner.unwrap_or(JSValue::UNDEFINED);
        self.close_promise.set(ctx, owner, Some(close_p));
        // Spec WritableStreamClose: if backpressured, resolve `ready` in place.
        if self.backpressure
            && let Some(mut w) = self.writer.get()
            && let Some(wp) = w.payload_mut()
            && let Some(mut rp) = wp.ready_promise.get()
            && rp.state() == PromiseState::Pending
        {
            rp.resolve(ctx, JSValue::UNDEFINED);
        }
        self.try_close(ctx)?;
        Ok(close_p)
    }
}



// flush fulfilled: close the readable side of the transform stream and mark
// the writable stream closed, per spec (close after flush resolves).
fn flush_close_ok(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut stream_val = cc.data(0);
    {
        if let Some(sp) = JSWritableStream::payload_mut_of(&mut stream_val)
            && let Some(controller) = sp.controller.get()
            && let Some(cp) = controller.payload()
            && let Some(tc) = cp.transform_controller.get()
            && let Some(tcp) = tc.payload()
            && let Some(rcp) = tcp.readable_controller.get().payload()
        {
            rcp.set_close_requested(true);
            rcp.resolve_pending_read(ctx, JSValue::UNDEFINED, true);
            if rcp.queue().borrow().is_empty()
                && let Some(mut rs_val) = rcp.stream()
                && let Some(rsp) = rs_val.payload_mut()
            {
                rsp.state = RsState::Closed;
            }
        }
    }
    WritableStreamPayload::finish_close(ctx, &mut stream_val, true, JSValue::UNDEFINED)
}

// flush rejected: error the writable stream with the flush error and reject the
// close promise.
fn flush_close_err(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut stream_val = cc.data(0);
    let err = cc.arg(0);

    if let Some(sp) = JSWritableStream::payload_mut_of(&mut stream_val) {
        sp.in_flight_close = false;
        if let Some(mut cp) = sp.close_promise.take() {
            cp.reject(ctx, err);
        }
        sp.state = RsState::Errored;
        // The guard slot records the barrier (no handle yet: UNDEFINED = no-op bind).
        let owner = sp.owner.unwrap_or(JSValue::UNDEFINED);
        sp.stored_error.set(ctx, owner, err);
        if let Some(w) = sp.writer.get() {
            let mut wv = JSValue::from(w);
            if let Some(wp) = JSWritableStreamDefaultWriter::payload_mut_of(&mut wv) {
                wp.ensure_closed_rejected(ctx, err);
            }
        }
    }
    Ok(JSValue::UNDEFINED)
}

const WRITABLE_STREAM_PROTO: &[FieldDef] = &[
    FieldDef::GETSET_ENUM("locked", Some(js_writable_stream_locked), None, 0),
    FieldDef::FUNC_ENUM("getWriter", 0, js_writable_stream_get_writer, 0),
    FieldDef::FUNC_ENUM("abort", 1, js_writable_stream_abort, 0),
    FieldDef::FUNC_ENUM("close", 0, js_writable_stream_close, 0),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "WritableStream",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "WritableStream",
    JSWritableStream,
    WritableStreamPayload,
    WRITABLE_STREAM_PROTO,
    Some(ClassCtorDef::new(js_writable_stream_constructor, 1, false).expose_to_global())
);

/// `def_native_object!` generates no `GcBind`, but the transform controller
/// payload's `WriteBarrier<JSWritableStream>` slot needs one.
impl GcBind for JSWritableStream {
    fn bind_node(&self, ctx: &ScopedContext, owner: std::ptr::NonNull<zuqe::gc_lite::GcHead>) {
        GcBind::bind_node(self.as_object(), ctx, owner)
    }
}

impl JSWritableStream {
    /// Lock this stream by creating and installing a default writer.
    ///
    /// Errors with TypeError if the stream is already locked. The returned
    /// writer settles its `closed_promise` from the current `state`
    /// (`stored_error` on Errored).
    pub(crate) fn acquire_writer(
        &mut self,
        ctx: &mut ScopedContext,
    ) -> Result<JSWritableStreamDefaultWriter, i32> {
        let handle = *self;

        let sp = self
            .payload_mut()
            .ok_or_else(|| ctx.throw_type_error("not a WritableStream"))?;

        if sp.writer.get().is_some() {
            return Err(ctx.throw_type_error("WritableStream is already locked"));
        }

        // Per spec `SetUpWritableStreamDefaultWriter`, the writer's promises
        // depend on the current state:
        //  - writable, not backpressured: `ready` is a resolved promise;
        //  - writable, backpressured (or close pending): `ready` is a fresh
        //    pending promise;
        //  - erroring/errored: `ready` rejected with the stored error;
        //  - closed: `ready`/`closed` resolved; errored: both rejected.
        let (ready_promise, closed_promise) = match sp.state {
            RsState::Readable => {
                let backpressured = sp.close_requested || sp.current_backpressure();
                sp.backpressure = backpressured;
                let ready = if backpressured {
                    Promise::create(ctx)?.0
                } else {
                    Promise::from_resolve_value(ctx, JSValue::UNDEFINED)?
                };
                let closed = Promise::create(ctx)?.0;
                (ready, closed)
            }
            RsState::Closed => (
                Promise::from_resolve_value(ctx, JSValue::UNDEFINED)?,
                Promise::from_resolve_value(ctx, JSValue::UNDEFINED)?,
            ),
            RsState::Erroring | RsState::Errored => {
                let e = sp.stored_error.get();
                (
                    Promise::from_reject_value(ctx, e)?,
                    Promise::from_reject_value(ctx, e)?,
                )
            }
        };

        let mut writer = JSWritableStreamDefaultWriter::new_instance(
            ctx,
            JSValue::UNDEFINED,
            WriterPayload {
                stream: Some(handle),
                closed_promise: WriteBarrier::new(Some(closed_promise)),
                ready_promise: WriteBarrier::new(Some(ready_promise)),
                write_promise: WriteBarrier::new(None),
                abort_promise: WriteBarrier::new(None),
                owner: None,
            },
        )?;

        // Self-handle for the write barriers in the payload methods.
        let writer_val = JSValue::from(writer);
        if let Some(wp) = writer.payload_mut() {
            wp.owner = Some(writer_val);
        }
        // The guard slot records the barrier (no handle yet: UNDEFINED = no-op bind).
        let owner = sp.owner.unwrap_or(JSValue::UNDEFINED);
        sp.writer.set(ctx, owner, Some(writer));

        Ok(writer)
    }
}

fn js_writable_stream_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let new_target = cc.this();
    let underlying_sink = cc.arg(0);
    let queuing_strategy = cc.arg(1);
    let hwm = extract_high_water_mark(ctx, queuing_strategy, 1.0)?;

    // WritableStreamInit: any non-undefined `type` (e.g. "bytes") is unsupported
    // by this engine and must throw RangeError ("is not a supported type").
    if let Some(o) = underlying_sink.as_object() {
        let t = o.get_property_str(ctx, "type")?;
        if !t.is_undefined() && !t.is_null() {
            return Err(ctx.throw_range_error(
                "WritableStream with the given type is not supported: 'bytes' streams are not implemented",
            ));
        }
    }

    let size_algo = extract_size_algorithm(ctx, queuing_strategy)?;

    let mut stream = JSWritableStream::new_instance(ctx, new_target, WritableStreamPayload::new())?;
    // Self-handle for the write barriers in the payload methods.
    let stream_val = JSValue::from(stream);
    if let Some(sp) = stream.payload_mut() {
        sp.owner = Some(stream_val);
    }
    let controller = JSWritableStreamDefaultController::new_instance(
        ctx,
        JSValue::UNDEFINED,
        WritableControllerPayload::new(underlying_sink, Some(stream), hwm, size_algo),
    )?;

    // SetUpWritableStreamDefaultControllerFromUnderlyingSink: capture the sink's
    // `write`/`close`/`abort` callbacks once, so a throwing getter re-throws from
    // the constructor and later writes/closes/aborts do not re-run the getter. A
    // present but non-callable callback member throws TypeError (WebIDL).
    if let Some(o) = underlying_sink.as_object() {
        for method in ["write", "close", "abort"] {
            let v = o.get_property_str(ctx, method)?;
            if !v.is_undefined() && !v.is_callable() {
                let msg = [method, " must be a function"].concat();
                return Err(ctx.throw_type_error(&msg));
            }
        }
    }

    // Invoke the sink `start(controller)` **synchronously** so the controller is
    // observable immediately (e.g. `start(c) { ctrl = c }`). Per spec the stream
    // is only considered "started" (`_started === true`) after `start` finishes:
    // writes/closes issued before that point are enqueued (and count toward
    // `desiredSize`) but not handed to the sink until `start` resolves. A thrown
    // `start()` is re-thrown by the WritableStream() constructor.
    // `invoke_str_defined` returns `Ok(Some(Err))` when start throws, so the
    // inner JSResult must be unwrapped via `?`.
    let start_val = if let Some(o) = underlying_sink.as_object() {
        match o.invoke_str_defined(ctx, "start", &[JSValue::from(controller)])? {
            Some(r) => r?,
            None => JSValue::UNDEFINED,
        }
    } else {
        JSValue::UNDEFINED
    };

    // Defer `started = true` + queue advance to after `start` settles, so a
    // `write()` issued synchronously after construction is enqueued (matching
    // spec `_started` gating) and a following synchronous `abort()` can reject
    // it before the sink `write()` is ever called. For a synchronous `start`
    // (no promise returned) this runs on the next microtask; for an async
    // `start` it runs when the returned promise fulfills.
    let start_fn = ctx.create_native_function_with_data(
        Callback::Func(|_ctx, cc| {
            let mut stream_val = cc.data(0);
            if let Some(sp) = JSWritableStream::payload_mut_of(&mut stream_val) {
                sp.started = true;
                sp.advance_queue(_ctx)?;
                sp.try_close(_ctx)?;
                // `writer.ready` is driven by backpressure (`update_backpressure`
                // on enqueue/settle); no explicit resolution needed here.
            }
            Ok(JSValue::UNDEFINED)
        }),
        "writableStart",
        0,
        0,
        [JSValue::from(stream)].into(),
    )?;
    let start_err_fn = ctx.create_native_function_with_data(
        Callback::Func(|_ctx, cc| {
            let mut stream_val = cc.data(0);
            let e = cc.arg(0);
            // Per spec `SetUpWritableStreamDefaultController`: a rejected start
            // marks the stream started, then errors it (`DealWithRejection`),
            // rejecting queued writes, `ready` and `closed`.
            if let Some(sp) = JSWritableStream::payload_mut_of(&mut stream_val) {
                sp.started = true;
                sp.start_erroring(_ctx, e)?;
            }
            Ok(JSValue::UNDEFINED)
        }),
        "writableStartErr",
        1,
        0,
        [JSValue::from(stream)].into(),
    )?;

    if let Ok(mut p) = Promise::try_from(start_val) {
        p.perform_then(ctx, start_fn.into(), start_err_fn.into())?;
    } else {
        // Synchronous start (undefined / non-thenable): arm via a resolved
        // promise so it still defers past construction.
        // Use perform_then to avoid calling user-visible Promise.prototype.then.
        let mut resolved = Promise::from_resolve_value(ctx, JSValue::UNDEFINED)?;
        resolved.perform_then(ctx, start_fn.into(), JSValue::UNDEFINED)?;
    }

    if let Some(sp) = stream.payload_mut() {
        sp.set_controller(ctx, stream_val, controller);
    }

    Ok(stream.into())
}

fn js_writable_stream_locked(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSWritableStream::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("not a WritableStream"))?;
    Ok(JSValue::from(p.writer.get().is_some()))
}

fn js_writable_stream_get_writer(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    JSWritableStream::from_value(cc.this())
        .ok_or_else(|| ctx.throw_type_error("not a WritableStream"))?
        .acquire_writer(ctx)
        .map(JSValue::from)
}

fn js_writable_stream_abort(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut this = cc.this();
    let reason = cc.arg(0);

    let sp = JSWritableStream::payload_mut_of(&mut this)
        .ok_or_else(|| ctx.throw_type_error("not a WritableStream"))?;

    // Per spec: "If ! IsWritableStreamLocked(this) is true, return a
    // promise rejected with a TypeError exception."
    if sp.writer.get().is_some() {
        let err = ctx
            .create_error_object(
                zuqe::ErrorKind::Type,
                "Cannot abort a locked WritableStream",
                false,
            )
            .map(JSValue::from)
            .unwrap_or(JSValue::UNDEFINED);
        return Promise::from_reject_value(ctx, err).map(JSValue::from);
    }

    sp.abort(ctx, reason).map(JSValue::from)
}

fn js_writable_stream_close(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut this = cc.this();
    if let Some(stream) = JSWritableStream::payload_mut_of(&mut this) {
        // Per spec `WritableStream.close`: closing a locked stream rejects with
        // a TypeError.
        if stream.writer.get().is_some() {
            let err = ctx
                .create_error_object(
                    zuqe::ErrorKind::Type,
                    "Cannot close a locked WritableStream",
                    false,
                )
                .map(JSValue::from)
                .unwrap_or(JSValue::UNDEFINED);
            return Promise::from_reject_value(ctx, err).map(JSValue::from);
        }
        return stream.close(ctx).map(JSValue::from);
    }
    Err(ctx.throw_type_error("not a WritableStream"))
}

#[cfg(all(test, debug_assertions))]
mod gc_barrier_tests {
    use zuqe::{Context, EvalFlags, EvalName, EvalType, NativeObject, Runtime, ScopedContext};

    use super::JSWritableStream;

    #[test]
    fn in_flight_write_request_write_barrier_survives_a_minor() -> Result<(), i32> {
        let mut rt = Runtime::create()?;
        let mut ctx: Context<'static> = rt.create_context(ScopedContext::ECMA_CONTEXT_SETUP)?;

        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            let global = cx.global_obj();
            crate::init_whatwg(&mut cx, global)?;
            cx.eval(
                b"globalThis.__ws = new WritableStream({\n\
                    write() { return new Promise(r => { globalThis.__resolveWrite = r; }); }\n\
                  });\n\
                  globalThis.__writer = globalThis.__ws.getWriter();",
                &EvalName::Name("ws-iflight-barrier-setup".to_string()),
                EvalType::Global,
                EvalFlags::empty(),
            )?;
            Ok(())
        })?;
        // Let start settle so queued writes can become in-flight.
        rt.tick();

        // Promote the stream to old generation before the in-flight write promise is created.
        let _ = rt.gc_minor_now();

        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            cx.eval(
                b"globalThis.__writeP = globalThis.__writer.write('x');",
                &EvalName::Name("ws-iflight-barrier-write".to_string()),
                EvalType::Global,
                EvalFlags::empty(),
            )?;
            Ok(())
        })?;
        rt.tick();

        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            let ws_v = cx.eval(
                b"globalThis.__ws",
                &EvalName::Name("ws-iflight-barrier-stream".to_string()),
                EvalType::Global,
                EvalFlags::empty(),
            )?;
            let ws = JSWritableStream::from_value(ws_v).ok_or(-1)?;
            let p = ws.payload().ok_or(-1)?;
            assert!(
                p.in_flight_write_request.get().is_some(),
                "write() must install an in-flight promise (started={}, q={}, reqs={})",
                p.started,
                p.write_queue.len(),
                p.write_requests.len()
            );
            Ok(())
        })?;

        // A minor GC must not reclaim the young in-flight promise referenced by the old stream.
        let _ = rt.gc_minor_now();

        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            cx.eval(
                b"globalThis.__resolveWrite();",
                &EvalName::Name("ws-iflight-barrier-resolve".to_string()),
                EvalType::Global,
                EvalFlags::empty(),
            )?;
            Ok(())
        })?;
        rt.tick();

        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            let ws_v = cx.eval(
                b"globalThis.__ws",
                &EvalName::Name("ws-iflight-barrier-check".to_string()),
                EvalType::Global,
                EvalFlags::empty(),
            )?;
            let ws = JSWritableStream::from_value(ws_v).ok_or(-1)?;
            assert!(
                ws.payload()
                    .and_then(|p| p.in_flight_write_request.get())
                    .is_none(),
                "settled write must clear the in-flight promise"
            );
            Ok(())
        })
    }
}
