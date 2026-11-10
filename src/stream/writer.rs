// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WritableStreamDefaultWriter: the writer handle returned by
//! `WritableStream.getWriter()`.

use zuqe::{
    CallContext, ClassCtorDef, FieldDef, GcBind, JSResult, JSValue, NativeObject, ScopedContext,
    WriteBarrier,
    builtins::promise::{Promise, PromiseState},
    def_native_object,
    gc_lite::GcTrace,
};

use crate::stream::writable::JSWritableStream;

use super::RsState;

#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct WriterPayload {
    pub(super) stream: Option<JSWritableStream>,
    pub(crate) closed_promise: WriteBarrier<Option<Promise>>,
    /// `writer.ready`: fulfilled while the stream is writable, rejected on
    /// abort/error. Per the Streams spec, when the stream is aborted the
    /// pending `ready` is rejected in place; if `ready` was already settled,
    /// it is replaced by a fresh rejected promise.
    pub(crate) ready_promise: WriteBarrier<Option<Promise>>,
    /// The promise of the most recent in-flight `write()`, kept so that an
    /// abort/error can reject it (spec: outstanding write() promises reject).
    pub(crate) write_promise: WriteBarrier<Option<Promise>>,
    /// Memoized `writer.abort()` result. Per spec, repeated `writer.abort()`
    /// calls return the *same* promise.
    pub(crate) abort_promise: WriteBarrier<Option<Promise>>,
    /// The writer object's own handle, set right after construction. Payload
    /// methods store fresh (young) promises into this possibly-already-old
    /// writer, so the write barrier needs the owner node.
    #[gc(skip)]
    pub(crate) owner: Option<JSValue>,
}

impl WriterPayload {
    /// Abort the stream this writer is locked to, forwarding `reason`.
    ///
    /// Returns the underlying stream's abort result. If the writer is not
    /// locked to any stream, resolves with `undefined`.
    /// `writer.abort(reason)` — per spec `WritableStreamDefaultWriterAbort`.
    ///
    /// A released writer returns a rejected promise (TypeError), not a throw.
    /// Repeated `writer.abort()` calls return the *same* memoized promise. The
    /// result settles per `WritableStreamAbort`: the abort promise fulfills
    /// with `undefined` once the sink's `abort()` settles, or rejects with the
    /// sink's error if the sink's `abort()` rejects/throws.
    pub(crate) fn abort(
        &mut self,
        ctx: &mut ScopedContext,
        reason: JSValue,
    ) -> Result<Promise, i32> {
        // Released writer: abort returns a rejected promise (spec), not a throw.
        let Some(mut stream) = self.stream else {
            let err = Self::released_error(ctx);
            return Promise::from_reject_value(ctx, err);
        };

        // Memoize: repeated `writer.abort()` calls return the *same* promise.
        if let Some(ap) = self.abort_promise.get() {
            return Ok(ap);
        }

        let sp = stream.payload_mut().unwrap();
        let abort_p = sp.abort(ctx, reason)?;
        // The guard slot records the barrier (no handle yet: UNDEFINED = no-op bind).
        let owner = self.owner.unwrap_or(JSValue::UNDEFINED);
        self.abort_promise.set(ctx, owner, Some(abort_p));
        Ok(abort_p)
    }

    /// Per spec `WritableStreamDefaultWriterEnsureReadyPromiseRejected`: reject
    /// `ready` in place when pending; otherwise replace it with a fresh promise
    /// rejected with `error`.
    pub(crate) fn ensure_ready_rejected(&mut self, ctx: &mut ScopedContext, error: JSValue) {
        if let Some(mut p) = self.ready_promise.get() {
            if p.state() == PromiseState::Pending {
                p.reject(ctx, error);
            } else if let Ok(rp) = Promise::from_reject_value(ctx, error) {
                // The guard slot records the barrier (no handle yet: UNDEFINED = no-op bind).
                let owner = self.owner.unwrap_or(JSValue::UNDEFINED);
                self.ready_promise.set(ctx, owner, Some(rp));
            }
        }
    }

    /// Per spec `WritableStreamDefaultWriterEnsureClosedPromiseRejected`: reject
    /// `closed` in place when pending; otherwise replace it with a fresh promise
    /// rejected with `error`.
    pub(crate) fn ensure_closed_rejected(&mut self, ctx: &mut ScopedContext, error: JSValue) {
        if let Some(mut p) = self.closed_promise.get() {
            if p.state() == PromiseState::Pending {
                p.reject(ctx, error);
            } else if let Ok(rp) = Promise::from_reject_value(ctx, error) {
                // The guard slot records the barrier (no handle yet: UNDEFINED = no-op bind).
                let owner = self.owner.unwrap_or(JSValue::UNDEFINED);
                self.closed_promise.set(ctx, owner, Some(rp));
            }
        }
    }

    /// The error used when a writer is released and a monitoring getter
    /// (`closed`/`ready`/`desiredSize`) is accessed. Per the Streams spec
    /// (`defaultWriterLockException`), this is a TypeError: a released writer
    /// can no longer be used to monitor the stream's state.
    fn released_error(ctx: &mut ScopedContext) -> JSValue {
        ctx.create_error_object(
            zuqe::ErrorKind::Type,
            "Writer is released and cannot be used to monitor the stream's closedness",
            false,
        )
        .map(JSValue::from)
        .unwrap_or(JSValue::UNDEFINED)
    }

    /// Release this writer's lock on its stream: detach the stream, clear the
    /// stream's back-reference to this writer, and initialize `closed`/`ready`
    /// to rejected promises (spec `WritableStreamDefaultWriterRelease` invokes
    /// `defaultWriterClosedPromiseInitializeToRejected` / `...Ready...` with a
    /// released-writer TypeError). `desiredSize` throws on access once `stream`
    /// is `None`.
    pub(crate) fn release_lock(&mut self, ctx: &mut ScopedContext) {
        if let Some(mut stream_val) = self.stream.take()
            && let Some(sp) = stream_val.payload_mut()
        {
            sp.writer.take();
        }
        // Per spec `WritableStreamDefaultWriterRelease`, a released writer's
        // `ready`/`closed` are rejected with a released-writer TypeError: in
        // place when still pending, otherwise replaced.
        let err = Self::released_error(ctx);
        self.ensure_ready_rejected(ctx, err);
        self.ensure_closed_rejected(ctx, err);
    }
}



const WRITER_PROTO: &[FieldDef] = &[
    FieldDef::FUNC_ENUM("write", 1, js_writer_write, 0),
    FieldDef::FUNC_ENUM("close", 0, js_writer_close, 0),
    FieldDef::FUNC_ENUM("abort", 1, js_writer_abort, 0),
    FieldDef::FUNC_ENUM("releaseLock", 0, js_writer_release_lock, 0),
    FieldDef::GETSET_ENUM("closed", Some(js_writer_closed), None, 0),
    FieldDef::GETSET_ENUM("ready", Some(js_writer_ready), None, 0),
    FieldDef::GETSET_ENUM("desiredSize", Some(js_writer_desired_size), None, 0),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "WritableStreamDefaultWriter",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

fn js_writer_closed(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSWritableStreamDefaultWriter::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("not a WritableStream writer"))?;
    // Released writer: `closed` is a rejected promise (set on release_lock).
    if p.stream.is_none() {
        if let Some(cp) = p.closed_promise.get() {
            return Ok(JSValue::from(cp));
        }
        return Ok(JSValue::UNDEFINED);
    }
    if let Some(cp) = p.closed_promise.get() {
        return Ok(JSValue::from(cp));
    }
    Ok(JSValue::UNDEFINED)
}

fn js_writer_ready(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSWritableStreamDefaultWriter::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("not a WritableStream writer"))?;
    // Released writer: `ready` is a rejected promise (set on release_lock).
    if p.stream.is_none() {
        if let Some(rp) = p.ready_promise.get() {
            return Ok(JSValue::from(rp));
        }
        return Ok(JSValue::UNDEFINED);
    }
    if let Some(rp) = p.ready_promise.get() {
        return Ok(JSValue::from(rp));
    }
    Ok(JSValue::UNDEFINED)
}

fn js_writer_desired_size(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSWritableStreamDefaultWriter::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("not a WritableStream writer"))?;
    // Released writer: `desiredSize` throws a TypeError (spec:
    // `defaultWriterLockException`).
    let stream_val = p.stream.ok_or_else(|| {
        ctx.throw_type_error(
            "Writer is released and cannot be used to monitor the stream's closedness",
        )
    })?;
    if let Some(sp) = stream_val.payload() {
        // Spec: errored/erroring -> null, closed -> 0, else highWaterMark.
        match sp.state {
            RsState::Errored | RsState::Erroring => return Ok(JSValue::NULL),
            RsState::Closed => return Ok(JSValue::ZERO),
            RsState::Readable => {}
        }
        if let Some(ctrl) = sp.controller.get()
            && let Some(cp) = ctrl.payload()
        {
            // Spec: desiredSize = highWaterMark − total queued chunk size.
            return Ok(JSValue::from(cp.high_water_mark - sp.queue_total_size));
        }
    }
    Ok(JSValue::from(1))
}

fn js_writer_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let new_target = cc.this();

    let mut stream = JSWritableStream::from_value(cc.arg(0)).ok_or_else(|| {
        ctx.throw_type_error("WritableStreamDefaultWriter requires a WritableStream")
    })?;
    let handle = stream;

    // Per spec `SetUpWritableStreamDefaultWriter`: the stream must not be
    // locked; otherwise throw a TypeError.
    let (ready_promise, closed_promise) = {
        let sp = stream
            .payload_mut()
            .ok_or_else(|| ctx.throw_type_error("not a WritableStream"))?;
        if sp.writer.get().is_some() {
            return Err(ctx.throw_type_error("WritableStream is already locked"));
        }
        match sp.state {
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
        }
    };

    let mut writer = JSWritableStreamDefaultWriter::new_instance(
        ctx,
        new_target,
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
    if let Some(sp) = stream.payload_mut() {
        // The guard slot records the barrier (no handle yet: UNDEFINED = no-op bind).
        let owner = sp.owner.unwrap_or(JSValue::UNDEFINED);
        sp.writer.set(ctx, owner, Some(writer));
    }
    Ok(writer_val)
}

def_native_object!(
    "WritableStreamDefaultWriter",
    JSWritableStreamDefaultWriter,
    WriterPayload,
    WRITER_PROTO,
    Some(ClassCtorDef::new(js_writer_constructor, 0, false).expose_to_global())
);

/// `def_native_object!` generates no `GcBind`, but the payload's
/// `WriteBarrier<Option<…>>` slot needs one: the edge is owner → this object
/// node, identical to `Object`'s, so delegate.
impl GcBind for JSWritableStreamDefaultWriter {
    fn bind_node(&self, ctx: &ScopedContext, owner: std::ptr::NonNull<zuqe::gc_lite::GcHead>) {
        GcBind::bind_node(self.as_object(), ctx, owner)
    }
}

fn js_writer_write(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let chunk = cc.arg(0);
    let mut this = cc.this();

    let wp = JSWritableStreamDefaultWriter::payload_mut_of(&mut this)
        .ok_or_else(|| ctx.throw_type_error("not a WritableStreamDefaultWriter"))?;

    // The promise returned by `write()`, kept on the payload so an abort/error
    // can reject any outstanding (in-flight) write.
    let (mut write_p, _) = Promise::create(ctx)?;
    // The guard slot records the barrier (no handle yet: UNDEFINED = no-op bind).
    let owner = wp.owner.unwrap_or(JSValue::UNDEFINED);
    wp.write_promise.set(ctx, owner, Some(write_p));

    // Released writer: `write()` returns a rejected promise (spec).
    let Some(stream_handle) = wp.stream else {
        let err = ctx
            .create_error_object(zuqe::ErrorKind::Type, "Writer is released", false)
            .map(JSValue::from)
            .unwrap_or(JSValue::UNDEFINED);
        write_p.reject(ctx, err);
        return Ok(JSValue::from(write_p));
    };
    let mut stream_val = JSValue::from(stream_handle);

    // Normal writable path. Per spec `WritableStreamDefaultWriterWrite`: the
    // chunk size is computed FIRST (a throwing/invalid size errors the stream),
    // then the writer's stream is re-checked and the stream state validated;
    // only then is the write promise enqueued.
    if let Some(sp) = JSWritableStream::payload_mut_of(&mut stream_val) {
        // 1. Compute the chunk's size via the strategy's `size` algorithm
        //    (default 1). A throwing `size()` errors the stream (spec
        //    `WritableStreamDefaultControllerErrorIfNeeded`); `write()` returns
        //    a rejecting promise with the thrown error, never throws.
        let size = if let Some(ctrl) = sp.controller.get()
            && let Some(cp) = ctrl.payload()
        {
            if cp.size_algorithm.is_callable() {
                match cp.size_algorithm.call(ctx, JSValue::UNDEFINED, &[chunk]) {
                    Ok(v) => v.to_number(ctx)?.to_f64(),
                    Err(_) => {
                        let e = ctx.take_exception().to_value(ctx);
                        sp.start_erroring(ctx, e)?;
                        write_p.reject(ctx, e);
                        return Ok(JSValue::from(write_p));
                    }
                }
            } else {
                1.0
            }
        } else {
            1.0
        };

        // 2. The `size()` algorithm may have released/relocked the writer: if
        //    the writer's stream changed, reject with a TypeError (spec
        //    `If stream is not equal to writer.[[stream]]`).
        if wp.stream != Some(stream_handle) {
            let err = ctx
                .create_error_object(
                    zuqe::ErrorKind::Type,
                    "Writer is no longer locked to this stream",
                    false,
                )
                .map(JSValue::from)
                .unwrap_or(JSValue::UNDEFINED);
            write_p.reject(ctx, err);
            return Ok(JSValue::from(write_p));
        }

        // 3. Validate the stream state (may have changed during `size()`).
        match sp.state {
            RsState::Errored | RsState::Erroring => {
                let e = sp.stored_error.get();
                write_p.reject(ctx, e);
                return Ok(JSValue::from(write_p));
            }
            RsState::Closed => {
                let err = ctx
                    .create_error_object(zuqe::ErrorKind::Type, "Writer is closed", false)
                    .map(JSValue::from)
                    .unwrap_or(JSValue::UNDEFINED);
                write_p.reject(ctx, err);
                return Ok(JSValue::from(write_p));
            }
            _ => {}
        }
        // A close is queued or in flight: reject with TypeError (spec
        // `WritableStreamCloseQueuedOrInFlight` / state "closed").
        if sp.close_requested || sp.in_flight_close {
            let err = ctx
                .create_error_object(zuqe::ErrorKind::Type, "Stream is closing", false)
                .map(JSValue::from)
                .unwrap_or(JSValue::UNDEFINED);
            write_p.reject(ctx, err);
            return Ok(JSValue::from(write_p));
        }

        // 4. Per spec `EnqueueValueWithSize`, the chunk size must be a finite,
        //    non-negative number. An invalid size throws a RangeError which
        //    errors the stream, so `write()` and `writer.closed` reject with
        //    that same RangeError.
        if size.is_nan() || size.is_infinite() || size < 0.0 {
            let e = ctx
                .create_error_object(
                    zuqe::ErrorKind::Range,
                    "Chunk size must be a finite non-negative number",
                    false,
                )
                .map(JSValue::from)
                .unwrap_or(JSValue::UNDEFINED);
            sp.start_erroring(ctx, e)?;
            write_p.reject(ctx, e);
            return Ok(JSValue::from(write_p));
        }

        // 5. Enqueue the chunk + its `write()` promise, update backpressure and
        //    advance the queue. Writes issued before `start()` resolves are
        //    queued (and count toward `desiredSize`) but not handed to the sink
        //    until `started` is true (`WritableStreamPayload::advance_queue`).
        // The guard slots record the stream→chunk/promise barriers.
        let owner = sp.owner.unwrap_or(JSValue::UNDEFINED);
        sp.write_queue.push(ctx, owner, chunk);
        sp.write_queue_sizes.push(size);
        sp.queue_total_size += size;
        sp.write_requests.push(ctx, owner, write_p);
        sp.update_backpressure(ctx);
        if sp.started {
            sp.advance_queue(ctx)?;
        }
    }

    // `advance_queue` may have consumed the promise (turned it into the
    // in-flight write). `write_p` (Copy) is the same handle, so return it.
    Ok(JSValue::from(write_p))
}

fn js_writer_close(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut this = cc.this();
    let p = JSWritableStreamDefaultWriter::payload_mut_of(&mut this)
        .ok_or_else(|| ctx.throw_type_error("not a WritableStreamDefaultWriter"))?;

    // Released writer: close() returns a rejected promise (spec).
    let Some(mut stream) = p.stream else {
        let err = ctx
            .create_error_object(zuqe::ErrorKind::Type, "Writer is released", false)
            .map(JSValue::from)
            .unwrap_or(JSValue::UNDEFINED);
        return Promise::from_reject_value(ctx, err).map(JSValue::from);
    };

    let sp = stream
        .payload_mut()
        .ok_or_else(|| ctx.throw_type_error("not a WritableStream"))?;
    sp.close(ctx).map(JSValue::from)
}

fn js_writer_abort(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut this = cc.this();
    let reason = cc.arg(0);

    let p = JSWritableStreamDefaultWriter::payload_mut_of(&mut this)
        .ok_or_else(|| ctx.throw_type_error("not a WritableStreamDefaultWriter"))?;

    let abort_p = p.abort(ctx, reason)?;
    Ok(JSValue::from(abort_p))
}

fn js_writer_release_lock(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut this = cc.this();
    if let Some(p) = JSWritableStreamDefaultWriter::payload_mut_of(&mut this) {
        p.release_lock(ctx);
    }
    Ok(JSValue::UNDEFINED)
}
