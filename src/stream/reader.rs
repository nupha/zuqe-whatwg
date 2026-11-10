// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    time::{Duration, Instant},
};

use zuqe::{
    CallContext, ClassCtorDef, ErrorKind, Exception, FieldDef, GcBind, JSResult, JSValue,
    JobGcTrace, JobState, ScopedContext, WriteBarrier, WriteBarrierVec,
    builtins::{
        promise::{Promise, PromiseResultSlot, PromiseState},
        typed_array::TypedArray,
    },
    def_native_object,
    gc_lite::{GcTrace, GcTraceCtx},
};

use crate::stream::{readable::JSReadableStream, readable_controller::PullIntoDescriptor};

use super::{QueueEntry, RsState, iterator_result_promise};

/// Unified reader for ReadableStreamDefaultReaderPayload, ReadableStreamBYOBReaderPayload
#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct ReaderPayload {
    pub(super) stream: Option<JSReadableStream>,
    pub(crate) closed_promise: WriteBarrier<Option<Promise>>,
    /// True when acquired via `getReader({mode: 'byob'})`. A BYOB read writes
    /// the chunk into the caller-supplied view instead of allocating one.
    pub(super) byob: bool,
    /// The reader object's own handle, set right after construction. Used to
    /// record the write barrier when `release_lock` swaps in a fresh rejected
    /// `closed` promise on this possibly-already-old reader.
    #[gc(skip)]
    pub(crate) owner: Option<JSValue>,
}

impl ReaderPayload {

    /// Release the lock on the underlying stream: detach the reader so the
    /// stream can be acquired again, and reject `closed` plus any pending read
    /// requests with a TypeError (spec `ReadableStreamReaderGenericRelease` /
    /// `ReadableStreamDefaultReaderRelease`). No-op if the reader is already
    /// released.
    pub(crate) fn release_lock(&mut self, ctx: &mut ScopedContext) {
        // Spec `ReadableStreamReaderGenericRelease`: a readable stream rejects
        // the existing closedPromise in place; a closed/errored stream replaces
        // it with a fresh rejected promise (so `closed` changes identity).
        let stream_readable = self
            .stream
            .map(|rs| {
                rs.payload()
                    .is_some_and(|sp| sp.state == super::RsState::Readable)
            })
            .unwrap_or(false);
        if stream_readable {
            if let Some(mut cp) = self.closed_promise.get() {
                // Reject the same promise in place, keeping `closed`'s identity.
                if cp.state() == PromiseState::Pending
                    && let Some(e) =
                        ctx.create_error_object(ErrorKind::Type, "Reader released", false)
                {
                    cp.reject(ctx, e.into());
                }
            }
        } else if let Some(e) = ctx.create_error_object(ErrorKind::Type, "Reader released", false)
            && let Ok((mut np, _rr)) = Promise::create(ctx)
        {
            np.reject(ctx, e.into());
            // The guard slot records the barrier (no self-handle yet: UNDEFINED = no-op bind).
            let owner = self.owner.unwrap_or(JSValue::UNDEFINED);
            self.closed_promise.set(ctx, owner, Some(np));
        }

        if let Some(mut rs) = self.stream.take()
            && let Some(sp) = rs.payload_mut()
        {
            sp.reader.take();
            // spec ReleaseSteps for default controller is a no-op;
            // no pull trigger here.
            // Note: spec does NOT reject pending read() promises on
            // release — they remain pending and are eventually resolved
            // when the stream closes or errors.
        }
    }

    /// Cancel the underlying stream with `reason`. A released reader's
    /// `cancel()` rejects with a TypeError (spec
    /// `ReadableStreamDefaultReader.cancel(reason)` step 1).
    pub(crate) fn cancel(&self, ctx: &mut ScopedContext, reason: JSValue) -> Result<Promise, i32> {
        match self.stream {
            Some(mut rs) => rs.payload_mut().unwrap().cancel(ctx, reason),
            None => {
                if let Some(e) = ctx.create_error_object(ErrorKind::Type, "reader released", false)
                {
                    return Promise::from_reject_value(ctx, e.into());
                }
                Err(ctx.throw_internal_error("failed to create TypeError"))
            }
        }
    }

    /// Perform a `read()` on the underlying stream and return a Promise that
    /// resolves to `{ value, done }`. Internal callers (drain/tee/pipe/async
    /// iteration) call this directly instead of going through the JS `read`
    /// property; the JS API entry point `js_reader_read` delegates here.
    pub(crate) fn read(
        &self,
        ctx: &mut ScopedContext,
        byob_view: Option<TypedArray>,
        min: u32,
    ) -> Result<Promise, i32> {
        let Some(mut stream) = self.stream else {
            // Spec: reading from a released reader returns a promise rejected
            // with a TypeError (not a thrown exception).
            if let Some(e) = ctx.create_error_object(ErrorKind::Type, "reader released", false) {
                return Promise::from_reject_value(ctx, e.into());
            } else {
                return Err(ctx.throw_internal_error("failed to create TypeError"));
            }
        };

        // Mark disturbed before any early return: even a read on a closed or
        // errored stream counts as consuming it.
        if let Some(sp) = stream.payload_mut() {
            sp.disturbed = true;
        }

        // Copy to decouple borrow: stream_p borrows sv, leaving stream_val free
        // for mutable access later.
        let stream_p = stream
            .payload()
            .ok_or_else(|| ctx.throw_internal_error("invalid stream"))?;

        match stream_p.state {
            // Readable streams never enter the Erroring state.
            RsState::Errored | RsState::Erroring => {
                return Promise::from_reject_value(ctx, stream_p.stored_error.get());
            }
            RsState::Closed => {
                // BYOB read from a closed stream still transfers the buffer
                // per WHATWG ReadableByteStreamControllerBYOBRead.
                if let Some(view) = byob_view {
                    let transferred = transfer_view_buffer(ctx, view)?;
                    return iterator_result_promise(ctx, transferred, true);
                }
                return iterator_result_promise(ctx, JSValue::UNDEFINED, true);
            }
            RsState::Readable => {}
        }

        // WHATWG `ReadableByteStreamControllerPullInto` step 11: a BYOB read
        // transfers the caller's buffer up front, so the result below always
        // hands back a view over a fresh ArrayBuffer of the same byte length
        // (and the caller's buffer is detached). That is what lets a caller
        // read a body in chunks into one allocation: `value.buffer` stays the
        // full-size buffer while `value.byteOffset` tracks the write position.
        let byob_view = match byob_view {
            Some(view) => {
                let full = view.byte_length() as u32;
                Some(
                    TypedArray::try_from(transfer_view(ctx, view, full)?).map_err(|_| {
                        ctx.throw_type_error("failed to transfer the BYOB view buffer")
                    })?,
                )
            }
            None => None,
        };

        if let Some(controller_val) = stream_p.controller.get() {
            let cp = super::readable_controller::get_readable_controller(ctx, &controller_val)?;
            let owner = Some(controller_val);

            if !cp.queue().borrow().is_empty() {
                // The whole dequeue → fill → pull → result sequence runs inside
                // one traced hold: the dequeued chunk leaves the queue, and the
                // BYOB view is only a Rust local, yet `call_pull`/`subarray`
                // run JS that can force a GC.
                return cp.with_in_flight(owner, |held| -> Result<Promise, i32> {
                    let chunk;
                    {
                        let mut q = cp.queue().borrow_mut();
                        let entry = q.remove(0);
                        held.push(ctx, entry.chunk);
                        let total = cp.queue_total_size();
                        // Spec `DequeueValue`: clamp to 0 if floating-point drift makes
                        // the running total slightly negative.
                        let new_total = total - entry.size;
                        cp.set_queue_total_size(if new_total < 0.0 { 0.0 } else { new_total });

                        // BYOB: copy as much of the chunk as fits into the caller's view
                        // and push the remainder back so the next read continues where
                        // this one stopped. Done before the close transition so a
                        // partially consumed chunk keeps the stream readable.
                        chunk = if let Some(view) = byob_view {
                            let filled = byob_fill_view(ctx, view, entry.chunk, &mut q, held)?;
                            if !q.is_empty() {
                                cp.set_queue_total_size(cp.queue_total_size() + 1.0);
                            }
                            filled
                        } else {
                            entry.chunk
                        };
                        held.push(ctx, chunk);

                        // Per spec: after draining last item, if close_requested,
                        // transition stream to closed state.
                        if q.is_empty()
                            && cp.close_requested()
                            && let Some(sp) = stream.payload_mut()
                        {
                            sp.state = RsState::Closed;
                        }
                    }

                    // Spec PullSteps step 2.3: after dequeue, if stream is not
                    // closed, call CallPullIfNeeded to refill the queue.
                    if cp.should_call_pull(ctx)? {
                        cp.call_pull(ctx)?;
                    }
                    iterator_result_promise(ctx, chunk, false)
                });
            }

            if cp.close_requested() {
                // WHATWG: BYOB read from a closing controller still transfers
                // the view buffer even when the queue is empty.
                if let Some(view) = byob_view {
                    let transferred = transfer_view_buffer(ctx, view)?;
                    return iterator_result_promise(ctx, transferred, true);
                }
                return iterator_result_promise(ctx, JSValue::UNDEFINED, true);
            }

            // No data in queue — register a pending read on this controller so a
            // later enqueue()/close()/error() can resolve it. Stored per-controller
            // (not globally) so concurrent/sequential streams don't steal chunks.
            //
            // For byte controllers with a BYOB view, create a pull-into
            // descriptor instead so the controller fills the view when data
            // arrives.
            if let Some(view) = byob_view
                && let Some(pending) = cp.pending_pull_intos()
            {
                let element_size = view.byte_length() as u32;
                // Read byteOffset and buffer.byteLength via JS property access.
                let view_jv = JSValue::from(view);
                let byte_offset = view_jv
                    .get_property_str(ctx, "byteOffset")?
                    .to_number(ctx)?
                    .to_f64() as u32;
                let buffer_byte_length = {
                    let buf_jv = view_jv.get_property_str(ctx, "buffer")?;
                    buf_jv
                        .get_property_str(ctx, "byteLength")?
                        .to_number(ctx)?
                        .to_f64() as u32
                };
                let (promise, resolve_funcs) = Promise::create(ctx)?;
                // Create the BYOBRequest eagerly to avoid new_instance scope issues
                // during the pull callback (call_pull_inner).
                let br = super::readable_byob_request::JSReadableStreamBYOBRequest::new_instance(
                    ctx,
                    JSValue::UNDEFINED,
                    super::readable_byob_request::ByobRequestPayload::new(
                        controller_val,
                        JSValue::from(view),
                    ),
                )
                .ok()
                .map(JSValue::from);

                // The controller may already be old; the push below binds
                // every GC leaf of the descriptor to it (the non-BYOB
                // pending-read path stores its promise through the guard slot).
                pending.borrow_mut().push(
                    ctx,
                    cp.owner_value().unwrap_or(JSValue::UNDEFINED),
                    PullIntoDescriptor {
                        view: WriteBarrier::new(view),
                        resolve_fn: WriteBarrier::new(resolve_funcs[0]),
                        promise: WriteBarrier::new(promise),
                        bytes_filled: 0,
                        element_size,
                        byte_offset,
                        buffer_byte_length,
                        byob_request: WriteBarrier::new(br),
                        reader_type: super::readable_controller::ReaderType::Byob,
                        minimum_fill: min
                            * if view.length() > 0 {
                                (view.byte_length() / view.length()) as u32
                            } else {
                                1
                            },
                    },
                );
                cp.call_pull(ctx)?;
                return Ok(promise);
            }

            let (promise, _rr) = Promise::create(ctx)?;
            let owner = cp.owner_value().unwrap_or(JSValue::UNDEFINED);
            cp.pending_read().borrow_mut().push(ctx, owner, promise);
            cp.call_pull(ctx)?;

            return Ok(promise);
        }

        // No controller (e.g. detached) — nothing to read.
        iterator_result_promise(ctx, JSValue::UNDEFINED, true)
    }

    /// Synchronously drain the stream's body into a byte buffer. Valid only
    /// for already-settled (queue-backed) reads; a pending read cannot be
    /// waited on synchronously and rejects with a TypeError.
    pub(crate) fn drain_sync(&self, ctx: &mut ScopedContext) -> Result<Vec<u8>, i32> {
        let mut buf = Vec::new();

        loop {
            let pr = self.read(ctx, None, 1)?;
            match pr.state() {
                PromiseState::Fulfilled => {
                    let result = pr.result();
                    let done = result
                        .get_property_str(ctx, "done")
                        .and_then(|d| d.to_bool())
                        .unwrap_or(false);
                    if done {
                        break;
                    }
                    let value = result
                        .get_property_str(ctx, "value")
                        .map_err(|_| ctx.throw_internal_error("missing read value"))?;
                    let ta = TypedArray::try_from(value)
                        .map_err(|_| ctx.throw_type_error("body chunk is not a Uint8Array"))?;
                    ta.with_bytes(|b| buf.extend_from_slice(b));
                }

                // A stream that is not synchronously settled cannot be drained here.
                PromiseState::Pending | PromiseState::Rejected => {
                    return Err(ctx.throw_type_error("body stream is not synchronously readable"));
                }
            }
        }

        Ok(buf)
    }
}



/// WHATWG `TransferArrayBuffer` + `Construct`: detach `view`'s ArrayBuffer and
/// return a view of the same type over the fresh buffer, covering `bytes` bytes
/// from `view`'s byte offset.
///
/// This is the transfer at the heart of BYOB reads
/// (`ReadableByteStreamControllerPullInto` step 11, then
/// `ReadableByteStreamControllerConvertPullIntoDescriptor`): the caller's
/// buffer is detached and every result hands back a new ArrayBuffer of the same
/// byte length. `bytes` must be a multiple of the view's element size.
pub(crate) fn transfer_view(
    ctx: &mut ScopedContext,
    view: TypedArray,
    bytes: u32,
) -> Result<JSValue, i32> {
    let view_jv = JSValue::from(view);
    let byte_offset = view_jv
        .get_property_str(ctx, "byteOffset")?
        .to_number(ctx)?
        .to_f64() as i32;
    // elementSize = byteLength / length; 1 for Uint8Array and DataView.
    let byte_length = view.byte_length() as u32;
    let elements = view.length() as u32;
    let element_size = if elements > 0 {
        (byte_length / elements).max(1)
    } else {
        1
    };
    let count = bytes / element_size;
    // `ArrayBuffer.prototype.transfer()` detaches the source and yields a fresh
    // ArrayBuffer carrying the same bytes (a move, so this stays O(1)).
    let new_buffer = view_jv
        .get_property_str(ctx, "buffer")?
        .invoke_str(ctx, "transfer", &[])?;
    view_jv.get_property_str(ctx, "constructor")?.call_ctor(
        ctx,
        &[
            new_buffer,
            JSValue::from(byte_offset),
            JSValue::from(count as i32),
        ],
    )
}

/// Empty view over a transferred buffer, for a BYOB read from a closed stream
/// (`ReadableByteStreamControllerPullInto` step 12): the caller's buffer is
/// still transferred, only the returned view is zero length.
pub(crate) fn transfer_view_buffer(
    ctx: &mut ScopedContext,
    view: TypedArray,
) -> Result<JSValue, i32> {
    transfer_view(ctx, view, 0)
}

/// Copy `chunk` into the BYOB destination `view`, then transfer the buffer and
/// hand back the resulting view (`ReadableByteStreamControllerConvertPullIntoDescriptor`).
/// Bytes that do not fit are pushed to the front of `queue` so the following
/// read resumes from there. The returned view spans exactly the bytes written,
/// over a freshly transferred ArrayBuffer of the view's byte length.
///
/// `view` is pushed into `held` for the whole function: `transfer_view` runs JS,
/// and the view is otherwise only a Rust local here (see the Rule 4 notes in
/// docs/gc.md).
fn byob_fill_view(
    ctx: &mut ScopedContext,
    mut view: TypedArray,
    chunk: JSValue,
    queue: &mut WriteBarrierVec<QueueEntry>,
    held: &super::readable_controller::InFlight<'_>,
) -> Result<JSValue, i32> {
    let src: Vec<u8> = match chunk.as_object().and_then(|o| TypedArray::try_from(o).ok()) {
        Some(ta) => ta.with_bytes(|b| b.to_vec()),
        // Non-byte chunk in a byte stream: hand it through untouched.
        None => return Ok(chunk),
    };

    held.push(ctx, JSValue::from(view));
    let n = view.with_bytes_mut(|dest| {
        let n = src.len().min(dest.len());
        dest[..n].copy_from_slice(&src[..n]);
        n
    });

    if n < src.len() {
        let rest = TypedArray::create_from_vec_u8(ctx, src[n..].to_vec())?;
        let rest_val = JSValue::from(rest);
        // The guard slot records the barrier.
        queue.insert(
            ctx,
            held.owner().unwrap_or(JSValue::UNDEFINED),
            0,
            QueueEntry {
                chunk: rest_val,
                size: 1.0,
            },
        );
    }

    transfer_view(ctx, view, n as u32)
}

/// Get the `&ReaderPayload` attached to a `ReadableStreamDefaultReader` value.
pub(crate) fn get_read_payload<'a>(
    ctx: &mut ScopedContext,
    this: &'a JSValue,
) -> Result<&'a ReaderPayload, i32> {
    JSReadableStreamDefaultReader::payload_of(this)
        .ok_or_else(|| ctx.throw_type_error("not a ReadableStreamDefaultReader"))
}

/// Get the `&mut ReaderPayload` attached to a `ReadableStreamDefaultReader` value.
pub(crate) fn get_read_payload_mut<'a>(
    ctx: &mut ScopedContext,
    this: &'a mut JSValue,
) -> Result<&'a mut ReaderPayload, i32> {
    JSReadableStreamDefaultReader::payload_mut_of(this)
        .ok_or_else(|| ctx.throw_type_error("not a ReadableStreamDefaultReader"))
}

const READER_PROTO: &[FieldDef] = &[
    FieldDef::FUNC_ENUM("read", 0, js_reader_read, 0),
    FieldDef::FUNC_ENUM("cancel", 1, js_reader_cancel, 0),
    FieldDef::FUNC_ENUM("releaseLock", 0, js_reader_release_lock, 0),
    FieldDef::GETSET_ENUM("closed", Some(js_reader_closed), None, 0),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "ReadableStreamDefaultReader",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

fn js_reader_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    // Spec: `new ReadableStreamDefaultReader(stream)` is a public constructor
    // that locks the stream (throwing TypeError if it is already locked).
    let stream_val = cc.arg(0);
    let mut stream = JSReadableStream::try_from(stream_val)
        .map_err(|_| ctx.throw_type_error("stream must be a ReadableStream"))?;
    let reader = stream.acquire_reader(ctx, false)?;
    Ok(reader.into())
}

def_native_object!(
    "ReadableStreamDefaultReader",
    JSReadableStreamDefaultReader,
    ReaderPayload,
    READER_PROTO,
    Some(ClassCtorDef::new(js_reader_constructor, 0, false).expose_to_global())
);

/// `def_native_object!` generates no `GcBind`, but the payload's
/// `WriteBarrier<Option<…>>` slot needs one: the edge is owner → this object
/// node, identical to `Object`'s, so delegate.
impl GcBind for JSReadableStreamDefaultReader {
    fn bind_node(&self, ctx: &ScopedContext, owner: std::ptr::NonNull<zuqe::gc_lite::GcHead>) {
        GcBind::bind_node(self.as_object(), ctx, owner)
    }
}

fn js_reader_read(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = get_read_payload(ctx, &this)?;

    if !p.byob {
        return p.read(ctx, None, 1).map(JSValue::from);
    }

    // BYOB read: validate view type, then parse + validate options.min.
    let view_jv = cc.arg(0);
    let ta = TypedArray::try_from(view_jv);
    let is_dataview = ta.is_err() && view_jv.as_object_DataView().is_some();

    if ta.is_err() && !is_dataview {
        return Err(ctx.throw_type_error("view must be a TypedArray or DataView"));
    }

    // Extract byte_length and element_size for min validation.
    let (view_byte_length, element_size): (usize, usize) = if let Ok(ref ta) = ta {
        let bl = ta.byte_length();
        if bl == 0 {
            let _ = ctx.throw_type_error("view must have non-zero length");
            let err_val = ctx.take_exception().to_value(ctx);
            return Promise::from_reject_value(ctx, err_val).map(JSValue::from);
        }
        // elementSize = TypedArrayElementSize = byte_length / length
        let es = if ta.length() > 0 { bl / ta.length() } else { 1 };
        (bl, es)
    } else {
        // DataView: elementSize is 1.
        let bl = view_jv
            .get_property_str(ctx, "byteLength")?
            .to_number(ctx)?
            .to_f64() as usize;
        if bl == 0 {
            let _ = ctx.throw_type_error("view must have non-zero length");
            let err_val = ctx.take_exception().to_value(ctx);
            return Promise::from_reject_value(ctx, err_val).map(JSValue::from);
        }
        (bl, 1)
    };

    // WHATWG: parse options.min, default 1.
    let min: u32 = {
        let opts = cc.arg(1);
        if opts.is_undefined() {
            1
        } else {
            let min_val = opts.get_property_str(ctx, "min")?;
            if min_val.is_undefined() {
                1
            } else {
                let min_f = min_val.to_number(ctx)?.to_f64();
                if min_f <= 0.0 {
                    let _ = ctx.throw_type_error("'min' must be a positive non-zero value");
                    let err_val = ctx.take_exception().to_value(ctx);
                    return Promise::from_reject_value(ctx, err_val).map(JSValue::from);
                }
                let min_i = min_f as u64;
                if (min_i as f64) != min_f || min_i == 0 {
                    let _ = ctx.throw_type_error("'min' must be a non-negative integer");
                    let err_val = ctx.take_exception().to_value(ctx);
                    return Promise::from_reject_value(ctx, err_val).map(JSValue::from);
                }
                if min_i * element_size as u64 > view_byte_length as u64 {
                    let _ = ctx.throw_range_error("'min' option is larger than view's byte length");
                    let err_val = ctx.take_exception().to_value(ctx);
                    return Promise::from_reject_value(ctx, err_val).map(JSValue::from);
                }
                min_i as u32
            }
        }
    };

    // For DataView, wrap as Uint8Array over the same buffer region so the
    // existing BYOB descriptor path works. The result will still be a TypedArray;
    // DataView result-wrapping is handled in commit_pull_into_descriptor.
    let byob_view = if let Ok(ta) = ta {
        ta
    } else {
        let buf_jv = view_jv.get_property_str(ctx, "buffer")?;
        let offset = view_jv
            .get_property_str(ctx, "byteOffset")?
            .to_number(ctx)?
            .to_f64() as usize;
        // Create a Uint8Array(buffer, offset, length) via constructor call.
        let uint8_ctor = ctx
            .global_obj()
            .get_property_str(ctx, "Uint8Array")?
            .ensure_callable(ctx)?;
        let new_view = uint8_ctor.call_ctor(
            ctx,
            &[
                buf_jv,
                JSValue::from(offset as i32),
                JSValue::from(view_byte_length as i32),
            ],
        )?;
        TypedArray::try_from(new_view)
            .map_err(|_| ctx.throw_type_error("failed to create Uint8Array view"))?
    };

    p.read(ctx, Some(byob_view), min).map(JSValue::from)
}

fn js_reader_cancel(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let reason = cc.arg(0);
    let p = get_read_payload(ctx, &this)?;
    p.cancel(ctx, reason).map(JSValue::from)
}

fn js_reader_release_lock(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut this = cc.this();
    let p = get_read_payload_mut(ctx, &mut this)?;
    p.release_lock(ctx);
    Ok(JSValue::UNDEFINED)
}

fn js_reader_closed(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = get_read_payload(ctx, &this)?;
    if let Some(cp) = p.closed_promise.get() {
        return Ok(JSValue::from(cp));
    }
    Ok(JSValue::UNDEFINED)
}

/// GC roots for the reader-drain job. The job outlives many event-loop turns,
/// so every JS value it can touch later must be traced from here, including the
/// cells it mutates (`pending` read promise, captured error value).
struct ReaderDrainRoots {
    reader: JSReadableStreamDefaultReader,
    pending: Rc<RefCell<Option<Promise>>>,
    raw_err: Rc<RefCell<Option<JSValue>>>,
}

impl JobGcTrace for ReaderDrainRoots {
    fn job_trace_values(&self, gcx: &mut GcTraceCtx) {
        self.reader.trace(gcx);
        if let Some(p) = *self.pending.borrow() {
            JSValue::from(p).trace(gcx);
        }
        if let Some(ref v) = *self.raw_err.borrow() {
            v.trace(gcx);
        }
    }
}

impl JSReadableStreamDefaultReader {
    /// Pump this reader to completion, committing the concatenated bytes (or
    /// the stream's error) into `slot`.
    ///
    /// Runs as a polling job because `read()` returns a promise that may settle
    /// later (e.g. from an async `pull()`); we inspect its state each tick
    /// rather than attaching JS callbacks, which native fn-pointer callbacks
    /// cannot capture state for.
    pub(crate) fn drain(
        &self,
        ctx: &mut ScopedContext,
        slot: PromiseResultSlot<Result<Vec<u8>, String>>,
        raw_err: Rc<RefCell<Option<JSValue>>>,
        timeout: Duration,
    ) -> Result<(), i32> {
        let reader = *self;

        // Holds the in-flight read() promise between polls.
        let pending = Rc::new(RefCell::new(None::<Promise>));
        let roots = ReaderDrainRoots {
            reader,
            pending: pending.clone(),
            raw_err: raw_err.clone(),
        };

        // Accumulated body bytes across polling turns. The job closure is `Fn`
        // (not `FnMut`), so interior mutability via RefCell is required to grow
        // `buf` on each turn.
        let buf = Rc::new(RefCell::new(Vec::<u8>::new()));
        let start = Instant::now();

        // Set once the drain has committed the slot. The result-slot polling
        // job (created by `create_with_result_slot`) holds only a `Weak`, so
        // this job must keep its strong reference to `slot` alive until that
        // job has consumed the committed value — otherwise `weak.upgrade()`
        // fails and panics on the next tick even though the data was committed.
        let committed = Rc::new(Cell::new(false));
        let committed_ref = committed.clone();

        ctx.queue_job(
            move |cx| {
                if committed_ref.get() {
                    return if slot.is_empty() {
                        Ok(JobState::Done)
                    } else {
                        Ok(JobState::Block)
                    };
                }
                // Start a new read() unless one is already in flight.
                if pending.borrow().is_none() {
                    let p = reader
                        .payload()
                        .ok_or_else(|| cx.throw_type_error("reader released"))?;

                    match p.read(cx, None, 1) {
                        Ok(pv) => {
                            *pending.borrow_mut() = Some(pv);
                        }
                        Err(_) => {
                            // read() threw synchronously — carry the thrown value
                            // over so identity is preserved.
                            if let Exception::Error(v) = cx.take_exception() {
                                *raw_err.borrow_mut() = Some(v);
                            }
                            committed_ref.set(true);
                            let _ = slot.commit(Err("stream read failed".into()));
                            return Ok(JobState::Block);
                        }
                    }
                }

                let p = pending.borrow().unwrap();
                match p.state() {
                    PromiseState::Pending => {
                        if start.elapsed() > timeout {
                            committed_ref.set(true);
                            let _ = slot.commit(Err("body read timeout".into()));
                            return Ok(JobState::Block);
                        }
                        Ok(JobState::Block)
                    }
                    PromiseState::Rejected => {
                        // Stream errored — hand over the original reason value (not
                        // a stringified copy) so identity is preserved, as
                        // `promise_rejects_exactly` and user `catch` blocks expect.
                        *raw_err.borrow_mut() = Some(p.result());
                        committed_ref.set(true);
                        let _ = slot.commit(Err("stream errored".into()));
                        Ok(JobState::Block)
                    }
                    PromiseState::Fulfilled => {
                        *pending.borrow_mut() = None;
                        let result = p.result();
                        let done = result
                            .get_property_str(cx, "done")
                            .and_then(|d| d.to_bool())
                            .unwrap_or(false);
                        if done {
                            let full = std::mem::take(&mut *buf.borrow_mut());
                            committed_ref.set(true);
                            let _ = slot.commit(Ok(full));
                            return Ok(JobState::Block);
                        }
                        let value = match result.get_property_str(cx, "value") {
                            Ok(v) => v,
                            // Missing `value` on a non-done chunk — malformed.
                            _ => {
                                *raw_err.borrow_mut() = cx
                                    .create_error_object(
                                        ErrorKind::Type,
                                        "body chunk is not a Uint8Array",
                                        false,
                                    )
                                    .map(Into::into);
                                committed_ref.set(true);
                                let _ = slot.commit(Err("body chunk is not a Uint8Array".into()));
                                return Ok(JobState::Block);
                            }
                        };

                        // Per WHATWG fetch, a ReadableStream body must yield
                        // Uint8Array chunks (see "extract a byte stream"); any
                        // other chunk type must reject the consume promise with
                        // a TypeError.
                        let Ok(ta) = TypedArray::try_from(value) else {
                            *raw_err.borrow_mut() = cx
                                .create_error_object(
                                    ErrorKind::Type,
                                    "body chunk is not a Uint8Array",
                                    false,
                                )
                                .map(Into::into);
                            committed_ref.set(true);
                            let _ = slot.commit(Err("body chunk is not a Uint8Array".into()));
                            return Ok(JobState::Block);
                        };
                        ta.with_bytes(|b| buf.borrow_mut().extend_from_slice(b));

                        Ok(JobState::Block)
                    }
                }
            },
            roots,
        );

        Ok(())
    }
}
