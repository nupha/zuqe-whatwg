// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! Unified readable stream controller payload.
//!
//! `ReadableStreamDefaultController` and `ReadableByteStreamController` share a
//! single payload enum `ReadableControllerPayload`. Operations are exposed as
//! methods on the enum and dispatch on the variant internally, so callers use
//! one uniform API without caring which controller kind they hold.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use zuqe::{
    CallContext, Callback, ErrorKind, Exception, GcBind, JSResult, JSValue, ScopedContext,
    WriteBarrier, WriteBarrierVec,
    builtins::{promise::Promise, typed_array::TypedArray},
    gc_lite::GcTrace,
};

use super::{
    JSReadableByteStreamController, JSReadableStream, JSReadableStreamDefaultController,
    QueueEntry, RsState, make_iterator_result,
};

/// WHATWG §2.4.3 pull-into descriptor: records a pending BYOB read so the byte
/// controller can fill the caller-supplied view when data arrives.
#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct PullIntoDescriptor {
    pub(crate) view: WriteBarrier<TypedArray>,
    /// Resolve function from `Promise::create` — calling it goes through
    /// thenable assimilation (checks `value.then`) per spec, unlike
    /// `Promise::resolve()` which settles directly.
    pub(crate) resolve_fn: WriteBarrier<JSValue>,
    /// The promise itself, used for rejection (direct settle is fine there).
    pub(crate) promise: WriteBarrier<Promise>,
    pub(crate) bytes_filled: u32,
    pub(crate) element_size: u32,
    /// Original byte offset of the view into its ArrayBuffer.
    pub(crate) byte_offset: u32,
    /// Byte length of the underlying ArrayBuffer (set once at creation).
    pub(crate) buffer_byte_length: u32,
    /// Cached BYOBRequest object wrapping this descriptor. Created at push
    /// time (reader.rs) to avoid `new_instance` scope issues during pull.
    pub(crate) byob_request: WriteBarrier<Option<JSValue>>,
    /// WHATWG reader type: "byob" for BYOB reader reads, "default" for
    /// auto-allocated descriptors, "none" for detached-from-queue descriptors.
    pub(crate) reader_type: ReaderType,
    /// Minimum number of bytes that must be filled before the descriptor
    /// is committed (WHATWG `minimumFill`). 0 means no minimum (fill eagerly).
    pub(crate) minimum_fill: u32,
}

/// One descriptor pushed into `pending_pull_intos`: `push`/`insert` bind every
/// GC leaf to the controller in one step. There is no `GcBind for
/// WriteBarrier<T>`, so each leaf is unwrapped with `get()` first.
impl GcBind for PullIntoDescriptor {
    fn bind_node(&self, ctx: &ScopedContext, owner: std::ptr::NonNull<zuqe::gc_lite::GcHead>) {
        self.view.get().bind_node(ctx, owner);
        self.resolve_fn.get().bind_node(ctx, owner);
        self.promise.get().bind_node(ctx, owner);
        self.byob_request.get().bind_node(ctx, owner);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) enum ReaderType {
    Byob,
    Default,
    None,
}

/// Fields that differ between the default and byte controller kinds. Common
/// fields (stream, underlying_source, queue, queue_total_size, high_water_mark,
/// close_requested) live on `ReadableControllerPayload` directly.
#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) enum ReadableControllerKind {
    Default {
        controller: WriteBarrier<Option<JSReadableStreamDefaultController>>,
        started: Cell<bool>,
        pulling: Cell<bool>,
        pull_again: Cell<bool>,
        pending_read: RefCell<WriteBarrierVec<Promise>>,
        in_tee: Cell<bool>,
        /// True when the stream was constructed with `type: 'owning'`.
        owning: Cell<bool>,
    },

    /// Byte stream controller. Maintains a queue of pending pull-into
    /// descriptors so BYOB reads can be fulfilled when enqueue() provides data.
    Byte {
        // Cached BYOBRequest object (controller-level cache). Invariant: if
        // present, it must also be stored in the current descriptor's
        // `PullIntoDescriptor.byob_request` (guard slot). Whenever the
        // descriptor slot is taken or cleared, `clear_byob_request()` must be
        // called in the same path.
        byob_request: RefCell<WriteBarrier<Option<JSValue>>>,
        pending_pull_intos: RefCell<WriteBarrierVec<PullIntoDescriptor>>,
        pending_read: RefCell<WriteBarrierVec<Promise>>,
        started: Cell<bool>,
        pulling: Cell<bool>,
        pull_again: Cell<bool>,
        /// Self-handle: the JSValue wrapping the byte controller, so call_pull
        /// can pass it as the first argument to the underlying source's pull().
        self_handle: RefCell<WriteBarrier<Option<JSValue>>>,
        /// WHATWG autoAllocateChunkSize: when set, default reader reads
        /// auto-allocate a buffer of this size and expose it via byobRequest.
        auto_allocate_chunk_size: Cell<u32>,
    },
}

/// Unified controller payload
#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct ReadableControllerPayload {
    pub(crate) stream: Option<JSReadableStream>,
    pub(crate) underlying_source: JSValue,
    pub(crate) queue: Rc<RefCell<WriteBarrierVec<QueueEntry>>>,
    pub(crate) queue_total_size: Rc<Cell<f64>>,
    pub(crate) high_water_mark: f64,
    pub(crate) close_requested: Cell<bool>,
    /// Captured at stream setup (spec `SetUpReadableStreamDefaultController`):
    /// the underlying source's `pull`/`cancel` and the strategy's `size`
    /// callbacks. `undefined` means "absent". Capturing once avoids re-running
    /// the property getters on every pull/cancel/enqueue. Guarded: setup runs
    /// after the controller instance exists, so a minor may have aged it.
    pub(crate) pull_algorithm: WriteBarrier<JSValue>,
    pub(crate) cancel_algorithm: WriteBarrier<JSValue>,
    pub(crate) size_algorithm: WriteBarrier<JSValue>,
    /// Chunks dequeued but not yet handed to a reader. They are out of `queue`
    /// while `pull` runs (and `pull` may force a GC), so they are traced here.
    /// Use `with_in_flight`, not this field directly.
    in_flight: RefCell<WriteBarrierVec<JSValue>>,
    pub(crate) kind: ReadableControllerKind,
}

/// Guard over the in-flight slot: every pushed value is bound to the controller
/// node, so a minor during the hold (or a JS call inside it) keeps the value.
pub(crate) struct InFlight<'a> {
    values: &'a RefCell<WriteBarrierVec<JSValue>>,
    owner: Option<JSValue>,
}

impl InFlight<'_> {
    pub(crate) fn push(&self, ctx: &mut ScopedContext, value: JSValue) {
        // No owner: UNDEFINED makes the barrier a no-op; the store still happens.
        self.values
            .borrow_mut()
            .push(ctx, self.owner.unwrap_or(JSValue::UNDEFINED), value);
    }

    /// The controller value, for callers that also write to another payload
    /// slot during the same hold.
    pub(crate) fn owner(&self) -> Option<JSValue> {
        self.owner
    }
}

impl ReadableControllerPayload {
    /// The controller object's own JSValue.
    ///
    /// Resolved through the stream's `controller` back-pointer (set during
    /// stream setup), with the byte controller's self-handle as a fallback.
    pub(crate) fn owner_value(&self) -> Option<JSValue> {
        if let Some(stream) = self.stream {
            let sv = JSValue::from(stream);
            if let Some(sp) = JSReadableStream::payload_of(&sv)
                && let Some(ctrl) = sp.controller.get()
            {
                return Some(ctrl);
            }
        }
        if let ReadableControllerKind::Byte { self_handle, .. } = &self.kind {
            return self_handle.borrow().get();
        }
        None
    }

    pub(crate) fn new_default(
        underlying_source: JSValue,
        stream: Option<JSReadableStream>,
        high_water_mark: f64,
    ) -> Self {
        Self {
            stream,
            underlying_source,
            queue: Rc::new(RefCell::new(WriteBarrierVec::new())),
            queue_total_size: Rc::new(Cell::new(0.0)),
            high_water_mark,
            close_requested: Cell::new(false),
            pull_algorithm: WriteBarrier::new(JSValue::UNDEFINED),
            cancel_algorithm: WriteBarrier::new(JSValue::UNDEFINED),
            size_algorithm: WriteBarrier::new(JSValue::UNDEFINED),
            in_flight: RefCell::new(WriteBarrierVec::new()),
            kind: ReadableControllerKind::Default {
                controller: WriteBarrier::new(None),
                started: Cell::new(false),
                pulling: Cell::new(false),
                pull_again: Cell::new(false),
                pending_read: RefCell::new(WriteBarrierVec::new()),
                in_tee: Cell::new(false),
                owning: Cell::new(false),
            },
        }
    }

    pub(crate) fn new_byte(
        underlying_source: JSValue,
        stream: Option<JSReadableStream>,
        high_water_mark: f64,
        auto_allocate_chunk_size: u32,
    ) -> Self {
        Self {
            stream,
            underlying_source,
            queue: Rc::new(RefCell::new(WriteBarrierVec::new())),
            queue_total_size: Rc::new(Cell::new(0.0)),
            high_water_mark,
            close_requested: Cell::new(false),
            pull_algorithm: WriteBarrier::new(JSValue::UNDEFINED),
            cancel_algorithm: WriteBarrier::new(JSValue::UNDEFINED),
            size_algorithm: WriteBarrier::new(JSValue::UNDEFINED),
            in_flight: RefCell::new(WriteBarrierVec::new()),
            kind: ReadableControllerKind::Byte {
                byob_request: RefCell::new(WriteBarrier::new(None)),
                pending_pull_intos: RefCell::new(WriteBarrierVec::new()),
                pending_read: RefCell::new(WriteBarrierVec::new()),
                started: Cell::new(false),
                pulling: Cell::new(false),
                pull_again: Cell::new(false),
                self_handle: RefCell::new(WriteBarrier::new(None)),
                auto_allocate_chunk_size: Cell::new(auto_allocate_chunk_size),
            },
        }
    }

    /// The controlled readable stream, if attached.
    pub(crate) fn stream(&self) -> Option<JSReadableStream> {
        self.stream
    }

    pub(crate) fn cancel_algorithm(&self) -> JSValue {
        self.cancel_algorithm.get()
    }

    /// The underlying source object handed to `start()`/`pull()`.
    pub(crate) fn underlying_source(&self) -> JSValue {
        self.underlying_source
    }

    /// Pending read promises (read() calls awaiting a chunk). Byte streams
    /// have no pending read concept, so this is unreachable there.
    pub(crate) fn pending_read(&self) -> &RefCell<WriteBarrierVec<Promise>> {
        match &self.kind {
            ReadableControllerKind::Default { pending_read, .. } => pending_read,
            ReadableControllerKind::Byte { pending_read, .. } => pending_read,
        }
    }

    /// Pending BYOB pull-into descriptors (byte streams only). Returns `None`
    /// for default streams.
    pub(crate) fn pending_pull_intos(
        &self,
    ) -> Option<&RefCell<WriteBarrierVec<PullIntoDescriptor>>> {
        match &self.kind {
            ReadableControllerKind::Byte {
                pending_pull_intos, ..
            } => Some(pending_pull_intos),
            _ => None,
        }
    }

    /// Clear the cached byob_request so the next access re-creates it
    /// (called after respond/respondWithNewView invalidate the descriptor).
    /// Must stay paired with clearing/taking the descriptor's byob_request slot.
    pub(crate) fn clear_byob_request(&self) {
        if let ReadableControllerKind::Byte { byob_request, .. } = &self.kind {
            let _ = byob_request.borrow_mut().take();
        }
    }

    /// WHATWG `ReadableByteStreamControllerRespond` — process a BYOB respond.
    /// Sets bytesFilled, then commits (shifts + fulfills read) when minimumFill
    /// is met. When pendingPullIntos is empty, this is a no-op (per spec the
    /// assertion is debug-only, not a runtime error).
    pub(crate) fn respond(
        &self,
        ctx: &mut ScopedContext,
        bytes_written: JSValue,
    ) -> Result<(), i32> {
        let ReadableControllerKind::Byte {
            pending_pull_intos,
            pending_read,
            ..
        } = &self.kind
        else {
            return Err(ctx.throw_type_error("respond() on non-byte controller"));
        };
        let bytes = bytes_written.to_number(ctx)?.to_f64();
        if bytes < 0.0 {
            return Err(ctx.throw_range_error("`bytesWritten` must be non-negative"));
        }

        // Spec assertion: pendingPullIntos should not be empty. When it IS
        // empty (e.g. respond called after enqueue shifted the descriptor),
        // treat as a no-op rather than throwing.
        if pending_pull_intos.borrow().is_empty() {
            return Ok(());
        }

        // WHATWG ReadableByteStreamControllerRespondInReadableState:
        // Validate and fill the first descriptor, then commit if minimumFill met.
        {
            let mut descs = pending_pull_intos.borrow_mut();
            let first = descs
                .first_mut()
                .ok_or_else(|| ctx.throw_type_error("No pending BYOB read to respond to"))?;

            if first.view.get().is_detached() {
                return Err(ctx.throw_type_error(
                    "Cannot respond to a BYOB request whose buffer has been detached",
                ));
            }
            let bytes_u = bytes as u32;
            if first.bytes_filled + bytes_u > first.element_size {
                return Err(
                    ctx.throw_range_error("respond() would overflow the BYOB request byte length")
                );
            }
            if bytes_u == 0 {
                return Err(
                    ctx.throw_type_error("`bytesWritten` must be non-zero for a readable stream")
                );
            }

            // FillHeadPullIntoDescriptor: accumulate bytesFilled.
            first.bytes_filled += bytes_u;

            // If bytesFilled < minimumFill, don't commit yet.
            if first.bytes_filled < first.minimum_fill {
                // Clear both controller-level and descriptor-level byob_request
                // so the next pull() gets a fresh view of the remaining bytes.
                // Emptying the slot needs no barrier (removal).
                let _ = first.byob_request.take();
                self.clear_byob_request();
                return Ok(());
            }
        }

        // Commit: shift the descriptor, create a view, fulfill the read.
        self.commit_pull_into_descriptor(ctx, pending_pull_intos, pending_read)
    }

    /// WHATWG `ReadableByteStreamControllerCommitPullIntoDescriptor`: shift the
    /// first descriptor, create a view of its committed bytes, and either fulfill
    /// a pending read request or enqueue the data.
    fn commit_pull_into_descriptor(
        &self,
        ctx: &mut ScopedContext,
        pending_pull_intos: &RefCell<WriteBarrierVec<PullIntoDescriptor>>,
        pending_read: &RefCell<WriteBarrierVec<Promise>>,
    ) -> Result<(), i32> {
        let desc = pending_pull_intos.borrow_mut().remove(0);
        self.clear_byob_request();

        // WHATWG `ReadableByteStreamControllerConvertPullIntoDescriptor`: the
        // committed view is a fresh view over the descriptor's *transferred*
        // buffer, covering exactly the filled bytes.
        let committed = super::reader::transfer_view(ctx, desc.view.get(), desc.bytes_filled)?;

        // Try to fulfill a pending non-BYOB read request first.
        if self.resolve_pending_read(ctx, committed, false) {
            return Ok(());
        }

        // No pending read — enqueue the committed data for a future read.
        // The guard slot records the barrier.
        let owner = self.owner_value().unwrap_or(JSValue::UNDEFINED);
        self.queue.borrow_mut().push(
            ctx,
            owner,
            QueueEntry {
                chunk: committed,
                size: 1.0,
            },
        );
        self.queue_total_size.set(self.queue_total_size.get() + 1.0);
        Ok(())
    }

    /// WHATWG `ReadableByteStreamControllerRespondWithNewView` — process a BYOB
    /// respond with a new view (validating offset/length match).
    pub(crate) fn respond_with_new_view(
        &self,
        ctx: &mut ScopedContext,
        new_view: JSValue,
    ) -> Result<(), i32> {
        let ReadableControllerKind::Byte {
            pending_pull_intos,
            pending_read,
            ..
        } = &self.kind
        else {
            return Err(ctx.throw_type_error("respondWithNewView() on non-byte controller"));
        };
        if pending_pull_intos.borrow().is_empty() {
            return Ok(());
        }
        // Validate the new view is not detached.
        let new_ta = TypedArray::try_from(new_view)
            .map_err(|_| ctx.throw_type_error("view is not a TypedArray"))?;
        if new_ta.is_detached() {
            return Err(ctx.throw_type_error("Cannot respond with a detached view"));
        }
        let new_byte_length = new_view
            .get_property_str(ctx, "byteLength")?
            .to_number(ctx)?
            .to_f64() as i32;
        // WHATWG: check state-dependent zero-length rules BEFORE buffer checks.
        let state = match self.stream {
            Some(rs) => match rs.payload() {
                Some(sp) => sp.state,
                None => RsState::Readable,
            },
            None => RsState::Readable,
        };
        match state {
            RsState::Closed => {
                if new_byte_length != 0 {
                    return Err(ctx.throw_type_error(
                        "respondWithNewView() view must be zero-length on a closed stream",
                    ));
                }
            }
            _ => {
                // readable
                if new_byte_length == 0 {
                    return Err(ctx.throw_type_error(
                        "respondWithNewView() view must not be zero-length on a readable stream",
                    ));
                }
            }
        }
        let new_offset = new_view
            .get_property_str(ctx, "byteOffset")?
            .to_number(ctx)?
            .to_f64() as i32;
        let new_buffer_length = {
            let buf = new_view.get_property_str(ctx, "buffer")?;
            buf.get_property_str(ctx, "byteLength")?
                .to_number(ctx)?
                .to_f64() as i32
        };
        let mut descs = pending_pull_intos.borrow_mut();
        let first = descs.first_mut().unwrap();
        // WHATWG step 7: byte offset check.
        let req_offset = (first.byte_offset + first.bytes_filled) as i32;
        if new_offset != req_offset {
            return Err(ctx.throw_range_error(
                "respondWithNewView() view byte offset does not match the BYOB request",
            ));
        }
        // WHATWG step 8: buffer byte length check.
        let req_buffer_length = first.buffer_byte_length as i32;
        if new_buffer_length != req_buffer_length {
            return Err(ctx.throw_range_error(
                "respondWithNewView() view buffer length does not match the BYOB request view buffer length",
            ));
        }
        // WHATWG step 9: bytesFilled + viewByteLength > byteLength
        if first.bytes_filled + new_byte_length as u32 > first.element_size {
            return Err(ctx.throw_range_error(
                "respondWithNewView() view would exceed the BYOB request byte length",
            ));
        }
        // Update the descriptor's view and bytes filled. The guard slot binds
        // the new view: the bare assignment it replaces had no barrier.
        first.view.set(
            ctx,
            self.owner_value().unwrap_or(JSValue::UNDEFINED),
            new_ta,
        );
        first.bytes_filled = new_byte_length as u32;

        // If bytesFilled < minimumFill, don't commit yet.
        if first.bytes_filled < first.minimum_fill {
            self.clear_byob_request();
            return Ok(());
        }

        // Commit: shift the descriptor, create a view, fulfill the read.
        drop(descs);
        self.commit_pull_into_descriptor(ctx, pending_pull_intos, pending_read)
    }

    pub(crate) fn set_in_tee(&self, v: bool) {
        if let ReadableControllerKind::Default { in_tee, .. } = &self.kind {
            in_tee.set(v);
        }
    }

    pub(crate) fn set_owning(&self, v: bool) {
        if let ReadableControllerKind::Default { owning, .. } = &self.kind {
            owning.set(v);
        }
    }

    pub(crate) fn high_water_mark(&self) -> f64 {
        self.high_water_mark
    }

    pub(crate) fn close_requested(&self) -> bool {
        self.close_requested.get()
    }

    pub(crate) fn set_close_requested(&self, v: bool) {
        self.close_requested.set(v);
    }

    /// Whether `start()` has completed (the start promise fulfilled). Pull is
    /// only allowed once started (spec `[[started]]`).
    pub(crate) fn set_started(&self, v: bool) {
        if let ReadableControllerKind::Default { started, .. } = &self.kind {
            started.set(v);
        }
    }

    /// Queue of buffered chunks.
    pub(crate) fn queue(&self) -> &Rc<RefCell<WriteBarrierVec<QueueEntry>>> {
        &self.queue
    }

    /// Run `f` with a traced slot for values that must survive JS re-entry.
    /// Entries pushed by `f` are truncated when it returns, so the hold ends
    /// with the closure, including on error. Each `push` binds the value to
    /// `owner` (the controller): a minor may run inside `f` while the
    /// controller is already old, and the payload is not re-scanned.
    pub(crate) fn with_in_flight<R>(
        &self,
        owner: Option<JSValue>,
        f: impl FnOnce(&InFlight<'_>) -> R,
    ) -> R {
        let base = self.in_flight.borrow().len();
        let guard = InFlight {
            values: &self.in_flight,
            owner,
        };
        let r = f(&guard);
        // `WriteBarrierVec` has no `truncate`: pop back down to the base length.
        let mut v = self.in_flight.borrow_mut();
        while v.len() > base {
            v.pop();
        }
        r
    }

    pub(crate) fn queue_total_size(&self) -> f64 {
        self.queue_total_size.get()
    }

    pub(crate) fn set_queue_total_size(&self, v: f64) {
        self.queue_total_size.set(v);
    }

    /// Resolve the controller's *oldest* pending read (if any) with an iterator
    /// result `{value, done}`. Returns true if a pending read was resolved.
    pub(crate) fn resolve_pending_read(
        &self,
        ctx: &mut ScopedContext,
        value: JSValue,
        done: bool,
    ) -> bool {
        let pending_read = match &self.kind {
            ReadableControllerKind::Default { pending_read, .. } => pending_read,
            ReadableControllerKind::Byte { pending_read, .. } => pending_read,
        };
        let promise = pending_read.borrow_mut().first().copied();
        if let Some(mut p) = promise {
            if let Ok(result) = make_iterator_result(ctx, value, done) {
                pending_read.borrow_mut().remove(0);
                // Settle directly so an injected Object.prototype.then cannot
                // intercept the read result.
                p.resolve(ctx, result);
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Reject every outstanding pending read with `reason` (used on error).
    pub(crate) fn reject_all_pending_reads(&self, ctx: &mut ScopedContext, reason: JSValue) {
        let pending_read = match &self.kind {
            ReadableControllerKind::Default { pending_read, .. } => pending_read,
            ReadableControllerKind::Byte { pending_read, .. } => pending_read,
        };
        let reads = {
            // `WriteBarrierVec` has no `drain`: remove(0) keeps the reject order.
            let mut pr = pending_read.borrow_mut();
            let mut v = Vec::new();
            while !pr.is_empty() {
                v.push(pr.remove(0));
            }
            v
        };
        for mut p in reads {
            p.reject(ctx, reason);
        }
    }

    /// WHATWG ReadableByteStreamControllerFillPullIntoDescriptor: copy bytes
    /// from `chunk` into pending pull-into descriptors. Any leftover bytes
    /// are pushed back to the queue.
    fn fill_pending_pull_intos(
        &self,
        ctx: &mut ScopedContext,
        owner: Option<JSValue>,
        pending: &RefCell<WriteBarrierVec<PullIntoDescriptor>>,
        chunk: &JSValue,
    ) -> Result<(), i32> {
        let chunk_bytes: Vec<u8> =
            match chunk.as_object().and_then(|o| TypedArray::try_from(o).ok()) {
                Some(ta) => ta.with_bytes(|b| b.to_vec()),
                None => return Ok(()),
            };
        let mut src_offset: u32 = 0;
        // Collect fully-filled descriptors to resolve AFTER the loop,
        // so byobRequest returns null before any thenable assimilation
        // triggers the patched Object.prototype.then getter.
        let mut resolved: Vec<(JSValue, JSValue)> = Vec::new();

        // Every value in `resolved` is also held in the traced slot: once a
        // descriptor leaves `pending`, nothing else traces it, and `subarray` /
        // `resolve_fn` may run JS that GCs.
        self.with_in_flight(owner, |held| -> Result<(), i32> {
            loop {
                let desc_bytes_needed = {
                    let mut descs = pending.borrow_mut();
                    // Remove detached descriptors at the front (user detached the buffer).
                    while let Some(d) = descs.first() {
                        if d.view.get().is_detached() {
                            descs.remove(0);
                        } else {
                            break;
                        }
                    }
                    match descs.first() {
                        Some(d) => d.element_size - d.bytes_filled,
                        None => break,
                    }
                };

                let available = chunk_bytes.len() as u32 - src_offset;
                let copy_len = desc_bytes_needed.min(available);

                if copy_len == 0 {
                    break;
                }

                // Copy bytes into the descriptor's view.
                let mut descs = pending.borrow_mut();
                let Some(desc) = descs.first_mut() else { break };
                desc.view.get().with_bytes_mut(|dest| {
                    let dest_start = desc.bytes_filled as usize;
                    dest[dest_start..dest_start + copy_len as usize].copy_from_slice(
                        &chunk_bytes[src_offset as usize..src_offset as usize + copy_len as usize],
                    );
                });
                desc.bytes_filled += copy_len;
                src_offset += copy_len;

                if desc.bytes_filled == desc.element_size {
                    let n = desc.element_size;
                    let resolve_fn = desc.resolve_fn.get();
                    held.push(ctx, resolve_fn);
                    // Commit: hand back a view over the transferred buffer.
                    let filled = super::reader::transfer_view(ctx, desc.view.get(), n)?;
                    held.push(ctx, filled);
                    descs.remove(0);
                    resolved.push((resolve_fn, filled));
                }
            }

            // Resolve fully-filled descriptors now that all pending_pull_intos
            // updates are complete — byobRequest will see null for consumers.
            for (resolve_fn, filled) in resolved {
                let result = make_iterator_result(ctx, filled, false)?;
                resolve_fn.call(ctx, JSValue::UNDEFINED, &[result])?;
            }
            Ok(())
        })?;

        // Push leftover bytes back to queue. The queue is borrowed only here,
        // never across the JS resolves above (a GC during them traces the queue).
        if src_offset < chunk_bytes.len() as u32 {
            let rest =
                TypedArray::create_from_vec_u8(ctx, chunk_bytes[src_offset as usize..].to_vec())?;
            let rest_val = JSValue::from(rest);
            // The guard slot records the barrier.
            self.queue.borrow_mut().insert(
                ctx,
                owner.unwrap_or(JSValue::UNDEFINED),
                0,
                QueueEntry {
                    chunk: rest_val,
                    size: 1.0,
                },
            );
            self.queue_total_size.set(self.queue_total_size.get() + 1.0);
        }

        Ok(())
    }

    /// Reject all pending pull-into descriptors with `reason`.
    fn reject_all_pending_pull_intos(
        &self,
        ctx: &mut ScopedContext,
        pending: &RefCell<WriteBarrierVec<PullIntoDescriptor>>,
        reason: JSValue,
    ) {
        // `WriteBarrierVec` has no `drain`: remove(0) keeps the reject order.
        let descs: Vec<_> = {
            let mut p = pending.borrow_mut();
            let mut v = Vec::new();
            while !p.is_empty() {
                v.push(p.remove(0));
            }
            v
        };
        for desc in descs {
            desc.promise.get().reject(ctx, reason);
        }
    }

    /// ReadableStreamDefaultControllerShouldCallPull: pull when the stream
    /// can still produce data, the queue is empty, and either the desired size
    /// is positive or the stream has a pending read (consumer demand).
    /// aike models "started" via `call_pull` itself, so it is not checked here.
    pub(crate) fn should_call_pull(&self, ctx: &mut ScopedContext) -> Result<bool, i32> {
        if self.close_requested() {
            return Ok(false);
        }
        let readable = match self.stream {
            Some(rs) => match rs.payload() {
                Some(sp) => sp.state == RsState::Readable,
                None => false,
            },
            None => false,
        };
        if !readable {
            return Ok(false);
        }
        // Spec `ReadableStreamDefaultControllerShouldCallPull`: pull() must not
        // run until start() has completed.
        if let ReadableControllerKind::Default { started, .. } = &self.kind
            && !started.get()
        {
            return Ok(false);
        }
        // A pending read request also forces a pull (spec
        // `ReadableStreamDefaultControllerShouldCallPull` step 5), which keeps
        // hwm-0 transform/readable streams flowing.
        if !self.pending_read().borrow().is_empty() {
            return Ok(true);
        }
        if !self.queue().borrow().is_empty() {
            return Ok(false);
        }
        Ok(self.desired_size(ctx)? > 0.0)
    }

    /// Ask the underlying source to pull one more chunk.
    pub(crate) fn call_pull(&self, ctx: &mut ScopedContext) -> Result<(), i32> {
        match &self.kind {
            ReadableControllerKind::Default {
                pulling,
                pull_again,
                controller,
                ..
            } => {
                // Spec: pull() never runs before start() completes. `started`
                // is set by the constructor's start-completion path.
                if pulling.get() {
                    pull_again.set(true);
                    return Ok(());
                }

                pulling.set(true);

                let pull_fn = self.pull_algorithm.get();
                if !pull_fn.is_callable() {
                    pulling.set(false);
                    return Ok(());
                }

                let controller_val = controller
                    .get()
                    .ok_or_else(|| ctx.throw_internal_error("invalid controller"))?;

                self.call_pull_inner(ctx, pulling, pull_again, controller_val.into())
            }
            ReadableControllerKind::Byte {
                pulling,
                started,
                pull_again,
                self_handle,
                pending_pull_intos,
                auto_allocate_chunk_size,
                ..
            } => {
                if !started.get() {
                    started.set(true);
                }
                if pulling.get() {
                    pull_again.set(true);
                    return Ok(());
                }

                pulling.set(true);

                let pull_fn = self.pull_algorithm.get();
                if !pull_fn.is_callable() {
                    pulling.set(false);
                    return Ok(());
                }

                // WHATWG ReadableByteStreamControllerCallPullIfNeeded steps 5-8:
                // If pendingPullIntos is empty and autoAllocateChunkSize > 0,
                // create an auto-allocated pull-into descriptor before calling pull.
                let aacs = auto_allocate_chunk_size.get();
                if pending_pull_intos.borrow().is_empty() && aacs > 0 {
                    let view = TypedArray::create_from_vec_u8(ctx, vec![0u8; aacs as usize])?;
                    let (promise, resolve_funcs) = Promise::create(ctx)?;
                    let desc = PullIntoDescriptor {
                        view: WriteBarrier::new(view),
                        resolve_fn: WriteBarrier::new(resolve_funcs[0]),
                        promise: WriteBarrier::new(promise),
                        bytes_filled: 0,
                        element_size: 1,
                        byte_offset: 0,
                        buffer_byte_length: aacs,
                        byob_request: WriteBarrier::new(None),
                        reader_type: ReaderType::Default,
                        minimum_fill: 1,
                    };
                    // The guard slot records the barrier (the push binds every
                    // GC leaf of the descriptor to the controller).
                    let owner = self.owner_value().unwrap_or(JSValue::UNDEFINED);
                    pending_pull_intos.borrow_mut().push(ctx, owner, desc);
                }

                let controller_val = self_handle.borrow().get().ok_or_else(|| {
                    ctx.throw_internal_error("byte controller self-handle not set")
                })?;

                self.call_pull_inner(ctx, pulling, pull_again, controller_val)
            }
        }
    }

    fn call_pull_inner(
        &self,
        ctx: &mut ScopedContext,
        pulling: &Cell<bool>,
        pull_again: &Cell<bool>,
        controller_val: JSValue,
    ) -> Result<(), i32> {
        let pull_fn = self.pull_algorithm.get();

        let pull_res = pull_fn.call(ctx, self.underlying_source, &[controller_val]);
        if pull_res.is_err() {
            let err_val = ctx.take_exception().to_value(ctx);
            pulling.set(false);
            self.reject_all_pending_reads(ctx, err_val);
            self.reject_all_pending_pull_intos(
                ctx,
                match &self.kind {
                    ReadableControllerKind::Byte {
                        pending_pull_intos, ..
                    } => pending_pull_intos,
                    _ => return Ok(()),
                },
                err_val,
            );
            self.queue.borrow_mut().clear();
            self.queue_total_size.set(0.0);
            if let Some(mut stream_val) = self.stream {
                stream_val.payload_mut().unwrap().settle_state(
                    ctx,
                    RsState::Errored,
                    Some(err_val),
                );
            }
            let in_tee = match &self.kind {
                ReadableControllerKind::Default { in_tee, .. } => in_tee.get(),
                _ => false,
            };
            return if in_tee {
                Err(ctx.throw_internal_error("pull() threw"))
            } else {
                Ok(())
            };
        }

        let pull_val = pull_res?;
        pulling.set(false);

        if pull_again.get() {
            pull_again.set(false);
            let is_thenable = pull_val.is_object()
                && pull_val
                    .get_property_str(ctx, "then")
                    .map(|t| t.is_callable())
                    .unwrap_or(false);
            if is_thenable {
                let (mut ready, _rr) = Promise::create(ctx)?;
                let controller_clone = controller_val;
                let data = [controller_clone].into();
                let follow_up = ctx
                    .create_native_function_with_data(
                        Callback::Func(controller_refill_pull),
                        "refillPull",
                        0,
                        0,
                        data,
                    )?
                    .into();
                ready.resolve(ctx, JSValue::UNDEFINED);
                ready.perform_then(ctx, follow_up, follow_up)?;
            } else if self.should_call_pull(ctx)? {
                self.call_pull(ctx)?;
            }
        }

        Ok(())
    }

    /// Enqueue a chunk. Per the current spec, a non-readable stream or a
    /// close-requested controller makes this a silent no-op
    /// (`CanCloseOrEnqueue` returns false), not a throw.
    /// For `owning` type streams, the options may contain a `transfer` list.
    pub(crate) fn enqueue(
        &self,
        ctx: &mut ScopedContext,
        owner: Option<JSValue>,
        chunk: JSValue,
        options: JSValue,
    ) -> JSResult {
        // Handle the `transfer` option for owning-type streams.
        let chunk = if !options.is_undefined_or_null() {
            self.handle_transfer(ctx, chunk, options)?
        } else {
            chunk
        };

        match &self.kind {
            ReadableControllerKind::Default { .. } => {
                if self.close_requested.get() || !self.can_close_or_enqueue() {
                    return Ok(JSValue::UNDEFINED);
                }

                let resolved = self.resolve_pending_read(ctx, chunk, false);
                if resolved {
                    // A pending read consumed this chunk and the queue is still
                    // below the high water mark — pull again to refill.
                    if self.should_call_pull(ctx)? {
                        self.call_pull(ctx)?;
                    }
                    return Ok(JSValue::UNDEFINED);
                }

                // No pending read: compute the chunk's size via the strategy's
                // size algorithm. A throwing size() errors the stream and
                // re-throws; an invalid size (NaN/±Infinity/negative) is a
                // RangeError that also errors the stream.
                let size = if self.size_algorithm.get().is_callable() {
                    match self
                        .size_algorithm
                        .get()
                        .call(ctx, JSValue::UNDEFINED, &[chunk])
                    {
                        Ok(v) => v.to_number(ctx)?.to_f64(),
                        Err(_) => {
                            let e = ctx.take_exception().to_value(ctx);
                            self.error(ctx, e)?;
                            // Re-throw the same value so `enqueue()` surfaces it.
                            ctx.throw(Exception::Error(e));
                            return Err(-1);
                        }
                    }
                } else {
                    1.0
                };
                if size.is_nan() || size.is_infinite() || size < 0.0 {
                    let e = ctx
                        .create_error_object(
                            ErrorKind::Range,
                            "strategy.size must return a finite non-negative number",
                            false,
                        )
                        .ok_or(-1)?;
                    let e = e.into();
                    self.error(ctx, e)?;
                    ctx.throw(Exception::Error(e));
                    return Err(-1);
                }

                // The guard slot records the barrier.
                let owner = owner.unwrap_or(JSValue::UNDEFINED);
                self.queue
                    .borrow_mut()
                    .push(ctx, owner, QueueEntry { chunk, size });
                self.queue_total_size
                    .set(self.queue_total_size.get() + size);
                Ok(JSValue::UNDEFINED)
            }
            ReadableControllerKind::Byte {
                pending_pull_intos, ..
            } => {
                // WHATWG ReadableByteStreamControllerEnqueue steps 2-3:
                // If closeRequested is true or state is not readable, throw TypeError.
                if self.close_requested.get() || !self.can_close_or_enqueue() {
                    return Err(ctx.throw_type_error(
                        "Cannot enqueue into a closed or errored ReadableStream",
                    ));
                }

                // Validate the chunk per WHATWG steps 3-7.
                let chunk = validate_and_transfer_byte_chunk(ctx, chunk)?;

                // WHATWG step 8: if there are pending pull-into descriptors,
                // transfer buffer and handle based on reader type.
                if !pending_pull_intos.borrow().is_empty() {
                    // Step 8b: buffer must not be detached.
                    {
                        let descs = pending_pull_intos.borrow();
                        if let Some(first) = descs.first()
                            && first.view.get().is_detached()
                        {
                            return Err(ctx.throw_type_error(
                                    "Cannot enqueue when the pending BYOB request's buffer has been detached",
                                ));
                        }
                    }

                    // Step 8c: invalidate BYOBRequest.
                    self.clear_byob_request();

                    // Step 8d's TransferArrayBuffer is already covered: the
                    // descriptor's buffer was transferred when the BYOB read
                    // created it (see `transfer_view`), so it is a fresh
                    // full-size buffer here and must not be replaced by a
                    // view-sized one.

                    // Step 8e: if reader type is "none", enqueue detached
                    // descriptor's bytes to the queue and return.
                    if pending_pull_intos
                        .borrow()
                        .get(0)
                        .is_some_and(|d| d.reader_type == ReaderType::None)
                    {
                        let desc = pending_pull_intos.borrow_mut().remove(0);
                        let ta = TypedArray::create_from_vec_u8(
                            ctx,
                            desc.view.get().with_bytes(|b| b.to_vec()),
                        )?;
                        let ta_val = JSValue::from(ta);
                        // The guard slot records the barrier.
                        let owner = owner.unwrap_or(JSValue::UNDEFINED);
                        self.queue.borrow_mut().push(
                            ctx,
                            owner,
                            QueueEntry {
                                chunk: ta_val,
                                size: 1.0,
                            },
                        );
                        self.queue_total_size.set(self.queue_total_size.get() + 1.0);
                        return Ok(JSValue::UNDEFINED);
                    }

                    // For "default" readerType (auto-allocated): shift
                    // descriptor, fulfill pending read with the chunk directly.
                    if pending_pull_intos
                        .borrow()
                        .get(0)
                        .is_some_and(|d| d.reader_type == ReaderType::Default)
                    {
                        let desc = pending_pull_intos.borrow_mut().remove(0);
                        let _ = desc;
                        self.resolve_pending_read(ctx, chunk, false);
                        return Ok(JSValue::UNDEFINED);
                    }

                    // For "byob" readerType: copy chunk bytes into all
                    // pending descriptor views (fill + commit each when full).
                    self.fill_pending_pull_intos(ctx, owner, pending_pull_intos, &chunk)?;
                    return Ok(JSValue::UNDEFINED);
                }

                // WHATWG step 9: no pending pull-intos — enqueue to queue.
                //
                // A byte stream has no "pending read requests" in the spec (it uses
                // pull-into descriptors), but aike models a default reader's wait
                // as one. Such a reader is waiting for exactly this chunk, so hand
                // it over directly instead of leaving the promise unresolved —
                // otherwise any byte stream read before data is available hangs
                // (reachable via `Response.clone()`, which tees the byte stream).
                if !self.resolve_pending_read(ctx, chunk, false) {
                    // The guard slot records the barrier.
                    let owner = owner.unwrap_or(JSValue::UNDEFINED);
                    self.queue
                        .borrow_mut()
                        .push(ctx, owner, QueueEntry { chunk, size: 1.0 });
                    self.queue_total_size.set(self.queue_total_size.get() + 1.0);
                }
                Ok(JSValue::UNDEFINED)
            }
        }
    }

    /// Handle the `transfer` option for owning-type streams.
    /// Neuters each buffer in the transfer list via `ArrayBuffer.prototype.transfer()`,
    /// then clones the chunk so it references the transferred data.
    fn handle_transfer(
        &self,
        ctx: &mut ScopedContext,
        chunk: JSValue,
        options: JSValue,
    ) -> Result<JSValue, i32> {
        // Get the transfer list from options. If the getter throws, propagate.
        let transfer_list = match options.as_object() {
            Some(o) => o.get_property_str(ctx, "transfer")?,
            None => JSValue::UNDEFINED,
        };

        if transfer_list.is_undefined_or_null() {
            return Ok(chunk);
        }

        // Transfer is only allowed for owning-type streams.
        let is_owning = if let ReadableControllerKind::Default { owning, .. } = &self.kind {
            owning.get()
        } else {
            false
        };
        if !is_owning {
            return Err(ctx.throw_type_error(
                "Transfer is only allowed for ReadableStream with type 'owning'",
            ));
        }

        // Convert to array and iterate.
        let len_val = transfer_list.get_property_str(ctx, "length")?;
        let len = len_val.to_number(ctx)?.to_f64() as i32;
        if len <= 0 {
            return Ok(chunk);
        }

        // Build a map: original buffer → transferred buffer.
        let mut replacements: Vec<(JSValue, JSValue)> = Vec::new();
        for i in 0..len {
            let buf = match transfer_list.get_property_u32(ctx, i as u32) {
                Ok(v) => v,
                Err(_) => {
                    ctx.take_exception();
                    continue;
                }
            };
            if buf.is_undefined_or_null() {
                continue;
            }
            // Call ArrayBuffer.prototype.transfer() to neuter the original
            // and get a new buffer with the same data.
            let transfer_fn = match buf.get_property_str(ctx, "transfer") {
                Ok(v) => v,
                Err(_) => {
                    ctx.take_exception();
                    continue;
                }
            };
            if !transfer_fn.is_callable() {
                continue;
            }
            let new_buf = match transfer_fn.call(ctx, buf, &[]) {
                Ok(v) => v,
                Err(_) => {
                    ctx.take_exception();
                    continue;
                }
            };
            replacements.push((buf, new_buf));
        }

        if replacements.is_empty() {
            return Ok(chunk);
        }

        // For TypedArrays: create a new TypedArray backed by the transferred buffer.
        // For plain ArrayBuffers: return the transferred buffer directly.
        let is_ta = chunk
            .get_property_str(ctx, "byteLength")
            .map(|v| !v.is_undefined())
            .unwrap_or(false)
            && chunk
                .get_property_str(ctx, "buffer")
                .map(|v| v.is_object())
                .unwrap_or(false);

        if is_ta {
            // TypedArray: create a new instance with the transferred buffer.
            let constructor = chunk.get_property_str(ctx, "constructor")?;
            if constructor.is_callable() {
                // Find the replacement buffer for this TypedArray's buffer.
                let orig_buf = chunk.get_property_str(ctx, "buffer")?;
                if let Some((_, new_buf)) = replacements.iter().find(|(old, _)| *old == orig_buf) {
                    let byte_offset = chunk
                        .get_property_str(ctx, "byteOffset")
                        .ok()
                        .and_then(|v| v.to_number(ctx).ok().map(|n| n.to_f64() as u32))
                        .unwrap_or(0);
                    let byte_length = chunk
                        .get_property_str(ctx, "byteLength")
                        .ok()
                        .and_then(|v| v.to_number(ctx).ok().map(|n| n.to_f64() as u32))
                        .unwrap_or(0);

                    // TypedArray(buffer, byteOffset, byteLength)
                    return constructor.call(
                        ctx,
                        JSValue::UNDEFINED,
                        &[
                            *new_buf,
                            JSValue::from(byte_offset as f64),
                            JSValue::from(byte_length as f64),
                        ],
                    );
                }
            }

            // Fallback: return chunk as-is (transfer didn't match).
            return Ok(chunk);
        }

        // Plain ArrayBuffer or other: return the transferred buffer.
        if let Some((_, new_buf)) = replacements.first() {
            return Ok(*new_buf);
        }

        Ok(chunk)
    }

    /// Spec `ReadableStreamDefaultControllerCanCloseOrEnqueue`: false once the
    /// stream has left the readable state or close has been requested.
    pub(crate) fn can_close_or_enqueue(&self) -> bool {
        if self.close_requested.get() {
            return false;
        }

        match self.stream {
            Some(rs) => match rs.payload() {
                Some(sp) => sp.state == RsState::Readable,
                None => false,
            },
            None => false,
        }
    }

    /// Close the controlled stream. Per WHATWG
    /// `ReadableStreamDefaultControllerClose` / `ReadableByteStreamControllerClose`
    /// step 1, throws a TypeError when `CanCloseOrEnqueue` is false (stream not
    /// readable or close already requested).
    pub(crate) fn close(&self, ctx: &mut ScopedContext) -> Result<(), i32> {
        if !self.can_close_or_enqueue() {
            return Err(ctx.throw_type_error(
                "Cannot close a ReadableStreamController whose stream is not readable",
            ));
        }

        match &self.kind {
            ReadableControllerKind::Default { .. } => {
                // WHATWG ReadableStreamDefaultControllerClose
                self.close_requested.set(true);
                while self.resolve_pending_read(ctx, JSValue::UNDEFINED, true) {}
                if self.queue.borrow().is_empty()
                    && let Some(mut rs) = self.stream
                {
                    rs.payload_mut()
                        .unwrap()
                        .settle_state(ctx, RsState::Closed, None);
                }
            }
            ReadableControllerKind::Byte {
                pending_pull_intos, ..
            } => {
                // WHATWG ReadableByteStreamControllerClose:
                // 1. If closeRequested or not readable, return (checked above).
                // 2. If queueTotalSize > 0: set closeRequested, return.
                if self.queue_total_size.get() > 0.0 {
                    self.close_requested.set(true);
                    return Ok(());
                }
                // 3. If pendingPullIntos not empty: check alignment.
                if !pending_pull_intos.borrow().is_empty() {
                    let first = &pending_pull_intos.borrow()[0];
                    if first.bytes_filled % first.element_size != 0 {
                        let e =
                            ctx.throw_type_error("bytesFilled is not a multiple of elementSize");
                        let e_val = ctx.take_exception().to_value(ctx);
                        self.error(ctx, e_val)?;
                        return Err(e);
                    }
                }
                // 4. ClearAlgorithms + ReadableStreamClose
                if let Some(mut rs) = self.stream {
                    rs.payload_mut()
                        .unwrap()
                        .settle_state(ctx, RsState::Closed, None);
                }
            }
        }

        Ok(())
    }

    /// Error the controlled stream with `e`. Per WHATWG
    /// `ReadableStreamDefaultControllerError`, the guard is
    /// `stream.[[state]]` only (not `CanCloseOrEnqueue`):
    ///   1. Let stream be controller.[[stream]].
    ///   2. If stream.[[state]] is not "readable", return.
    ///
    /// This means `controller.error()` still works after
    /// `controller.terminate()` as long as the readable side hasn't
    /// transitioned away from "readable" (i.e. the queue was non-empty
    /// when terminate closed it).
    pub(crate) fn error(&self, ctx: &mut ScopedContext, e: JSValue) -> Result<(), i32> {
        let is_readable = match self.stream {
            Some(rs) => match rs.payload() {
                Some(sp) => sp.state == RsState::Readable,
                None => false,
            },
            None => false,
        };
        if !is_readable {
            return Ok(());
        }

        match &self.kind {
            ReadableControllerKind::Default { .. } => {
                self.reject_all_pending_reads(ctx, e);
                self.queue.borrow_mut().clear();
                self.queue_total_size.set(0.0);
                if let Some(mut rs) = self.stream {
                    rs.payload_mut()
                        .unwrap()
                        .settle_state(ctx, RsState::Errored, Some(e));
                }
            }
            ReadableControllerKind::Byte {
                pending_pull_intos, ..
            } => {
                // Spec `ReadableByteStreamControllerError` clears pending
                // pull-intos and then delegates to
                // `ReadableStreamDefaultControllerError`, which rejects pending
                // read requests. A default reader's `read()` on a byte stream
                // registers in `pending_read` (not in `pending_pull_intos`), so
                // both lists must be rejected or that read hangs forever (e.g.
                // a fetch body errored by a network failure or an abort).
                self.reject_all_pending_pull_intos(ctx, pending_pull_intos, e);
                self.reject_all_pending_reads(ctx, e);
                if let Some(mut rs) = self.stream {
                    rs.payload_mut()
                        .unwrap()
                        .settle_state(ctx, RsState::Errored, Some(e));
                }
            }
        }

        Ok(())
    }

    /// Spec: errored -> null (signalled as `f64::NAN`), closed -> 0, else
    /// highWaterMark - queueTotalSize. The result can be negative when the
    /// queue is over-full; that is the spec-mandated backpressure signal.
    /// A NaN highWaterMark is impossible (rejected at extraction), so NaN is a
    /// safe sentinel for the errored state.
    pub(crate) fn desired_size(&self, _: &mut ScopedContext) -> Result<f64, i32> {
        if let Some(s) = self.stream
            && let Some(sp) = s.payload()
        {
            match sp.state {
                // Readable streams never enter the Erroring state.
                RsState::Errored | RsState::Erroring => return Ok(f64::NAN),
                RsState::Closed => return Ok(0.0),
                RsState::Readable => {}
            }
        }

        Ok(self.high_water_mark - self.queue_total_size.get())
    }

    /// WHATWG `ReadableByteStreamControllerGetBYOBRequest`: returns a cached
    /// `ReadableStreamBYOBRequest` wrapping the first pending pull-into
    /// descriptor's view. When `pendingPullIntos` is empty and
    /// `autoAllocateChunkSize > 0`, auto-allocates a new descriptor.
    pub(crate) fn byob_request(&self, ctx: &mut ScopedContext) -> Result<JSValue, i32> {
        match &self.kind {
            ReadableControllerKind::Default { .. } => Ok(JSValue::UNDEFINED),
            ReadableControllerKind::Byte {
                byob_request,
                pending_pull_intos,
                self_handle,
                auto_allocate_chunk_size,
                ..
            } => {
                // Controller-level cache (set after respond/respondWithNewView clears it).
                if let Some(cached) = byob_request.borrow().get() {
                    return Ok(cached);
                }

                // WHATWG ReadableByteStreamControllerGetBYOBRequest:
                // If pendingPullIntos is empty but autoAllocateChunkSize > 0,
                // auto-allocate a new descriptor so byobRequest is non-null.
                if pending_pull_intos.borrow().is_empty() {
                    let aacs = auto_allocate_chunk_size.get();
                    if aacs == 0 {
                        return Ok(JSValue::NULL);
                    }
                    // Create auto-allocated descriptor.
                    let view = TypedArray::create_from_vec_u8(ctx, vec![0u8; aacs as usize])?;
                    let (promise, resolve_funcs) = Promise::create(ctx)?;
                    let desc = PullIntoDescriptor {
                        view: WriteBarrier::new(view),
                        resolve_fn: WriteBarrier::new(resolve_funcs[0]),
                        promise: WriteBarrier::new(promise),
                        bytes_filled: 0,
                        element_size: aacs,
                        byte_offset: 0,
                        buffer_byte_length: aacs,
                        byob_request: WriteBarrier::new(None),
                        reader_type: ReaderType::Default,
                        minimum_fill: 1,
                    };
                    // The guard slot records the barrier (the push binds every
                    // GC leaf of the descriptor to the controller).
                    let owner = self.owner_value().unwrap_or(JSValue::UNDEFINED);
                    pending_pull_intos.borrow_mut().push(ctx, owner, desc);
                }

                // A descriptor that already carries a request returns it. The
                // borrow is immutable and ends with the statement, so no
                // mutable borrow is held across the JS calls below.
                if let Some(br) = pending_pull_intos
                    .borrow()
                    .first()
                    .and_then(|d| d.byob_request.get())
                {
                    return Ok(br);
                }
                // Copy the front descriptor's fields out under an immutable
                // borrow: the container keeps it rooted while `subarray` /
                // `new_instance` run JS (Rule 4).
                let (view, bytes_filled, element_size) = match pending_pull_intos.borrow().first() {
                    Some(d) => (d.view.get(), d.bytes_filled, d.element_size),
                    None => return Ok(JSValue::NULL),
                };
                // WHATWG ReadableByteStreamControllerGetBYOBRequest:
                // Create a BYOBRequest wrapping the remaining unfilled
                // portion of the descriptor's view and cache it.
                let controller_val = self_handle
                    .borrow()
                    .get()
                    .ok_or_else(|| ctx.throw_internal_error("controller self-handle not set"))?;
                // View = original view[bytesFilled .. elementSize]
                let view_val = if bytes_filled > 0 {
                    view.invoke_str(
                        ctx,
                        "subarray",
                        &[
                            JSValue::from(bytes_filled as i32),
                            JSValue::from(element_size as i32),
                        ],
                    )?
                } else {
                    JSValue::from(view)
                };
                let br = super::readable_byob_request::JSReadableStreamBYOBRequest::new_instance(
                    ctx,
                    JSValue::UNDEFINED,
                    super::readable_byob_request::ByobRequestPayload::new(controller_val, view_val),
                )?;
                // The descriptor leaves the container only between `remove`
                // and `push`: `set`/`push` only bind, never a GC point.
                let owner = self.owner_value().unwrap_or(JSValue::UNDEFINED);
                let mut d = pending_pull_intos.borrow_mut().remove(0);
                d.byob_request.set(ctx, owner, Some(JSValue::from(br)));
                pending_pull_intos.borrow_mut().push(ctx, owner, d);
                byob_request
                    .borrow_mut()
                    .set(ctx, owner, Some(JSValue::from(br)));
                Ok(JSValue::from(br))
            }
        }
    }
}

/// Post-construction setters live on the native wrapper, not on the payload.
/// The owner is always `JSValue::from(*self)`, so a caller cannot pass the
/// wrong stream/object and silently bind the edge to somebody else.
impl JSReadableStreamDefaultController {
    /// Wire this controller's self-handle (call_controller_pull needs it).
    pub(crate) fn set_controller(
        &mut self,
        ctx: &ScopedContext,
        c: Option<JSReadableStreamDefaultController>,
    ) {
        let owner = JSValue::from(*self);
        if let Some(p) = self.payload_mut()
            && let ReadableControllerKind::Default { controller, .. } = &mut p.kind
        {
            controller.set(ctx, owner, c);
        }
    }

    /// Capture the underlying source's callbacks once, at stream setup.
    pub(crate) fn set_algorithms(
        &mut self,
        ctx: &ScopedContext,
        pull: JSValue,
        cancel: JSValue,
        size: JSValue,
    ) {
        let owner = JSValue::from(*self);
        if let Some(p) = self.payload_mut() {
            p.pull_algorithm.set(ctx, owner, pull);
            p.cancel_algorithm.set(ctx, owner, cancel);
            p.size_algorithm.set(ctx, owner, size);
        }
    }
}

impl JSReadableByteStreamController {
    /// Capture the underlying source's callbacks once, at stream setup.
    pub(crate) fn set_algorithms(
        &mut self,
        ctx: &ScopedContext,
        pull: JSValue,
        cancel: JSValue,
        size: JSValue,
    ) {
        let owner = JSValue::from(*self);
        if let Some(p) = self.payload_mut() {
            p.pull_algorithm.set(ctx, owner, pull);
            p.cancel_algorithm.set(ctx, owner, cancel);
            p.size_algorithm.set(ctx, owner, size);
        }
    }

    /// Store this controller as its own guarded self-handle. The value and the
    /// owner are both this instance, so there is nothing for a caller to pass.
    pub(crate) fn set_byte_self_handle(&self, ctx: &ScopedContext) {
        let owner = JSValue::from(*self);
        if let Some(p) = self.payload()
            && let ReadableControllerKind::Byte { self_handle, .. } = &p.kind
        {
            self_handle.borrow_mut().set(ctx, owner, Some(owner));
        }
    }
}

/// WHATWG `ReadableByteStreamControllerEnqueue` steps 4-7: validate the chunk
/// and transfer its buffer so the stream takes ownership.
fn validate_and_transfer_byte_chunk(
    ctx: &mut ScopedContext,
    chunk: JSValue,
) -> Result<JSValue, i32> {
    // Try TypedArray first (most common case for byte streams).
    if let Ok(ta) = TypedArray::try_from(chunk) {
        // Step 4: If chunk.[[ViewedArrayBuffer]] is detached, throw TypeError.
        if ta.is_detached() {
            return Err(
                ctx.throw_type_error("Cannot enqueue into a byte stream with a detached buffer")
            );
        }
        // Step 5: If chunk.[[ByteLength]] is 0, throw TypeError.
        if ta.byte_length() == 0 {
            return Err(
                ctx.throw_type_error("Cannot enqueue into a byte stream with a zero-length view")
            );
        }
        // Step 6: If chunk.[[ByteOffset]] is not 0, throw RangeError.
        let byte_offset = chunk
            .get_property_str(ctx, "byteOffset")
            .ok()
            .and_then(|v| v.to_number(ctx).ok())
            .map(|n| n.to_f64() as u32)
            .unwrap_or(0);
        if byte_offset != 0 {
            return Err(ctx.throw_range_error(
                "Cannot enqueue into a byte stream with a non-zero byte offset",
            ));
        }
        // Step 7: If chunk.[[BufferByteLength]] != chunk.[[ByteLength]], throw RangeError.
        let byte_length = ta.byte_length() as u32;
        let buffer_byte_length = ta.array_buffer().payload().byte_length() as u32;
        if buffer_byte_length != byte_length {
            return Err(
                ctx.throw_range_error("Cannot enqueue into a byte stream with a misaligned view")
            );
        }
        // Transfer the buffer: copy bytes, detach original, return fresh array.
        let bytes = ta.with_bytes(|b| b.to_vec());
        ta.array_buffer().detatch(ctx);
        let new_ta = TypedArray::create_from_vec_u8(ctx, bytes)?;
        return Ok(JSValue::from(new_ta));
    }

    // Plain ArrayBuffer (no view).
    if let Some(ab) = chunk.as_object_ArrayBuffer() {
        if ab.is_detached() {
            return Err(
                ctx.throw_type_error("Cannot enqueue into a byte stream with a detached buffer")
            );
        }
        if ab.payload().byte_length() == 0 {
            return Err(
                ctx.throw_type_error("Cannot enqueue into a byte stream with a zero-length buffer")
            );
        }
        return transfer_chunk_buffer(ctx, chunk);
    }

    Err(ctx.throw_type_error("chunk must be an ArrayBuffer or a TypedArray"))
}

/// Transfer a plain ArrayBuffer: call `ArrayBuffer.prototype.transfer()`
/// to detach the original, then return the new buffer.
fn transfer_chunk_buffer(ctx: &mut ScopedContext, chunk: JSValue) -> Result<JSValue, i32> {
    let transfer_fn = match chunk.get_property_str(ctx, "transfer") {
        Ok(v) if v.is_callable() => v,
        _ => {
            ctx.take_exception();
            return Ok(chunk);
        }
    };
    match transfer_fn.call(ctx, chunk, &[]) {
        Ok(v) => Ok(v),
        Err(_) => {
            ctx.take_exception();
            Ok(chunk)
        }
    }
}

// Follow-up pull scheduled by `call_pull` when a concurrent pull was requested
// while the source was already pulling (the `pullAgain` flag). Runs as a promise
// reaction so a queue drained by a read is refilled before later await steps.
fn controller_refill_pull(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let controller_val = cc.data(0);
    let cp = JSReadableStreamDefaultController::payload_of(&controller_val)
        .ok_or_else(|| ctx.throw_internal_error("invalid controller"))?;
    // Spec `CallPullIfNeeded`: the pullAgain follow-up runs through
    // ShouldCallPull, so a stream that closed/errored meanwhile does not pull
    // again.
    if cp.should_call_pull(ctx)? {
        cp.call_pull(ctx)?;
    }
    Ok(JSValue::UNDEFINED)
}

/// Fetch the shared `ReadableControllerPayload` from a controller `this` value,
/// accepting either the default or byte controller native type. The returned
/// borrow is tied to `this`'s lifetime.
pub(super) fn get_readable_controller<'a>(
    ctx: &mut ScopedContext,
    this: &'a JSValue,
) -> Result<&'a ReadableControllerPayload, i32> {
    if let Some(p) = JSReadableStreamDefaultController::payload_of(this) {
        Ok(p)
    } else if let Some(p) = JSReadableByteStreamController::payload_of(this) {
        Ok(p)
    } else {
        Err(ctx.throw_type_error("not a ReadableStream controller"))
    }
}

#[cfg(all(test, debug_assertions))]
mod gc_barrier_tests {
    use zuqe::{
        Context, EvalFlags, EvalName, EvalType, JSValue, NativeObject, Runtime, ScopedContext,
    };

    use super::{
        JSReadableStreamDefaultController, ReadableControllerKind, ReadableControllerPayload,
    };

    fn eval(cx: &mut ScopedContext, src: &[u8], name: &str) -> Result<JSValue, i32> {
        cx.eval(
            src,
            &EvalName::Name(name.to_string()),
            EvalType::Global,
            EvalFlags::empty(),
        )
    }

    fn setup() -> Result<(Runtime, Context<'static>), i32> {
        let mut rt = Runtime::create()?;
        let mut ctx: Context<'static> = rt.create_context(ScopedContext::ECMA_CONTEXT_SETUP)?;
        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            let global = cx.global_obj();
            crate::init_whatwg(&mut cx, global)?;
            eval(
                &mut cx,
                b"new ReadableStream({ start(c) { globalThis.__rc = c; } });",
                "controller-barrier-setup",
            )?;
            Ok(())
        })?;
        Ok((rt, ctx))
    }

    fn old_controller(
        rt: &mut Runtime,
        ctx: &mut Context<'static>,
    ) -> Result<JSReadableStreamDefaultController, i32> {
        // Promote the controller (and its payload) to old generation.
        let _ = rt.gc_minor_now();
        ctx.with_root_scope(|mut cx| -> Result<JSReadableStreamDefaultController, i32> {
            let v = eval(&mut cx, b"globalThis.__rc", "controller-barrier-old")?;
            JSReadableStreamDefaultController::from_value(v).ok_or(-1)
        })
    }

    /// P0-2: `set_controller` derives the owner from the wrapper. Once the
    /// owner is old, writing a young controller must record the edge or the
    /// next minor frees the young controller while it is still referenced.
    #[test]
    fn set_controller_write_barrier_survives_a_minor() -> Result<(), i32> {
        let (mut rt, mut ctx) = setup()?;
        let mut old = old_controller(&mut rt, &mut ctx)?;

        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            // Fresh (young) controller; it is not rooted anywhere else after
            // this scope closes, so only the old controller's barrier can
            // keep it alive across the next minor.
            let v = eval(
                &mut cx,
                b"(function () { let c; new ReadableStream({ start(x) { c = x; } }); return c; })()",
                "controller-barrier-young",
            )?;
            let young = JSReadableStreamDefaultController::from_value(v).ok_or(-1)?;
            old.set_controller(&cx, Some(young));
            Ok(())
        })?;

        let _ = rt.gc_minor_now();

        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            let v = eval(&mut cx, b"globalThis.__rc", "controller-barrier-check")?;
            let old = JSReadableStreamDefaultController::from_value(v).ok_or(-1)?;
            let p = old.payload().ok_or(-1)?;
            let ReadableControllerKind::Default { controller, .. } = &p.kind else {
                return Err(-1);
            };
            let young = controller.get().ok_or(-1)?;
            assert!(
                young.payload().is_some(),
                "young controller was collected: the write barrier missed the owner edge"
            );
            Ok(())
        })
    }

    /// P0-2: the same point test for `set_algorithms`; all three callback
    /// slots are written after the owner was promoted.
    #[test]
    fn set_algorithms_write_barrier_survives_a_minor() -> Result<(), i32> {
        let (mut rt, mut ctx) = setup()?;
        let mut old = old_controller(&mut rt, &mut ctx)?;

        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            let f = eval(&mut cx, b"(function () {})", "controller-barrier-algo")?;
            old.set_algorithms(&cx, f, f, f);
            Ok(())
        })?;

        let _ = rt.gc_minor_now();

        ctx.with_root_scope(|mut cx| -> Result<(), i32> {
            let v = eval(&mut cx, b"globalThis.__rc", "controller-barrier-algo-check")?;
            let old = JSReadableStreamDefaultController::from_value(v).ok_or(-1)?;
            let p: &ReadableControllerPayload = old.payload().ok_or(-1)?;
            for (name, cb) in [
                ("pull", p.pull_algorithm.get()),
                ("cancel", p.cancel_algorithm.get()),
                ("size", p.size_algorithm.get()),
            ] {
                assert!(
                    cb.is_callable(),
                    "{name} callback was collected: the write barrier missed the owner edge"
                );
            }
            Ok(())
        })
    }
}
