// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    time::{Duration, Instant},
};

use crossbeam::channel::TryRecvError;
use zuqe::{
    CallContext, Callback, ClassCtorDef, ErrorKind, Exception, FieldDef, GcBind, JSResult, JSValue,
    JobGcTrace, JobState, NativeObject, Object, ScopedContext, WriteBarrier,
    builtins::{
        iterator::{AsyncIterableIterator, AsyncIteratorFetcher, IterFetchStatus},
        promise::Promise,
        typed_array::TypedArray,
    },
    def_native_object,
    gc_lite::{GcTrace, GcTraceCtx},
};

use crate::{
    abort::{signal_is_aborted, signal_reason},
    dom::make_dom_exception,
    fetch::body::BodySource,
    state::WhatwgState,
    stream::{
        extract_high_water_mark,
        reader::{JSReadableStreamDefaultReader, ReaderPayload},
    },
};

use super::{
    JSReadableByteStreamController, JSReadableStreamDefaultController, ReadableControllerPayload,
    RsState, iterator_result_promise, make_iterator_result, notify_peer_closed,
};

/// NOTE: `gc_trace` must NOT remove the CHANNEL_STREAMS entry for this stream.
/// Tracing runs for LIVE streams too, so removing the id would orphan the poller.
/// The poller reaps entries on Disconnected/error/idle-timeout.
#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct ReadableStreamPayload {
    #[gc(skip)]
    pub(crate) state: RsState,
    pub(crate) stored_error: WriteBarrier<JSValue>,
    pub(crate) reader: WriteBarrier<Option<JSReadableStreamDefaultReader>>,
    pub(crate) controller: WriteBarrier<Option<JSValue>>,
    /// Set once read() is called. Unlike the reader lock this is never
    /// cleared by releaseLock(), so a used stream stays unusable as a body.
    pub(crate) disturbed: bool,
    /// Abort signal tied to this body's fetch. When aborted mid-body the stream
    /// errors with the signal's reason. Stored on the stream payload (not just
    /// the channel registry) so GC keeps it alive while the stream is live.
    pub(crate) signal: WriteBarrier<Option<JSValue>>,
    /// True when the stream was constructed with `type: 'bytes'`. Used by
    /// `getReader({mode:'byob'})` and `ReadableStreamBYOBReader` to validate
    /// that only byte streams support BYOB reading.
    pub(crate) is_byte_stream: bool,
}

impl ReadableStreamPayload {
    pub(crate) fn new() -> Self {
        Self {
            state: RsState::Readable,
            stored_error: WriteBarrier::new(JSValue::UNDEFINED),
            reader: WriteBarrier::new(None),
            controller: WriteBarrier::new(None),
            disturbed: false,
            signal: WriteBarrier::new(None),
            is_byte_stream: false,
        }
    }

    /// Extract the shared `ReadableControllerPayload` from the stream's
    /// controller, which may be either a default or byte controller.
    pub(crate) fn controller_payload(&self) -> Option<&ReadableControllerPayload> {
        let cv = self.controller.get()?;
        // `payload_of` ties the returned ref to `&cv` (a local JSValue copy).
        // The payload lives in the GC heap for as long as the controller object
        // is alive (and `self` keeps it reachable), so extending the lifetime
        // to `&self` is sound.
        unsafe {
            if let Some(p) = JSReadableStreamDefaultController::payload_of(&cv) {
                return Some(std::mem::transmute::<
                    &ReadableControllerPayload,
                    &ReadableControllerPayload,
                >(p));
            }
            JSReadableByteStreamController::payload_of(&cv).map(|p| {
                std::mem::transmute::<&ReadableControllerPayload, &ReadableControllerPayload>(p)
            })
        }
    }

    /// The stream object's own handle, resolved through the controller's
    /// `stream` back-pointer (set during stream setup). Used to record write
    /// barriers for values stored into this possibly-already-old payload
    /// (`stored_error` on error/cancel, the peer reader, …).
    pub(crate) fn owner_value(&self) -> Option<JSValue> {
        self.controller_payload()
            .and_then(|cp| cp.stream)
            .map(JSValue::from)
    }

    /// Set this stream's state (and `stored_error` when errored), then settle
    /// the peer reader's `closed_promise` accordingly.
    ///
    /// A stream can only leave the Readable state once. Re-settling (e.g. cancel
    /// after an error) must not re-settle the peer's closed_promise, which would
    /// violate the Promise contract.
    pub(crate) fn settle_state(
        &mut self,
        ctx: &mut ScopedContext,
        state: RsState,
        reason: Option<JSValue>,
    ) {
        if self.state != RsState::Readable {
            return;
        }
        self.state = state;
        if let Some(r) = reason {
            // The guard slot records the barrier (no handle yet: UNDEFINED = no-op bind).
            let owner = self.owner_value().unwrap_or(JSValue::UNDEFINED);
            self.stored_error.set(ctx, owner, r);
        }
        // Spec ReadableStreamClose: for each pending readRequest, perform its
        // close steps ({done:true}). Must happen before notify_peer_closed so
        // read results settle before reader.closed resolves.
        if state == RsState::Closed
            && let Some(cp) = self.controller_payload()
        {
            while cp.resolve_pending_read(ctx, JSValue::UNDEFINED, true) {}
        }

        notify_peer_closed(ctx, self.reader.get().map(JSValue::from), reason);
    }

    /// Cancel this stream. Sets `disturbed` and settles the stream as Closed
    /// (per spec `ReadableStreamCancel` -> `ReadableStreamClose`, so the peer
    /// reader's `closed` promise resolves), then propagates the underlying
    /// source's `cancel()` result (including a rejection) to the caller.
    pub(crate) fn cancel(
        &mut self,
        ctx: &mut ScopedContext,
        reason: JSValue,
    ) -> Result<Promise, i32> {
        // Spec `ReadableStreamCancel`:
        //   - sets disturbed (stream is no longer usable as a body);
        //   - a closed stream resolves immediately;
        //   - an errored stream rejects with the stored error (no cancelAlgorithm);
        //   - a readable stream closes and invokes the source's cancelAlgorithm.
        // Note: the locked-stream TypeError is checked in the public
        // `cancel()` method steps, not here — reader.cancel() also funnels
        // through this and must succeed while the stream is locked.
        self.disturbed = true;
        match self.state {
            RsState::Closed => {
                return Promise::from_resolve_value(ctx, JSValue::UNDEFINED);
            }
            // Readable streams never enter the Erroring state; treat it as
            // errored for exhaustiveness.
            RsState::Errored | RsState::Erroring => {
                return Promise::from_reject_value(ctx, self.stored_error.get());
            }
            RsState::Readable => {}
        }

        // Spec: cancel() closes the stream, not errors it — reader.closed must
        // resolve, and a later getReader().closed resolves too. Only a stream
        // error rejects `closed`. The cancel reason is forwarded to the
        // underlying source's cancel() below, not stored as the stream error.
        self.settle_state(ctx, RsState::Closed, None);

        if let Some(cp) = self.controller_payload() {
            let source = cp.underlying_source();
            let cancel_fn = cp.cancel_algorithm();
            // Propagate the underlying source's cancel() result (including a
            // rejection) to the reader.cancel() promise — pipeTo relies on this
            // to surface source cancel errors.
            return if cancel_fn.is_callable() {
                match cancel_fn.call(ctx, source, &[reason]) {
                    Ok(v) => {
                        if let Ok(p) = Promise::try_from(v) {
                            Ok(p)
                        } else {
                            Promise::from_resolve_value(ctx, v)
                        }
                    }
                    Err(_) => {
                        let e = ctx.take_exception().to_value(ctx);
                        Promise::from_reject_value(ctx, e)
                    }
                }
            } else {
                Promise::from_resolve_value(ctx, JSValue::UNDEFINED)
            };
        }

        Promise::from_resolve_value(ctx, JSValue::UNDEFINED)
    }
}

impl JSReadableStream {
    /// Lock this stream by acquiring a reader. Creates a default (or BYOB)
    /// reader bound to this stream and stores it in the stream's `reader`
    /// field. Returns the reader as a JSValue. Errors with TypeError if the
    /// stream is already locked.
    ///
    /// Shared by `getReader()` and the internal "lock the body so a later
    /// getReader() throws" operations (e.g. after text()/json()/bytes()
    /// consumed the body), so the lock semantics live in exactly one place.
    pub(crate) fn acquire_reader(
        &mut self,
        ctx: &mut ScopedContext,
        byob: bool,
    ) -> Result<JSReadableStreamDefaultReader, i32> {
        let handle = *self;

        let sp = self
            .payload_mut()
            .ok_or_else(|| ctx.throw_type_error("not a ReadableStream"))?;

        if sp.reader.get().is_some() {
            return Err(ctx.throw_type_error("ReadableStream is already locked"));
        }

        // WHATWG SetUpReadableStreamBYOBReader step 2: if the stream's
        // controller is not a ReadableByteStreamController, throw TypeError.
        if byob && !sp.is_byte_stream {
            return Err(ctx.throw_type_error(
                "getReader can only be used on byte streams when mode is \"byob\"",
            ));
        }

        let mut closed_promise = Promise::create(ctx)?.0;
        match sp.state {
            RsState::Closed => closed_promise.resolve(ctx, JSValue::UNDEFINED),
            // Readable streams never enter the Erroring state; treat it as
            // errored for exhaustiveness.
            RsState::Errored | RsState::Erroring => {
                closed_promise.reject(ctx, sp.stored_error.get())
            }
            RsState::Readable => {}
        }
        let mut reader = JSReadableStreamDefaultReader::new_instance(
            ctx,
            JSValue::UNDEFINED,
            ReaderPayload {
                stream: Some(handle),
                closed_promise: WriteBarrier::new(Some(closed_promise)),
                byob,
                owner: None,
            },
        )?;
        // Self-handle for the write barrier in `release_lock`.
        let reader_val = JSValue::from(reader);
        if let Some(rp) = reader.payload_mut() {
            rp.owner = Some(reader_val);
        }
        // The guard slot records the barrier.
        sp.reader.set(ctx, JSValue::from(handle), Some(reader));

        // WHATWG: ReadableStreamBYOBReader.prototype.constructor must point to
        // the global ReadableStreamBYOBReader constructor.  Instances created by
        // getReader({mode:'byob'}) are JSReadableStreamDefaultReader (unified
        // class), so their prototype chain's .constructor resolves to
        // ReadableStreamDefaultReader.  Patch the instance-level `constructor`
        // property so that tests which do `new X.constructor(stream)` invoke the
        // correct BYOB constructor (which validates is_byte_stream).
        if byob {
            // WHATWG: the BYOB reader is a separate class. Our unified
            // implementation uses JSReadableStreamDefaultReader for both, so
            // we patch the prototype chain so `instanceof ReadableStreamBYOBReader`
            // works correctly.
            if let Ok(byob_ctor) = ctx
                .global_obj()
                .get_property_str(ctx, "ReadableStreamBYOBReader")
            {
                let rv = JSValue::from(reader);
                // Set the constructor property on the instance.
                if let Some(mut obj) = rv.as_object() {
                    let _ = obj.define_property_value_str(
                        ctx,
                        "constructor",
                        byob_ctor,
                        zuqe::JS_PROP_C_W_E,
                    );
                }
                // Set prototype: reader.__proto__ = ReadableStreamBYOBReader.prototype
                if let Some(byob_proto) = byob_ctor
                    .get_property_str(ctx, "prototype")
                    .ok()
                    .and_then(|p| p.as_object())
                    && let Some(mut obj) = rv.as_object()
                {
                    let _ = obj.set_prototype(ctx, JSValue::from(byob_proto));
                }
            }
        }

        Ok(reader)
    }
}

const READABLE_STREAM_PROTO: &[FieldDef] = &[
    FieldDef::GETSET_ENUM("locked", Some(js_readable_stream_locked), None, 0),
    FieldDef::GETSET_ENUM("state", Some(js_readable_stream_state), None, 0),
    FieldDef::FUNC_ENUM("getReader", 0, js_readable_stream_get_reader, 0),
    FieldDef::FUNC_ENUM("cancel", 1, js_readable_stream_cancel, 0),
    FieldDef::FUNC_ENUM("pipeTo", 1, super::pipe::js_readable_stream_pipe_to, 0),
    FieldDef::FUNC_ENUM(
        "pipeThrough",
        1,
        super::pipe::js_readable_stream_pipe_through,
        0,
    ),
    FieldDef::FUNC_ENUM("tee", 0, super::readable_tee::js_readable_stream_tee, 0),
    FieldDef::FUNC_ENUM("values", 0, js_readable_stream_async_iterator, 0),
    FieldDef::GETSET(
        "[Symbol.asyncIterator]",
        Some(js_readable_stream_async_iterator_getter),
        None,
        0,
    ),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "ReadableStream",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "ReadableStream",
    JSReadableStream,
    ReadableStreamPayload,
    READABLE_STREAM_PROTO,
    Some(ClassCtorDef::new(js_readable_stream_constructor, 1, false).expose_to_global())
);

// `def_native_object!` generates no `GcBind`, but `WriteBarrier<Option<…>>`
// slots need it. Delegate to `Object` (the `bind_node` body must live here:
// `ScopedContext::bind_node` is crate-private to zuqe).
impl GcBind for JSReadableStream {
    fn bind_node(&self, ctx: &ScopedContext, owner: std::ptr::NonNull<zuqe::gc_lite::GcHead>) {
        GcBind::bind_node(&**self, ctx, owner)
    }
}

pub(crate) fn get_readable_stream_payload<'a>(
    ctx: &mut ScopedContext,
    val: &'a JSValue,
) -> Result<&'a ReadableStreamPayload, i32> {
    JSReadableStream::payload_of(val).ok_or_else(|| ctx.throw_type_error("not a ReadableStream"))
}

pub(crate) fn get_readable_stream_payload_mut<'a>(
    ctx: &mut ScopedContext,
    val: &'a mut JSValue,
) -> Result<&'a mut ReadableStreamPayload, i32> {
    JSReadableStream::payload_mut_of(val)
        .ok_or_else(|| ctx.throw_type_error("not a ReadableStream"))
}

fn js_readable_stream_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let new_target = cc.this();
    let underlying_source = cc.arg(0);
    let queuing_strategy = cc.arg(1);

    // WebIDL `optional object underlyingSource`: an explicit null is not an
    // object and must throw; undefined/missing (the common case) is fine.
    if underlying_source.is_null() {
        return Err(ctx.throw_type_error("underlyingSource must be an object"));
    }

    let payload = ReadableStreamPayload::new();
    let mut instance = JSReadableStream::new_instance(ctx, new_target, payload)?;

    // A byte stream uses a `ReadableByteStreamController`; a default stream uses
    // the `ReadableStreamDefaultController`. Both are created and the matching
    // one is passed to `start(controller)`.
    let is_bytes = {
        let ty = underlying_source
            .as_object()
            .and_then(|o| o.get_property_str(ctx, "type").ok())
            .unwrap_or(JSValue::UNDEFINED);
        if ty.is_undefined() {
            false
        } else {
            let s = ty.to_string(ctx)?.to_string();
            if s == "bytes" {
                true
            } else if s == "owning" {
                false
            } else {
                return Err(ctx.throw_type_error(
                    "ReadableStream type must be undefined, \"bytes\", or \"owning\"",
                ));
            }
        }
    };

    // Mark the stream as a byte stream so getReader({mode:'byob'}) and
    // ReadableStreamBYOBReader can validate the stream type.
    if is_bytes {
        instance.payload_mut().unwrap().is_byte_stream = true;
    }

    // WHATWG ReadableStream constructor byte-stream path:
    // step 4a: If strategy["size"] exists, throw a RangeError exception.
    if is_bytes && let Some(o) = queuing_strategy.as_object() {
        let size = o.get_property_str(ctx, "size")?;
        if !size.is_undefined() {
            return Err(
                ctx.throw_range_error("strategy.size must not be defined when type is \"bytes\"")
            );
        }
    }

    // WHATWG SetUpReadableByteStreamControllerFromUnderlyingSource:
    // step 6: if pull exists and is not callable, throw TypeError.
    // step 9: if autoAllocateChunkSize is 0, throw TypeError.
    let mut auto_chunk_size = 0u32;
    if is_bytes && let Some(o) = underlying_source.as_object() {
        let pull = o.get_property_str(ctx, "pull")?;
        if !pull.is_undefined() && !pull.is_callable() {
            return Err(ctx.throw_type_error("pull must be a function"));
        }

        let auto = o.get_property_str(ctx, "autoAllocateChunkSize")?;
        if !auto.is_undefined() {
            let n = auto.to_number(ctx)?.to_f64();
            if n == 0.0 {
                return Err(
                    ctx.throw_type_error("autoAllocateChunkSize must be a positive integer")
                );
            }
            auto_chunk_size = n as u32;
        }
    }

    let mut default_controller =
        create_readable_stream_controller(ctx, &instance, &underlying_source, &queuing_strategy)?;
    // Mark the controller as owning if the stream type is 'owning'.
    if !is_bytes {
        let ty_str = underlying_source
            .as_object()
            .and_then(|o| o.get_property_str(ctx, "type").ok())
            .and_then(|v| v.to_string(ctx).ok())
            .map(|s| s.to_string())
            .unwrap_or_default();
        if ty_str == "owning" {
            default_controller.payload_mut().unwrap().set_owning(true);
        }
    }
    let owner = JSValue::from(instance);
    instance
        .payload_mut()
        .unwrap()
        .controller
        .set(ctx, owner, Some(default_controller.into()));

    // SetUpReadableStreamDefaultControllerFromUnderlyingSource: capture the
    // source's `pull`/`cancel` and the strategy's `size` callbacks once, so a
    // throwing getter re-throws from the constructor and later pulls/cancels
    // do not re-run the getter.
    if !is_bytes {
        let mut pull_fn = JSValue::UNDEFINED;
        let mut cancel_fn = JSValue::UNDEFINED;
        if let Some(o) = underlying_source.as_object() {
            let pull = o.get_property_str(ctx, "pull")?;
            if pull.is_callable() {
                pull_fn = pull;
            } else if !pull.is_undefined() {
                // WebIDL: a present but non-callable callback member throws.
                return Err(ctx.throw_type_error("pull must be a function"));
            }
            let cancel = o.get_property_str(ctx, "cancel")?;
            if cancel.is_callable() {
                cancel_fn = cancel;
            } else if !cancel.is_undefined() {
                return Err(ctx.throw_type_error("cancel must be a function"));
            }
        }
        let size_fn = if let Some(o) = queuing_strategy.as_object() {
            let size = o.get_property_str(ctx, "size")?;
            if size.is_callable() {
                size
            } else {
                JSValue::UNDEFINED
            }
        } else {
            JSValue::UNDEFINED
        };
        let mut dc = default_controller;
        dc.set_algorithms(ctx, pull_fn, cancel_fn, size_fn);
    }

    let start_controller: JSValue = if is_bytes {
        let hwm = extract_high_water_mark(ctx, queuing_strategy, 1.0)?;
        let mut bc = JSReadableByteStreamController::new_instance(
            ctx,
            JSValue::UNDEFINED,
            ReadableControllerPayload::new_byte(
                if underlying_source.is_undefined_or_null() {
                    JSValue::UNDEFINED
                } else {
                    underlying_source
                },
                Some(instance),
                hwm,
                auto_chunk_size,
            ),
        )?;
        // Wire up algorithms for the byte controller
        if let Some(o) = underlying_source.as_object() {
            let pull = o.get_property_str(ctx, "pull")?;
            let cancel = o.get_property_str(ctx, "cancel")?;
            bc.set_algorithms(
                ctx,
                if pull.is_callable() {
                    pull
                } else {
                    JSValue::UNDEFINED
                },
                if cancel.is_callable() {
                    cancel
                } else {
                    JSValue::UNDEFINED
                },
                JSValue::UNDEFINED,
            );
        }
        // Store the byte controller as the stream's controller so reader.read()
        // can find the pull-into descriptors.
        let bc_val: JSValue = bc.into();
        let owner = JSValue::from(instance);
        instance
            .payload_mut()
            .unwrap()
            .controller
            .set(ctx, owner, Some(bc_val));
        // Set byte self-handle for call_pull.
        bc.set_byte_self_handle(ctx);
        bc_val
    } else {
        default_controller.into()
    };

    // Spec: a throwing underlying start() is re-thrown by the constructor (per
    // "Any thrown exceptions will be re-thrown by the ReadableStream()
    // constructor"); a start() returning a rejected promise errors the stream
    // asynchronously instead.
    let start_result = if let Some(o) = underlying_source.as_object() {
        match o.invoke_str_defined(ctx, "start", &[start_controller])? {
            Some(Err(_)) => {
                // start() threw synchronously — leave the exception set and
                // re-throw from the constructor.
                return Err(-1);
            }
            Some(Ok(v)) => Some(v),
            None => None,
        }
    } else {
        None
    };

    // A start() promise rejection errors the stream ("deal with rejection").
    // Fulfillment marks the controller started and may trigger the first pull.
    let mut start_handled_by_promise = false;
    if let Some(result) = start_result
        && let Ok(mut start_promise) = Promise::try_from(result)
    {
        start_handled_by_promise = true;
        let on_ok: JSValue = if is_bytes {
            ctx.create_native_function(
                Callback::Func(|_, _| Ok(JSValue::UNDEFINED)),
                "readableStartOk",
                0,
                0,
            )?
            .into()
        } else {
            ctx.create_native_function_with_data(
                Callback::Func(|cx, cc| mark_started_and_pull(cx, cc.data(0))),
                "readableStartOk",
                0,
                0,
                [start_controller].into(),
            )?
            .into()
        };
        let on_err: JSValue = ctx
            .create_native_function_with_data(
                Callback::Func(|cx, cc| {
                    let c = cc.data(0);
                    c.invoke_str(cx, "error", &[cc.arg(0)])?;
                    Ok(JSValue::UNDEFINED)
                }),
                "readableStartErr",
                1,
                0,
                [start_controller].into(),
            )?
            .into();
        start_promise.perform_then(ctx, on_ok, on_err)?;
    }

    // Spec: once start() completes, pull() fires when the stream needs data.
    // This lets a pull-only source push its first chunk (or error the stream)
    // without an explicit read. Use a resolved-promise reaction (not a job) so
    // start completion and the first pull run as a microtask, ordered before
    // any promise continuations queued by the caller.
    if !is_bytes && !start_handled_by_promise {
        let controller_val = JSValue::from(default_controller);
        let on_ok: JSValue = ctx
            .create_native_function_with_data(
                Callback::Func(|cx, cc| mark_started_and_pull(cx, cc.data(0))),
                "readableStartOk",
                0,
                0,
                [controller_val].into(),
            )?
            .into();
        let mut ready = Promise::from_resolve_value(ctx, JSValue::UNDEFINED)?;
        ready.perform_then(ctx, on_ok, on_ok)?;
    }

    Ok(instance.into())
}

/// Mark the default controller started (start() completed) and call `pull()`
/// when the stream needs data. Shared by the synchronous and promise-returning
/// start paths.
fn mark_started_and_pull(cx: &mut ScopedContext, controller_val: JSValue) -> JSResult {
    let cp = JSReadableStreamDefaultController::payload_of(&controller_val)
        .ok_or_else(|| cx.throw_internal_error("invalid controller"))?;
    cp.set_started(true);
    if cp.should_call_pull(cx)? {
        cp.call_pull(cx)?;
    }
    Ok(JSValue::UNDEFINED)
}

fn js_readable_stream_locked(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = get_readable_stream_payload(ctx, &this)?;
    Ok(JSValue::from(p.reader.get().is_some()))
}

fn js_readable_stream_state(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = get_readable_stream_payload(ctx, &this)?;
    let s = match p.state {
        RsState::Readable => "readable",
        RsState::Closed => "closed",
        // Readable streams never enter the Erroring state.
        RsState::Errored | RsState::Erroring => "errored",
    };
    let sref = ctx
        .create_string_from_utf8(s.as_bytes().to_vec())
        .map_err(|_| -1)?;
    Ok(JSValue::make_string(sref))
}

fn js_readable_stream_get_reader(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut stream = JSReadableStream::from_value(cc.this())
        .ok_or_else(|| ctx.throw_type_error("not a ReadableStream"))?;

    // options.mode: undefined -> default reader, "byob" -> BYOB reader,
    // anything else -> TypeError (the spec converts mode to a fixed enum).
    let options = cc.arg(0);
    // WebIDL `optional ReadableStreamGetReaderOptions options = {}`: a
    // non-object (other than undefined/null) throws a TypeError.
    if !options.is_undefined_or_null() && options.as_object().is_none() {
        return Err(ctx.throw_type_error("options must be an object"));
    }
    let byob = if options.is_undefined_or_null() {
        false
    } else {
        let mode = options.get_property_str(ctx, "mode")?;
        if mode.is_undefined() {
            false
        } else if mode.to_string(ctx)?.content().encode_utf8(false).as_ref() == "byob" {
            true
        } else {
            return Err(ctx.throw_type_error("`mode` must be undefined or \"byob\""));
        }
    };

    let reader = stream.acquire_reader(ctx, byob)?;
    Ok(JSValue::from(reader))
}

fn js_readable_stream_cancel(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let mut this = cc.this();
    let p = get_readable_stream_payload_mut(ctx, &mut this)?;
    // Spec `ReadableStream.cancel(reason)` step 1: canceling a locked stream
    // rejects with a TypeError (the cancelAlgorithm must not run).
    if p.reader.get().is_some() {
        if let Some(e) =
            ctx.create_error_object(ErrorKind::Type, "Cannot cancel a locked stream", false)
        {
            return Promise::from_reject_value(ctx, e.into()).map(JSValue::from);
        }
        return Err(ctx.throw_internal_error("failed to create TypeError"));
    }
    p.cancel(ctx, cc.arg(0)).map(JSValue::from)
}

// ============================================================================
// ReadableStream.from(asyncIterable)
// ============================================================================
// Builds a ReadableStream whose chunks are the yielded values of an async (or
// sync) iterable. Chunks are pulled **on demand**: the target controller's
// `pull` drives iterator.next() only when a read needs data (spec behavior),
// and each pull fetches at most one value. A resolved {done:false, value}
// enqueues `value`; {done:true} closes the stream; a rejection errors it.
//
// Callback `data` layout for the pull chain:
//   [0] = iterator object, [1] = iterator.next(), [2] = controller
fn js_readable_stream_from_static(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let source = cc.arg(0);
    // Spec: the source must be an Object. Primitives (incl. strings, which are
    // iterable) are rejected with a TypeError.
    if source.as_object().is_none() {
        return Err(ctx.throw_type_error("ReadableStream.from: source must be an object"));
    }
    let iterator = source
        .get_iterator(ctx, true)
        .map_err(|_| -1)?
        .ok_or_else(|| {
            ctx.throw_type_error(
                "value has neither [Symbol.asyncIterator] nor [Symbol.iterator] property",
            )
        })?;
    let next_fn = iterator.get_property_str(ctx, "next")?;
    if !next_fn.is_callable() {
        return Err(ctx.throw_type_error("ReadableStream.from: iterator has no callable next()"));
    }

    // Underlying source whose `pull` drives the iterator on demand. The
    // in-flight counter guards against re-entrant pulls calling next() again
    // before the previous next() has settled (e.g. a reader.read() issued from
    // inside next()).
    let mut in_flight = ctx.create_base_object()?;
    in_flight.define_property_value_str(ctx, "n", JSValue::ZERO, zuqe::JS_PROP_C_W_E)?;
    let in_flight_val = JSValue::from(in_flight);
    let pull_fn = ctx
        .create_native_function_with_data(
            Callback::Func(from_pump_step),
            "fromPull",
            1,
            0,
            [JSValue::from(iterator), next_fn, in_flight_val].into(),
        )?
        .into();
    let mut source_obj = ctx.create_base_object()?;
    source_obj.define_property_value_str(ctx, "pull", pull_fn, zuqe::JS_PROP_C_W_E)?;
    let source_val = JSValue::from(source_obj);

    let mut stream =
        JSReadableStream::new_instance(ctx, JSValue::UNDEFINED, ReadableStreamPayload::new())?;
    let mut controller = JSReadableStreamDefaultController::new_instance(
        ctx,
        JSValue::UNDEFINED,
        ReadableControllerPayload::new_default(source_val, Some(stream), 1.0),
    )?;
    // Wire the controller's self-handle (call_controller_pull needs it).
    let handle = controller;
    controller.set_controller(ctx, Some(handle));
    // No user `start()` runs for ReadableStream.from — treat it as started so
    // the pull-driven iterator feeding begins, and register the pull/cancel
    // callbacks (cancel drives the iterator's return()).
    controller
        .payload()
        .ok_or_else(|| ctx.throw_internal_error("invalid controller"))?
        .set_started(true);
    let iterator_val = JSValue::from(iterator);
    let return_fn = iterator_val.get_property_str(ctx, "return")?;
    let cancel_fn = ctx
        .create_native_function_with_data(
            Callback::Func(from_cancel),
            "fromCancel",
            1,
            0,
            [iterator_val, return_fn].into(),
        )?
        .into();
    controller.set_algorithms(ctx, pull_fn, cancel_fn, JSValue::UNDEFINED);
    let owner = JSValue::from(stream);
    stream
        .payload_mut()
        .unwrap()
        .controller
        .set(ctx, owner, Some(controller.into()));
    Ok(JSValue::from(stream))
}

// Controller `cancel` entry (spec `ReadableStreamFromIterable` cancelAlgorithm):
// call the iterator's `return(reason)`, awaiting its result. A missing return()
// resolves; a non-callable return(), a thrown/rejected return(), or a return()
// fulfilling with a non-object rejects the cancel promise.
// `data`: [0] = iterator, [1] = iterator.return (or undefined).
fn from_cancel(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let iterator = cc.data(0);
    let return_fn = cc.data(1);
    let reason = cc.arg(0);

    if return_fn.is_undefined() {
        return Promise::from_resolve_value(ctx, JSValue::UNDEFINED).map(JSValue::from);
    }
    if !return_fn.is_callable() {
        let e = ctx
            .create_error_object(ErrorKind::Type, "return is not a function", false)
            .ok_or(-1)?;
        return Promise::from_reject_value(ctx, e.into()).map(JSValue::from);
    }

    let return_res = return_fn.call(ctx, iterator, &[reason]);
    let mut return_promise = match return_res {
        Ok(v) => match Promise::try_from(v) {
            Ok(p) => p,
            Err(_) => {
                let (mut p, _rr) = Promise::create(ctx)?;
                p.resolve(ctx, v);
                p
            }
        },
        Err(_) => {
            // return() threw synchronously — reject with the thrown value.
            let e = ctx.take_exception().to_value(ctx);
            return Promise::from_reject_value(ctx, e).map(JSValue::from);
        }
    };

    let (output, _rr) = Promise::create(ctx)?;
    let ok = ctx
        .create_native_function_with_data(
            Callback::Func(from_cancel_ok),
            "fromCancelOk",
            1,
            0,
            [JSValue::from(output)].into(),
        )?
        .into();
    let err = ctx
        .create_native_function_with_data(
            Callback::Func(from_cancel_err),
            "fromCancelErr",
            1,
            0,
            [JSValue::from(output)].into(),
        )?
        .into();
    return_promise.perform_then(ctx, ok, err)?;
    Ok(output.into())
}

// return() fulfilled: a non-object result rejects with a TypeError, otherwise
// the cancel resolves.
fn from_cancel_ok(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let output = Promise::try_from(cc.data(0)).map_err(|_| -1)?;
    let mut p = output;
    if cc.arg(0).as_object().is_none() {
        let e = ctx
            .create_error_object(
                ErrorKind::Type,
                "return() must fulfill with an object",
                false,
            )
            .ok_or(-1)?;
        p.reject(ctx, e.into());
    } else {
        p.resolve(ctx, JSValue::UNDEFINED);
    }
    Ok(JSValue::UNDEFINED)
}

// return() rejected: propagate the rejection to the cancel promise.
fn from_cancel_err(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let output = Promise::try_from(cc.data(0)).map_err(|_| -1)?;
    let mut p = output;
    p.reject(ctx, cc.arg(0));
    Ok(JSValue::UNDEFINED)
}

// Controller `pull` entry: fetch at most one value from the iterator and enqueue
// it. Continues to the next pull only while reads are still waiting (driven via
// queue_job), so next() is never called past what readers need.
fn from_pump_step(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let iterator = Object::try_from(cc.data(0)).map_err(|_| -1)?;
    let next_fn = cc.data(1);
    let mut in_flight = cc.data(2);
    let controller = cc.arg(0);
    // Only fetch when a read is actually waiting, and never while a previous
    // next() is still in flight. Without these guards the controller's
    // post-enqueue refill (or a re-entrant read from inside next()) would call
    // next() repeatedly even though no consumer asked for more data.
    let has_pending = JSReadableStreamDefaultController::payload_of(&controller)
        .map(|cp| !cp.pending_read().borrow().is_empty())
        .unwrap_or(false);
    if !has_pending {
        return Ok(JSValue::UNDEFINED);
    }
    let in_fly = in_flight
        .get_property_str(ctx, "n")?
        .to_number(ctx)?
        .to_f64() as i32;
    if in_fly > 0 {
        return Ok(JSValue::UNDEFINED);
    }
    in_flight.set_property_str(ctx, "n", JSValue::from(1))?;
    from_pull_next(ctx, iterator, next_fn, in_flight, controller)
}

// Call iterator.next(), await the result, and branch into
// from_pump_fulfilled / from_pump_rejected.
fn from_pull_next(
    ctx: &mut ScopedContext,
    iterator: Object,
    next_fn: JSValue,
    in_flight: JSValue,
    controller: JSValue,
) -> JSResult {
    let next_promise = next_fn.call(ctx, JSValue::from(iterator), &[])?;
    // Spec: next()'s result is wrapped via PromiseResolve. If it is already a
    // promise use it; otherwise (next() returned a bare value) resolve it so the
    // iterator-result-object check below runs and errors the stream if needed.
    let mut promise: Promise = match Promise::try_from(next_promise) {
        Ok(p) => p,
        Err(_) => {
            let (mut p, _rr) = Promise::create(ctx)?;
            p.resolve(ctx, next_promise);
            p
        }
    };
    let step = ctx
        .create_native_function_with_data(
            Callback::Func(from_pump_fulfilled),
            "fromPump",
            1,
            0,
            [JSValue::from(iterator), next_fn, controller, in_flight].into(),
        )?
        .into();
    let fail = ctx
        .create_native_function_with_data(
            Callback::Func(from_pump_rejected),
            "fromPumpErr",
            1,
            0,
            [JSValue::from(iterator), next_fn, controller, in_flight].into(),
        )?
        .into();
    promise.perform_then(ctx, step, fail)?;
    Ok(JSValue::UNDEFINED)
}

// Await iterator.next() -> {done, value}. Enqueue `value`, then keep pulling
// only if reads are still outstanding; close when done.
fn from_pump_fulfilled(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let _iterator = Object::try_from(cc.data(0)).map_err(|_| -1)?;
    let _next_fn = cc.data(1);
    let controller = cc.data(2);
    let mut in_flight = cc.data(3);
    let result = cc.arg(0);
    in_flight.set_property_str(ctx, "n", JSValue::ZERO)?;
    // Spec: iterator.next() must fulfill with an iterator result object; a
    // non-object (e.g. a bare number) errors the stream with a TypeError.
    if result.as_object().is_none() {
        let _ = ctx.throw_type_error("iterator result must be an object");
        let e = ctx.take_exception().to_value(ctx);
        if !super::readable_tee::tee_branch_is_final(ctx, controller) {
            let error_fn = controller.get_property_str(ctx, "error")?;
            error_fn.call(ctx, controller, &[e])?;
        }
        return Ok(JSValue::UNDEFINED);
    }
    let done = result
        .get_property_str(ctx, "done")?
        .to_bool()
        .unwrap_or(false);
    if done {
        // Skip close() if the controller already errored/closed; otherwise
        // close() errors propagate via `?` (the promise-reaction job takes and
        // rejects with any thrown exception).
        if !super::readable_tee::tee_branch_is_final(ctx, controller) {
            let close_fn = controller.get_property_str(ctx, "close")?;
            close_fn.call(ctx, controller, &[])?;
        }
        return Ok(JSValue::UNDEFINED);
    }
    let value = result.get_property_str(ctx, "value")?;
    if !super::readable_tee::tee_branch_is_final(ctx, controller) {
        let enqueue_fn = controller.get_property_str(ctx, "enqueue")?;
        enqueue_fn.call(ctx, controller, &[value])?;
    }
    Ok(JSValue::UNDEFINED)
}

// Await iterator.next() rejected: error the stream with the rejection reason.
// Guard so error() is not called on an already-terminated controller.
fn from_pump_rejected(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let controller = cc.data(2);
    let mut in_flight = cc.data(3);
    in_flight.set_property_str(ctx, "n", JSValue::ZERO)?;
    // Skip error() if the controller already errored; otherwise error() errors
    // propagate via `?` (the promise-reaction job takes and rejects with it).
    if !super::readable_tee::tee_branch_is_final(ctx, controller) {
        let error_fn = controller.get_property_str(ctx, "error")?;
        error_fn.call(ctx, controller, &[cc.arg(0)])?;
    }
    Ok(JSValue::UNDEFINED)
}

fn js_readable_stream_async_iterator(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    create_stream_async_iterator(ctx, &cc.this(), cc.arg(0))
}

// Spec: `get [Symbol.asyncIterator]() { return this.values; }`.
fn js_readable_stream_async_iterator_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    cc.this().get_property_str(ctx, "values")
}

/// A channel-backed stream being polled. The idle deadline is per stream and
/// refreshed on every chunk, so a slow but live producer is never cut off; only
/// a stalled stream times out.
#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct ChannelStream {
    pub(crate) controller: JSReadableByteStreamController,
    #[gc(skip)]
    pub(crate) rx: zuqe::WakeReceiver<Result<Vec<u8>, String>>,
    #[gc(skip)]
    pub(crate) idle_deadline: Instant,
}

/// Per-runtime channel-backed streams, stored on `WhatwgState`.
#[derive(Default, GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct ChannelStreamState {
    pub(crate) streams: HashMap<u64, ChannelStream>,
    /// Ids start at 1.
    pub(crate) next_id: u64,
    /// Whether the pump job is currently queued. The pump is the only thing that
    /// moves channel bytes into a stream, and a queued job is dropped for good
    /// once it returns `Err`, so its liveness must be tracked explicitly: with
    /// leftover entries in `streams`, "is the map empty?" would report a dead
    /// pump as alive forever.
    pub(crate) poller_running: bool,
}

impl ChannelStreamState {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

fn create_readable_stream_controller(
    ctx: &mut ScopedContext,
    stream: &JSReadableStream,
    underlying_source: &JSValue,
    queuing_strategy: &JSValue,
) -> Result<JSReadableStreamDefaultController, i32> {
    let hwm = extract_high_water_mark(ctx, *queuing_strategy, 1.0)?;
    let mut controller = JSReadableStreamDefaultController::new_instance(
        ctx,
        JSValue::UNDEFINED,
        ReadableControllerPayload::new_default(
            if underlying_source.is_undefined_or_null() {
                JSValue::UNDEFINED
            } else {
                *underlying_source
            },
            Some(*stream),
            hwm,
        ),
    )?;
    let handle = controller;
    controller.set_controller(ctx, Some(handle));
    Ok(controller)
}

// ============================================================================
// Stream async iterator
// ============================================================================

fn create_stream_async_iterator(
    ctx: &mut ScopedContext,
    stream_val: &JSValue,
    options: JSValue,
) -> JSResult {
    // `values({ preventCancel })` drives the return() behavior.
    let prevent_cancel = if let Some(obj) = options.as_object() {
        obj.get_property_str(ctx, "preventCancel")?.to_bool()?
    } else {
        false
    };

    // Lock the stream by creating a reader.
    let reader_val = {
        let p = JSReadableStream::payload_of(stream_val)
            .ok_or_else(|| ctx.throw_type_error("not a ReadableStream"))?;
        if p.reader.get().is_some() {
            return Err(
                ctx.throw_type_error("ReadableStream is locked — cannot create async iterator")
            );
        }

        let mut this = *stream_val;
        let mut reader = JSReadableStreamDefaultReader::new_instance(
            ctx,
            JSValue::UNDEFINED,
            ReaderPayload {
                stream: Some(JSReadableStream::try_from(*stream_val)?),
                closed_promise: WriteBarrier::new(None),
                byob: false,
                owner: None,
            },
        )?;
        // Self-handle for the write barrier in `release_lock`.
        let reader_val = JSValue::from(reader);
        if let Some(rp) = reader.payload_mut() {
            rp.owner = Some(reader_val);
        }
        // Capture the owner before the `&mut this` borrow below.
        let owner = *stream_val;
        if let Some(sp) = JSReadableStream::payload_mut_of(&mut this) {
            // The guard slot records the barrier.
            sp.reader.set(ctx, owner, Some(reader));
        }
        reader_val
    };

    #[derive(GcTrace)]
    #[gc(crate_path = zuqe::gc_lite)]
    struct ReaderFetcher {
        reader_val: JSReadableStreamDefaultReader,
        prevent_cancel: bool,
        closed: Cell<bool>,
        // Cache the promise from reader.read() so we don't call reader.read()
        // again on every tick, which would create a new PENDING_READ and lose
        // the value committed by a previous enqueue().
        cached_promise: RefCell<Option<Promise>>,
    }

    impl ReaderFetcher {
        /// Release the reader lock (ReadableStreamDefaultReaderRelease), so the
        /// stream can be locked again by a later getReader()/values() and any
        /// pending read rejects with a TypeError.
        fn release_lock(&self, ctx: &mut ScopedContext) {
            let mut rv = JSValue::from(self.reader_val);
            if let Some(rp) = JSReadableStreamDefaultReader::payload_mut_of(&mut rv) {
                rp.release_lock(ctx);
            }
            *self.cached_promise.borrow_mut() = None;
        }

        /// (state, stored_error) of the stream behind this iterator's reader.
        fn stream_state(&self) -> Option<(RsState, JSValue)> {
            let rv = JSValue::from(self.reader_val);
            let rp = JSReadableStreamDefaultReader::payload_of(&rv)?;
            let stream = rp.stream?;
            let sp = stream.payload()?;
            Some((sp.state, sp.stored_error.get()))
        }
    }

    impl AsyncIteratorFetcher for ReaderFetcher {
        fn try_fetch(&self, ctx: &mut ScopedContext) -> Result<IterFetchStatus, i32> {
            if self.closed.get() {
                return Ok(IterFetchStatus::Done);
            }

            // Check cached promise first (from a previous try_fetch call).
            // The cached promise is moved out under a single borrow; for the
            // Pending case we put it back before returning so the same borrow
            // is never held across a second borrow_mut() call.
            let cached = self.cached_promise.borrow_mut().take();
            if let Some(promise) = cached {
                match promise.state() {
                    zuqe::builtins::promise::PromiseState::Fulfilled => {
                        let result = promise.result();
                        if let Ok(done_val) = result.get_property_str(ctx, "done")
                            && done_val.to_bool()?
                        {
                            // Stream exhausted: release the lock so a later
                            // getReader() works (spec: the iterator releases the
                            // reader when it completes).
                            self.release_lock(ctx);
                            return Ok(IterFetchStatus::Done);
                        }
                        if let Ok(value) = result.get_property_str(ctx, "value") {
                            return Ok(IterFetchStatus::Value(value));
                        }
                        return Ok(IterFetchStatus::Value(result));
                    }
                    zuqe::builtins::promise::PromiseState::Rejected => {
                        // Reject with the stream's real error, not a generic
                        // wrapper, and finish the iterator: a later next()
                        // returns {done: true}.
                        let reason = promise.result();
                        self.closed.set(true);
                        self.release_lock(ctx);
                        ctx.throw(Exception::Error(reason));
                        return Err(-1);
                    }
                    zuqe::builtins::promise::PromiseState::Pending => {
                        // Still pending — put it back and wait. Borrow is now
                        // released (promise is owned locally), so this is safe.
                        *self.cached_promise.borrow_mut() = Some(promise);
                        return Ok(IterFetchStatus::Wait);
                    }
                }
            }

            // No cached promise — make a fresh reader.read() call
            let reader_val = JSValue::from(self.reader_val);
            let p = match JSReadableStreamDefaultReader::payload_of(&reader_val) {
                Some(p) => p,
                None => return Ok(IterFetchStatus::Done),
            };

            let promise = p.read(ctx, None, 1)?;
            match promise.state() {
                zuqe::builtins::promise::PromiseState::Fulfilled => {
                    let result = promise.result();
                    if let Ok(done_val) = result.get_property_str(ctx, "done")
                        && done_val.to_bool()?
                    {
                        self.release_lock(ctx);
                        return Ok(IterFetchStatus::Done);
                    }
                    if let Ok(value) = result.get_property_str(ctx, "value") {
                        return Ok(IterFetchStatus::Value(value));
                    }
                    Ok(IterFetchStatus::Value(result))
                }
                zuqe::builtins::promise::PromiseState::Rejected => {
                    let reason = promise.result();
                    self.closed.set(true);
                    self.release_lock(ctx);
                    ctx.throw(Exception::Error(reason));
                    Err(-1)
                }
                zuqe::builtins::promise::PromiseState::Pending => {
                    // Cache the pending promise and wait for enqueue() to resolve it
                    *self.cached_promise.borrow_mut() = Some(promise);
                    Ok(IterFetchStatus::Wait)
                }
            }
        }

        fn on_return(
            &self,
            ctx: &mut ScopedContext,
            value: JSValue,
        ) -> Result<Option<Promise>, i32> {
            // Reader/stream already detached: nothing to cancel or release.
            let Some((state, stored_error)) = self.stream_state() else {
                self.closed.set(true);
                return iterator_result_promise(ctx, value, true).map(Some);
            };

            // Per spec, return() on an errored stream rejects with the stored
            // error (releasing the reader synchronously first).
            if state == RsState::Errored {
                let err = stored_error;
                self.release_lock(ctx);
                self.closed.set(true);
                return Promise::from_reject_value(ctx, err).map(Some);
            }

            // Closed stream or preventCancel: release and resolve {value, done}.
            if state == RsState::Closed || self.prevent_cancel {
                self.release_lock(ctx);
                self.closed.set(true);
                return iterator_result_promise(ctx, value, true).map(Some);
            }

            // Cancellable path: cancel the reader, release the lock, and resolve
            // {value, done} once the cancel promise settles (rejecting with the
            // cancel error if it rejects). The lock release stays synchronous so
            // getReader() works immediately after return().
            let rv = JSValue::from(self.reader_val);
            let mut cancel_promise = match JSReadableStreamDefaultReader::payload_of(&rv) {
                Some(rp) => match rp.cancel(ctx, value) {
                    Ok(p) => p,
                    Err(_) => {
                        let e = ctx.take_exception().to_value(ctx);
                        self.release_lock(ctx);
                        self.closed.set(true);
                        return Promise::from_reject_value(ctx, e).map(Some);
                    }
                },
                None => {
                    self.release_lock(ctx);
                    self.closed.set(true);
                    return iterator_result_promise(ctx, value, true).map(Some);
                }
            };

            self.release_lock(ctx);
            self.closed.set(true);

            let result = make_iterator_result(ctx, value, true)?;
            let (mut output, _rr) = Promise::create(ctx)?;

            // If the cancel settled synchronously, resolve the return() promise
            // right away so a next() issued in the same tick (which resolves
            // immediately on a completed iterator) settles after return()
            // (WPT: "next() resolves after return()").
            if cancel_promise.state() == zuqe::builtins::promise::PromiseState::Fulfilled {
                output.resolve(ctx, result);
                return Ok(Some(output));
            }

            let data = [JSValue::from(output), result];
            let on_ok = ctx
                .create_native_function_with_data(
                    Callback::Func(stream_iter_return_cancel_ok),
                    "returnCancelOk",
                    0,
                    0,
                    data.into(),
                )?
                .into();
            let on_err = ctx
                .create_native_function_with_data(
                    Callback::Func(stream_iter_return_cancel_err),
                    "returnCancelErr",
                    1,
                    0,
                    data.into(),
                )?
                .into();
            cancel_promise.perform_then(ctx, on_ok, on_err)?;

            Ok(Some(output))
        }

        fn close(&self) {
            self.closed.set(true);
            // The polling job checks `closed` and returns Done, so the cached
            // promise is the only thing that needs clearing. The in-flight read
            // is stored on the stream's controller (per-controller, not global),
            // and is released by GC once the iterator is dropped.
            *self.cached_promise.borrow_mut() = None;
        }
    }

    let iter = AsyncIterableIterator::create(
        ctx,
        ReaderFetcher {
            reader_val: JSReadableStreamDefaultReader::try_from(reader_val).map_err(|_| -1i32)?,
            prevent_cancel,
            closed: Cell::new(false),
            cached_promise: RefCell::new(None),
        },
    )
    .map_err(|_| -1i32)?;

    Ok(iter.into())
}

// The async cancel initiated by return() settled: resolve the return() promise
// with the prebuilt `{value, done: true}` result.
fn stream_iter_return_cancel_ok(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let output = Promise::try_from(cc.data(0)).map_err(|_| -1)?;
    let result = cc.data(1);
    let mut p = output;
    p.resolve(ctx, result);
    Ok(JSValue::UNDEFINED)
}

// The async cancel initiated by return() rejected: reject the return() promise
// with the cancel error.
fn stream_iter_return_cancel_err(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let output = Promise::try_from(cc.data(0)).map_err(|_| -1)?;
    let mut p = output;
    p.reject(ctx, cc.arg(0));
    Ok(JSValue::UNDEFINED)
}

/// GC roots for the text-channel polling job: it runs across event-loop turns
/// while only the job itself keeps the controller reachable.
struct TextStreamRoots {
    ctrl: JSReadableStreamDefaultController,
}

impl JobGcTrace for TextStreamRoots {
    fn job_trace_values(&self, gcx: &mut GcTraceCtx) {
        JSValue::from(self.ctrl).trace(gcx);
    }
}

impl JSReadableStream {
    /// Create a `ReadableStream` backed by a `crossbeam::Receiver<Result<Vec<u8>, String>>`.
    ///
    /// Uses a background microtask (queue_job) to poll the channel and push
    /// chunks into the stream's controller. A `Ok(bytes)` item enqueues a chunk;
    /// an `Err(msg)` item errors the stream (the reader's `read()` rejects); when
    /// the channel is disconnected the stream is closed.
    pub(crate) fn from_channel(
        ctx: &mut ScopedContext,
        rx: zuqe::WakeReceiver<Result<Vec<u8>, String>>,
        signal: Option<JSValue>,
    ) -> Result<Self, i32> {
        let source = ctx.create_base_object()?;

        let mut stream =
            JSReadableStream::new_instance(ctx, JSValue::UNDEFINED, ReadableStreamPayload::new())?;
        // A fetch response body is a byte stream (Fetch spec: an HTTP fetch runs
        // "extract a byte stream"), so `body.getReader({mode:"byob"})` must work.
        stream.payload_mut().unwrap().is_byte_stream = true;

        let controller = JSReadableByteStreamController::new_instance(
            ctx,
            JSValue::UNDEFINED,
            ReadableControllerPayload::new_byte(JSValue::from(source), Some(stream), 0.0, 0),
        )?;
        let controller_val: JSValue = controller.into();
        let owner = JSValue::from(stream);
        stream
            .payload_mut()
            .unwrap()
            .controller
            .set(ctx, owner, Some(controller_val));
        controller.set_byte_self_handle(ctx);

        // Keep the abort signal alive on the stream payload (GC-traced), not just in
        // the channel registry, so it cannot be reclaimed while the body is live.
        let sp = stream.payload_mut().unwrap();
        sp.signal.set(ctx, owner, signal);

        let start_poller = {
            let st = WhatwgState::of(ctx);
            let id = st.channel_streams.next_id;
            st.channel_streams.next_id = id + 1;
            st.channel_streams.streams.insert(
                id,
                ChannelStream {
                    controller,
                    rx,
                    idle_deadline: Instant::now(),
                },
            );
            !std::mem::replace(&mut st.channel_streams.poller_running, true)
        };

        if start_poller {
            start_channel_stream_poller(ctx);
        }

        Ok(stream)
    }

    /// Create a `ReadableStream` from a single byte buffer (synthetic body).
    ///
    /// Unlike `from_channel`, this does not create or poll a
    /// channel — the data is enqueued and the stream is closed immediately.
    pub(crate) fn from_bytes(ctx: &mut ScopedContext, bytes: Vec<u8>) -> Result<Self, i32> {
        let source = ctx.create_base_object()?;

        let mut stream =
            JSReadableStream::new_instance(ctx, JSValue::UNDEFINED, ReadableStreamPayload::new())?;
        // Synthetic HTTP bodies (data:/blob:) are byte streams too, same as
        // from_channel.
        stream.payload_mut().unwrap().is_byte_stream = true;

        let controller = JSReadableByteStreamController::new_instance(
            ctx,
            JSValue::UNDEFINED,
            ReadableControllerPayload::new_byte(JSValue::from(source), Some(stream), 0.0, 0),
        )?;
        let controller_val: JSValue = controller.into();
        let owner = JSValue::from(stream);
        stream
            .payload_mut()
            .unwrap()
            .controller
            .set(ctx, owner, Some(controller_val));
        controller.set_byte_self_handle(ctx);

        // Enqueue the single chunk as a TypedArray. A byte stream rejects a
        // zero-length view, so an empty body just closes.
        if !bytes.is_empty() {
            let ta = TypedArray::create_from_vec_u8(ctx, bytes)?;
            let enqueue_fn = controller_val.get_property_str(ctx, "enqueue")?;
            enqueue_fn.call(ctx, controller_val, &[JSValue::from(ta)])?;
        }

        // Close the stream — data is the full body.
        let close_fn = controller_val.get_property_str(ctx, "close")?;
        close_fn.call(ctx, controller_val, &[])?;

        Ok(stream)
    }

    /// Create a `ReadableStream` from an already-decoded text string. Non-empty
    /// text is enqueued as a single string chunk; empty text produces a closed,
    /// chunk-free stream. Used by Request/Response `textStream()`.
    pub(crate) fn from_text(ctx: &mut ScopedContext, text: String) -> Result<Self, i32> {
        let source = ctx.create_base_object()?;
        let mut stream =
            JSReadableStream::new_instance(ctx, JSValue::UNDEFINED, ReadableStreamPayload::new())?;
        let controller = JSReadableStreamDefaultController::new_instance(
            ctx,
            JSValue::UNDEFINED,
            ReadableControllerPayload::new_default(JSValue::from(source), Some(stream), 1.0),
        )?;
        let controller_val = JSValue::from(controller);
        let owner = JSValue::from(stream);
        stream
            .payload_mut()
            .unwrap()
            .controller
            .set(ctx, owner, Some(controller_val));

        if !text.is_empty() {
            let sval = ctx.create_string_from_utf8(text.into_bytes())?;
            let enqueue_fn = controller_val.get_property_str(ctx, "enqueue")?;
            enqueue_fn.call(ctx, controller_val, &[JSValue::make_string(sval)])?;
        }
        // Close the stream — the text is the entire body.
        let close_fn = controller_val.get_property_str(ctx, "close")?;
        close_fn.call(ctx, controller_val, &[])?;

        Ok(stream)
    }

    /// Create a `ReadableStream` of UTF-8-decoded string chunks from a byte
    /// channel. Each `Ok(bytes)` item is decoded and enqueued as a string; an
    /// `Err(msg)` item errors the stream; disconnect closes it. Used by
    /// `textStream()` on network responses.
    pub(crate) fn from_text_channel(
        ctx: &mut ScopedContext,
        rx: zuqe::WakeReceiver<Result<Vec<u8>, String>>,
    ) -> Result<Self, i32> {
        let source = ctx.create_base_object()?;
        let mut stream =
            JSReadableStream::new_instance(ctx, JSValue::UNDEFINED, ReadableStreamPayload::new())?;
        let controller = JSReadableStreamDefaultController::new_instance(
            ctx,
            JSValue::UNDEFINED,
            ReadableControllerPayload::new_default(JSValue::from(source), Some(stream), 1.0),
        )?;
        let owner = JSValue::from(stream);
        stream
            .payload_mut()
            .unwrap()
            .controller
            .set(ctx, owner, Some(controller.into()));

        let ctrl = controller;
        let start = Instant::now();
        const TEXT_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
        // The polling job keeps running while JS holds the stream (or after
        // JS drops it, until the timeout fires), so the controller it calls
        // into must be traced as a job root.
        let roots = TextStreamRoots { ctrl };
        ctx.queue_job(
            move |cx| match rx.try_recv() {
                Ok(Ok(bytes)) => {
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    let sval = cx.create_string_from_utf8(text.into_bytes())?;
                    let enqueue_fn = ctrl.get_property_str(cx, "enqueue")?;
                    enqueue_fn.call(cx, JSValue::from(ctrl), &[JSValue::make_string(sval)])?;
                    Ok(JobState::Block)
                }
                Ok(Err(msg)) => {
                    let err = cx
                        .create_error_object(ErrorKind::Type, &msg, false)
                        .ok_or(-1)?;
                    let error_fn = ctrl.get_property_str(cx, "error")?;
                    error_fn.call(cx, JSValue::from(ctrl), &[err.into()])?;
                    Ok(JobState::Done)
                }
                Err(TryRecvError::Disconnected) => {
                    let close_fn = ctrl.get_property_str(cx, "close")?;
                    close_fn.call(cx, JSValue::from(ctrl), &[])?;
                    Ok(JobState::Done)
                }
                Err(TryRecvError::Empty) => {
                    if start.elapsed() > TEXT_STREAM_IDLE_TIMEOUT {
                        let err = cx.create_string_from_utf8(b"text stream timeout".to_vec())?;
                        let error_fn = ctrl.get_property_str(cx, "error")?;
                        error_fn.call(cx, JSValue::from(ctrl), &[JSValue::make_string(err)])?;
                        Ok(JobState::Done)
                    } else {
                        Ok(JobState::Block)
                    }
                }
            },
            roots,
        );

        Ok(stream)
    }

    /// Build a `ReadableStream` of UTF-8-decoded string chunks from a body source.
    /// Used by Request/Response `textStream()`. A `Stream` body is drained
    /// synchronously, so it must already be populated (as in the WPT tests); a
    /// live `Channel` is decoded incrementally by a polling job.
    pub(crate) fn from_text_source(
        ctx: &mut ScopedContext,
        source: BodySource,
    ) -> Result<Self, i32> {
        match source {
            BodySource::Synthetic(bytes) => {
                let text = String::from_utf8_lossy(&bytes).into_owned();
                Self::from_text(ctx, text)
            }
            BodySource::Stream(mut stream) => {
                let reader_obj = stream.acquire_reader(ctx, false)?;
                let p = reader_obj
                    .payload()
                    .ok_or_else(|| ctx.throw_type_error("not a ReadableStreamDefaultReader"))?;
                let bytes = p.drain_sync(ctx)?;
                let text = String::from_utf8(bytes)
                    .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
                Self::from_text(ctx, text)
            }
            BodySource::Channel(rx) => Self::from_text_channel(ctx, rx),
        }
    }
}

/// Idle timeout for a channel-backed stream, applied per stream and refreshed
/// on every received chunk. A stream is only killed when its own producer goes
/// quiet for this long, so neither a slow body nor a long-lived sibling stream
/// can starve it.
///
/// Keep this well above a caller's own stall guard: a fetch body is bounded by
/// the request `timeout` (the transport errors the stream when it expires), so
/// this is only the wedged-producer safety net and must not cut off a slow but
/// alive transfer (slow origins can pause for tens of seconds between chunks).
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Pump one channel-backed stream: move every chunk its producer has queued
/// into the stream's controller.
///
/// Returns `Ok(true)` to keep the stream registered, `Ok(false)` once it is
/// finished (producer disconnected, producer failed, stream stalled past
/// `STREAM_IDLE_TIMEOUT`, or the abort signal fired). `Err` means a JS call
/// failed — the stream is unusable, but the caller must keep the pump alive.
fn pump_channel_stream(cx: &mut ScopedContext, id: u64) -> Result<bool, i32> {
    // Resolve abort signal from the GC-traced stream payload
    // (controller -> stream -> signal). Never read a dangling
    // handle: only visit entries that still map to a live stream.
    let resolved = WhatwgState::of(cx)
        .channel_streams
        .streams
        .get(&id)
        .map(|s| s.controller)
        .map(|ctrl| {
            let maybe_signal = JSReadableByteStreamController::payload_of(&JSValue::from(ctrl))
                .and_then(|cp| cp.stream())
                .and_then(|stream| {
                    JSReadableStream::payload_of(&JSValue::from(stream))
                        .and_then(|sp| sp.signal.get())
                });
            (JSValue::from(ctrl), maybe_signal)
        });
    let (controller, signal_opt) = match resolved {
        Some(v) => v,
        None => return Ok(true),
    };

    // Abort check before draining data: abort wins over a chunk.
    if let Some(s) = signal_opt
        && signal_is_aborted(&s)
    {
        let reason = signal_reason(&s).unwrap_or_else(|| {
            make_dom_exception(cx, "AbortError", "The operation was aborted.")
                .unwrap_or(JSValue::UNDEFINED)
        });
        let ef = controller.get_property_str(cx, "error")?;
        ef.call(cx, controller, &[reason])?;
        return Ok(false);
    }

    // Receive from the channel, releasing the state borrow before
    // any JS call below.
    let recv = WhatwgState::of(cx)
        .channel_streams
        .streams
        .get(&id)
        .map(|s| s.rx.try_recv());
    match recv {
        Some(Ok(Ok(data))) => {
            // Producer alive: refresh deadline, then enqueue.
            if let Some(s) = WhatwgState::of(cx).channel_streams.streams.get_mut(&id) {
                s.idle_deadline = Instant::now();
            }
            let ta = TypedArray::create_from_vec_u8(cx, data)
                .map_err(|_| cx.throw_internal_error("TypedArray creation failed"))?;
            let enqueue_fn = controller.get_property_str(cx, "enqueue")?;
            enqueue_fn.call(cx, controller, &[JSValue::from(ta)])?;
            Ok(true)
        }
        Some(Ok(Err(msg))) => {
            // Underlying network stream failed mid-body: error.
            let bytes = msg.into_bytes();
            let err = cx
                .create_error_object(ErrorKind::Type, &String::from_utf8_lossy(&bytes), false)
                .ok_or(-1)?;
            let error_fn = controller.get_property_str(cx, "error")?;
            error_fn.call(cx, controller, &[err.into()])?;
            Ok(false)
        }
        Some(Err(TryRecvError::Disconnected)) => {
            let close_fn = controller.get_property_str(cx, "close")?;
            close_fn.call(cx, controller, &[])?;
            Ok(false)
        }
        Some(Err(TryRecvError::Empty)) => {
            let expired = WhatwgState::of(cx)
                .channel_streams
                .streams
                .get(&id)
                .map(|s| s.idle_deadline.elapsed() > STREAM_IDLE_TIMEOUT)
                .unwrap_or(true);
            if expired {
                let err = cx
                    .create_string_from_utf8(b"channel stream timeout".to_vec())
                    .map(JSValue::make_string)
                    .map_err(|_| -1)?;
                let error_fn = controller.get_property_str(cx, "error")?;
                error_fn.call(cx, controller, &[err])?;
                Ok(false)
            } else {
                Ok(true)
            }
        }
        None => Ok(true),
    }
}

fn start_channel_stream_poller(ctx: &mut ScopedContext) {
    ctx.queue_job(
        move |cx| {
            // Snapshot ids first, then access one stream at a time so the state
            // borrow is never held across a JS call (which can trigger GC; the
            // engine traces the whole state).
            let ids: Vec<u64> = WhatwgState::of(cx)
                .channel_streams
                .streams
                .keys()
                .copied()
                .collect();
            let mut to_remove = Vec::new();

            for id in ids {
                match pump_channel_stream(cx, id) {
                    Ok(true) => {}
                    Ok(false) => to_remove.push(id),
                    Err(_) => {
                        // One stream broke — typically `enqueue` into a stream the
                        // consumer already cancelled. Drop just that stream (its
                        // producer's next `send` then fails, so the task stops)
                        // and keep pumping the others.
                        //
                        // The job must never return `Err`: the tick loop drops a
                        // failing job for good, and this pump is the only thing
                        // feeding channel-backed bodies, so losing it would stall
                        // every later body read for the rest of the process.
                        if let Exception::Error(e) = cx.take_exception() {
                            log::debug!("[channel stream] pump dropped stream {id}: {e:?}");
                        }
                        to_remove.push(id);
                    }
                }
            }

            if !to_remove.is_empty() {
                let st = WhatwgState::of(cx);
                for id in &to_remove {
                    st.channel_streams.streams.remove(id);
                }
            }

            if WhatwgState::of(cx).channel_streams.streams.is_empty() {
                // Nothing left to pump: let the next `from_channel` start a new
                // pump by clearing the liveness flag.
                WhatwgState::of(cx).channel_streams.poller_running = false;
                Ok(JobState::Done)
            } else {
                Ok(JobState::Block)
            }
        },
        (),
    );
}

// ============================================================================
// Registration
// ============================================================================

/// `new ReadableStreamBYOBReader(stream)` — validates the stream is a byte
/// stream (WHATWG SetUpReadableStreamBYOBReader step 2), then acquires a BYOB
/// reader.
fn js_readable_stream_byob_reader_static(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let stream_val = cc.arg(0);
    let mut stream = JSReadableStream::try_from(stream_val)
        .map_err(|_| ctx.throw_type_error("stream must be a ReadableStream"))?;
    {
        let sp = stream
            .payload()
            .ok_or_else(|| ctx.throw_type_error("not a ReadableStream"))?;
        if !sp.is_byte_stream {
            return Err(ctx.throw_type_error(
                "ReadableStreamBYOBReader requires a ReadableStream with type \"bytes\"",
            ));
        }
    }
    let reader = stream.acquire_reader(ctx, true)?;
    Ok(JSValue::from(reader))
}

/// Register the static `ReadableStream.from()` method on the global constructor.
pub fn init_readable_stream_statics(
    ctx: &mut ScopedContext,
    global: &mut Object,
) -> Result<(), i32> {
    let from_fn = ctx.create_native_function(
        zuqe::Callback::Func(js_readable_stream_from_static),
        "from",
        1,
        0,
    )?;
    let ctor_val = global.get_property_str(ctx, "ReadableStream")?;
    if let Some(mut ctor) = ctor_val.as_object() {
        ctor.define_property_value_str(ctx, "from", from_fn.into(), zuqe::JS_PROP_C_W_E)?;
    }

    // Expose ReadableStreamBYOBReader as a proper constructor on the global object.
    let empty_proto = ctx.create_base_object()?;
    let byob_ctor = ctx.create_constructor(
        "ReadableStreamBYOBReader",
        js_readable_stream_byob_reader_static,
        1,
        empty_proto,
        0,
        false,
    )?;
    global.define_property_value_str(
        ctx,
        "ReadableStreamBYOBReader",
        JSValue::from(byob_ctor),
        zuqe::JS_PROP_C_W_E,
    )?;

    // Set up prototype chain: ReadableStreamBYOBReader.prototype
    // inherits from ReadableStreamDefaultReader.prototype so that
    // BYOB readers get read()/cancel()/releaseLock()/closed.
    if let Ok(byob_proto) = byob_ctor.get_property_str(ctx, "prototype")
        && let Some(default_ctor) = global
            .get_property_str(ctx, "ReadableStreamDefaultReader")
            .ok()
        && let Some(default_proto) = default_ctor.get_property_str(ctx, "prototype").ok()
        && let Some(mut bp) = byob_proto.as_object()
    {
        let _ = bp.set_prototype(ctx, default_proto);
    }

    Ok(())
}

#[cfg(all(test, debug_assertions))]
mod gc_barrier_tests {
    use zuqe::{Context, Runtime, ScopedContext};

    /// The text-channel polling job outlives the stream it feeds. After the
    /// stream drops out of scope, the job's `TextStreamRoots` are the only
    /// reference to the controller it calls into — and, through the
    /// controller's `stream` back-pointer, to the stream itself.
    ///
    /// This pins the positive behavior (roots keep controller + stream alive
    /// across a collect, proven by `stream.payload()` and the job running to
    /// completion afterwards). Note the failure mode if the roots are lost:
    /// the stream + controller island is fully unreachable, so the minor
    /// frees it *cleanly* — no validator assert fires (it only sees edges a
    /// trace reports) and the later job call is a silent use-after-free, the
    /// exact hazard the roots exist to prevent.
    #[test]
    fn text_channel_job_keeps_its_controller_across_a_minor() -> Result<(), i32> {
        let mut rt = Runtime::create()?;
        let mut ctx: Context<'static> = rt.create_context(ScopedContext::ECMA_CONTEXT_SETUP)?;

        let (tx, rx) = ctx.with_root_scope(|cx| cx.make_local_channel::<Result<Vec<u8>, String>>());

        // Build the stream, then drop it: after this point nothing but the
        // queued polling job's trace roots references the controller.
        let stream =
            ctx.with_root_scope(|mut cx| super::JSReadableStream::from_text_channel(&mut cx, rx))?;

        let _ = rt.gc_minor_now();
        assert!(
            stream.payload().is_some(),
            "the stream must survive via the job-rooted controller's back-reference"
        );

        // Drive the poller to completion: one chunk, then disconnect. The job
        // calls into the controller; a stale handle would already have been
        // caught by the collect above.
        tx.send(Ok(b"hello".to_vec())).map_err(|_| -1)?;
        for _ in 0..4 {
            rt.tick();
        }
        drop(tx);
        for _ in 0..4 {
            rt.tick();
        }
        Ok(())
    }
}
