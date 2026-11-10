// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use crossbeam::channel::TryRecvError;
use zuqe::{
    Exception, JSResult, JSValue, JobState, ScopedContext,
    builtins::{
        array_buffer::ArrayBuffer,
        json::JSON,
        promise::{Promise, PromiseResultSlot},
        typed_array::TypedArray,
    },
};

use crate::{
    abort::signal_reason,
    blob::{blob_bytes_of, blob_from_bytes, blob_type_of},
    fetch::headers::HeaderList,
    form_data::{form_data_content_type, form_data_parse, form_data_to_bytes},
    stream::JSReadableStream,
    url::JSURLSearchParams,
};

/// Source of response body data.
pub(crate) enum BodySource {
    /// Streaming from a real network response — poll the channel.
    /// Each item is `Ok(bytes)` for a chunk or `Err(msg)` when the underlying
    /// network stream fails; the latter must reject the body reader, not be
    /// treated as a normal chunk (see `JSReadableStream::from_channel`).
    Channel(zuqe::WakeReceiver<Result<Vec<u8>, String>>),
    /// Entire body is already available as bytes (synthetic response).
    Synthetic(Vec<u8>),
    /// A JS `ReadableStream` body — drain by pumping its reader.
    Stream(JSReadableStream),
}

/// Convert a JS body argument (string or Uint8Array/TypedArray) into bytes.
/// A `ReadableStream` body is NOT handled here — it must be kept as a stream by
/// the caller, otherwise `to_string` would yield "[object ReadableStream]".
pub(crate) fn body_to_bytes(ctx: &mut ScopedContext, val: &JSValue) -> Result<Vec<u8>, i32> {
    if let Some(bytes) = blob_bytes_of(val) {
        return Ok(bytes.to_vec());
    }
    // A FormData body serializes to multipart/form-data; without this it would
    // stringify to "[object FormData]".
    if let Some(bytes) = form_data_to_bytes(val) {
        return Ok(bytes);
    }
    if let Ok(ta) = TypedArray::try_from(*val) {
        return Ok(ta.with_bytes(|b| b.to_vec()));
    }
    // DataView and ArrayBuffer are distinct classes from TypedArray — handle
    // them explicitly so they are serialized as their underlying bytes rather
    // than "[object DataView]" / "[object ArrayBuffer]".
    if let Some(dv) = val.as_object_DataView() {
        return Ok(dv.payload().with_bytes(|b| b.to_vec()));
    }
    if let Some(ab) = val.as_object_ArrayBuffer() {
        return Ok(ab.payload().with_bytes(|b| b.to_vec()));
    }
    let s = val.to_string(ctx)?;
    Ok(s.content().encode_utf8(false).as_bytes().to_vec())
}

/// WHATWG fetch "extract a body": the body's source determines a default
/// `Content-Type`. Buffer sources (ArrayBuffer / TypedArray / DataView) have
/// none, and a `Blob` contributes its own type only when non-empty.
///
/// Returns `None` when the source implies no default header.
pub(crate) fn body_content_type(val: &JSValue) -> Option<String> {
    if let Some(t) = blob_type_of(val) {
        return (!t.is_empty()).then_some(t);
    }

    if let Some(t) = form_data_content_type(val) {
        return Some(t);
    }

    if JSURLSearchParams::payload_of(val).is_some() {
        return Some("application/x-www-form-urlencoded;charset=UTF-8".into());
    }

    // Fetch spec "extract a body": any value that is not a BufferSource
    // (ArrayBuffer / TypedArray / DataView) nor a ReadableStream is encoded as a
    // string via its `toString`, and defaults to this Content-Type. This covers
    // string literals and objects exposing `toString` (e.g.
    // `{ toString: () => "hi!" }`). BufferSources and streams carry no default
    // Content-Type, so they fall through to `None` below.
    let is_buffer_source = val.as_object_DataView().is_some()
        || val.as_object_ArrayBuffer().is_some()
        || val.as_object_TypedArray().is_some()
        || JSReadableStream::payload_of(val).is_some();
    (!is_buffer_source).then(|| "text/plain;charset=UTF-8".into())
}

/// Whether a body-stream error is rustls's "peer closed connection without
/// sending TLS `close_notify`" (surfaced as `io::ErrorKind::UnexpectedEof`).
///
/// Rustls treats a missing `close_notify` as a hard EOF error and reqwest has no
/// knob to relax it, so *every* https response whose body is delimited by
/// connection close (no `Content-Length`, no chunking) fails to read. Treating
/// it as a clean end-of-body is safe rather than a truncation hole: a
/// length-framed body never needs EOF, so hyper reports a truncated one with a
/// different error ("connection closed before message completed") and this can
/// only fire for a body whose extent was "until close" to begin with.
pub(crate) fn is_tls_eof(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = src {
        if let Some(io) = e.downcast_ref::<std::io::Error>()
            && io.kind() == std::io::ErrorKind::UnexpectedEof
        {
            return true;
        }
        src = e.source();
    }
    false
}

/// Blob MIME type derived from a header list's current `Content-Type`: the
/// media type "essence" (type/subtype before any `;` parameter), trimmed and
/// lowercased. Absent `Content-Type` yields an empty string, per the Fetch
/// spec's "extract a MIME type" for blob bodies.
pub(crate) fn blob_type_from_header(list: &HeaderList) -> String {
    list.get("content-type")
        .map(|ct| {
            ct.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default()
}

pub(crate) const BODY_AS_BYTES: i32 = 0;
pub(crate) const BODY_AS_TEXT: i32 = 1;
pub(crate) const BODY_AS_JSON: i32 = 2;
/// Returns a `Blob` instance (type taken from `blob_type`).
pub(crate) const BODY_AS_BLOB: i32 = 4;
/// Returns a real `ArrayBuffer` (used by `Response.arrayBuffer()`; distinct
/// from `BODY_AS_BYTES`, which yields a `Uint8Array` view).
pub(crate) const BODY_AS_ARRAY_BUFFER: i32 = 5;
/// Returns a `FormData` parsed from the body. `blob_type` carries the full
/// `Content-Type` header (with parameters) so the multipart boundary and the
/// urlencoded variant can be told apart.
pub(crate) const BODY_AS_FORM_DATA: i32 = 6;

pub(crate) const BODY_TIMEOUT: Duration = Duration::from_secs(30);

/// Drain a body source into a `Promise` resolving to text/json/bytes.
/// `signal` is the owning request's `AbortSignal`: when it aborts mid-read the
/// promise rejects with the signal's reason (a `DOMException` `AbortError` by
/// default) rather than the raw transport error a cancellation produces.
pub(crate) fn drain_body(
    ctx: &mut ScopedContext,
    source: BodySource,
    mode: i32,
    blob_type: String,
    signal: Option<JSValue>,
) -> JSResult {
    let result_slot = PromiseResultSlot::<Result<Vec<u8>, String>>::new();
    // Carries a JS rejection value alongside the (Send-only) slot, so a stream
    // error can be rethrown as the original object rather than a copied string.
    let raw_err: Rc<RefCell<Option<JSValue>>> = Rc::new(RefCell::new(None));
    let convert_err = raw_err.clone();
    // Set when the failure came from the transport (a reset connection, a
    // content-decoding error, ...). Those are Fetch network errors and must
    // reject with a TypeError; only aike's own read timeout is an internal
    // error. A flag rather than a message match, so the two cannot be confused.
    let network_err = Rc::new(Cell::new(false));
    let network_err_slot = network_err.clone();
    let network_err_job = network_err.clone();
    let promise =
        Promise::create_with_result_slot(ctx, result_slot.clone(), move |cx, data| -> JSResult {
            let buf = data.map_err(|e| {
                // An abort cancels the transfer, which surfaces as a transport
                // error; the promise must reject with the signal's reason
                // instead (Fetch spec: "if aborted, reject with abort reason").
                if let Some(sig) = signal.as_ref()
                    && let Some(reason) = signal_reason(sig)
                {
                    cx.throw(Exception::Error(reason));
                    return -1;
                }
                match convert_err.borrow_mut().take() {
                    Some(v) => {
                        cx.throw(Exception::Error(v));
                        -1
                    }
                    None if network_err_slot.get() => cx.throw_type_error(&e),
                    None => cx.throw_internal_error(&e),
                }
            })?;
            match mode {
                BODY_AS_BYTES => TypedArray::create_from_vec_u8(cx, buf).map(JSValue::from),
                BODY_AS_ARRAY_BUFFER => ArrayBuffer::from_bytes(
                    cx,
                    JSValue::UNDEFINED,
                    buf.into_boxed_slice(),
                    std::ptr::null_mut(),
                )
                .map(JSValue::from),
                BODY_AS_TEXT => {
                    // WHATWG "UTF-8 decode" strips a single leading U+FEFF BOM
                    // (see decode branch of BODY_AS_JSON above). text() must
                    // match that, otherwise consumers see a stray BOM char.
                    let bytes = buf.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&buf);
                    let s = String::from_utf8_lossy(bytes);
                    cx.create_string_from_utf8(s.into_owned().into_bytes())
                        .map(JSValue::make_string)
                }
                BODY_AS_JSON => {
                    // WHATWG: JSON parse = UTF-8 decode the bytes, then run the
                    // JS JSON parse algorithm. That throws a `SyntaxError` on
                    // invalid input (e.g. UTF-16) and uses the engine's own
                    // duplicate-key / key-order semantics — so we must call the
                    // JS `JSON.parse`, not serde_json. "UTF-8 decode" also
                    // strips a leading BOM, which JSON.parse itself rejects.
                    let bytes = buf.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&buf);
                    let text = String::from_utf8_lossy(bytes);
                    JSON::parse(cx, &text)
                }
                BODY_AS_BLOB => blob_from_bytes(cx, buf.into(), blob_type),
                BODY_AS_FORM_DATA => {
                    // `blob_type` holds the raw Content-Type here, which
                    // selects the parse algorithm per the Fetch spec.
                    match form_data_parse(cx, &buf, &blob_type)? {
                        Some(v) => Ok(v),
                        None => Err(cx.throw_type_error("could not parse body as FormData")),
                    }
                }
                _ => unreachable!(),
            }
        })?;

    match source {
        BodySource::Synthetic(buf) => {
            // Entire body is already available — commit directly, no polling needed.
            let _ = result_slot.commit(Ok(buf));
            Ok(promise.into())
        }
        BodySource::Stream(stream) => {
            let mut s = stream;
            let reader = s.acquire_reader(ctx, false)?;
            reader.drain(ctx, result_slot, raw_err, BODY_TIMEOUT)?;
            Ok(promise.into())
        }
        BodySource::Channel(rx) => {
            let buf = Arc::new(Mutex::new(Some(Vec::new())));
            // Set once the body is committed (success, error, or timeout). The
            // commit happens from this polling job, which then must KEEP its
            // strong reference to `result_slot` alive until the result-slot
            // polling job (which holds only a `Weak`) has taken the data —
            // otherwise `weak.upgrade()` fails and panics on the very next
            // tick even though the data was committed.
            let committed = Arc::new(AtomicBool::new(false));
            let start = Instant::now();
            let network_err = network_err_job;
            ctx.queue_job(
                move |cx| {
                    if committed.load(Ordering::SeqCst) {
                        // Stay queued (holding the strong ref) until the
                        // result-slot job consumed the committed value.
                        return if result_slot.is_empty() {
                            Ok(JobState::Done)
                        } else {
                            Ok(JobState::Block)
                        };
                    }
                    let mut guard = buf.lock().unwrap_or_else(|e| e.into_inner());
                    let Some(inner) = guard.as_mut() else {
                        committed.store(true, Ordering::SeqCst);
                        return if result_slot.is_empty() {
                            Ok(JobState::Done)
                        } else {
                            Ok(JobState::Block)
                        };
                    };
                    let finish = |guard: &mut std::sync::MutexGuard<Option<Vec<u8>>>| {
                        guard.take();
                        committed.store(true, Ordering::SeqCst);
                    };

                    const BATCH: usize = 1024 * 1024;
                    let mut drained = 0usize;
                    loop {
                        match rx.try_recv() {
                            Ok(Ok(chunk)) => {
                                drained += chunk.len();
                                inner.extend_from_slice(&chunk);
                                if drained >= BATCH {
                                    // More data is still buffered in the channel but
                                    // the producer may already be gone (unbounded
                                    // channel holds it all), so no further wake is
                                    // coming — wake now or this `Again` parks forever.
                                    cx.wake_handle().wake();
                                    return Ok(JobState::Block);
                                }
                            }
                            // A network error mid-body: reject the buffered read.
                            Ok(Err(msg)) => {
                                finish(&mut guard);
                                network_err.set(true);
                                let _ = result_slot.commit(Err(msg));
                                return Ok(JobState::Block);
                            }
                            Err(TryRecvError::Disconnected) => {
                                let full = guard.take().unwrap_or_default();
                                committed.store(true, Ordering::SeqCst);
                                let _ = result_slot.commit(Ok(full));
                                cx.wake_handle().wake();
                                return Ok(JobState::Block);
                            }
                            Err(TryRecvError::Empty) => {
                                if start.elapsed() > BODY_TIMEOUT {
                                    finish(&mut guard);
                                    let _ = result_slot.commit(Err("body read timeout".into()));
                                }
                                return Ok(JobState::Block);
                            }
                        }
                    }
                },
                (),
            );
            Ok(promise.into())
        }
    }
}
