// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WHATWG standard API implementations for the zuqe runtime.

pub mod abort;
pub mod base64;
pub mod blob;
#[cfg(feature = "fetch_cache")]
pub(crate) mod cache_storage;
pub mod console;
#[cfg(feature = "fetch_cors_cookie")]
pub mod cookie_store;
pub mod crypto;
pub mod dom;
pub mod fetch;
pub mod form_data;
pub(crate) mod helpers;
pub(crate) mod inspect_value;
pub mod microtask;
mod state;
pub mod stream;
pub mod structured_clone;
pub mod text_decoder;
pub mod text_encoder;
pub mod timeout;
pub mod url;

pub use abort::{is_abort_signal, signal_is_aborted, signal_notify, signal_reason};
pub use crypto::get_buffer_source_bytes;
pub use dom::make_dom_exception;
pub use state::{
    OutputSink, StateAccessor, WhatwgState, install_output_sink, install_state_accessor,
};
pub use timeout::register_timer_once;
pub use url::{new_url, url_arg_to_str};

use zuqe::{NativeObject, Object, ScopedContext};

/// Install all WHATWG-standard global APIs.
pub fn init_whatwg(ctx: &mut ScopedContext, mut global: Object) -> Result<(), i32> {
    ctx.use_classes(&[
        abort::JSAbortController::class_id(),
        abort::JSAbortSignal::class_id(),
        dom::JSDOMException::class_id(),
        text_decoder::JSTextDecoder::class_id(),
        text_encoder::JSTextEncoder::class_id(),
        url::JSURL::class_id(),
        url::JSURLSearchParams::class_id(),
        stream::JSReadableStream::class_id(),
        stream::JSReadableStreamDefaultReader::class_id(),
        stream::JSReadableStreamDefaultController::class_id(),
        stream::JSReadableByteStreamController::class_id(),
        stream::JSReadableStreamBYOBRequest::class_id(),
        stream::JSWritableStream::class_id(),
        stream::JSWritableStreamDefaultWriter::class_id(),
        stream::JSWritableStreamDefaultController::class_id(),
        stream::JSTransformStream::class_id(),
        stream::JSTransformStreamDefaultController::class_id(),
        stream::JSByteLengthQueuingStrategy::class_id(),
        stream::JSCountQueuingStrategy::class_id(),
        blob::JSBlob::class_id(),
        form_data::JSFormData::class_id(),
        form_data::FormDataIterator::class_id(),
        crypto::JSCrypto::class_id(),
        crypto::JSCryptoSubtle::class_id(),
        crypto::JSCryptoKey::class_id(),
    ])?;
    #[cfg(feature = "fetch_cors_cookie")]
    ctx.use_classes(&[cookie_store::JSCookieStore::class_id()])?;

    console::init_console(ctx, &mut global)?;
    timeout::init_timeout(ctx, global)?;
    microtask::init_microtask(ctx, global)?;
    abort::init_abort_signal_statics(ctx, &mut global)?;
    stream::init_readable_stream_statics(ctx, &mut global)?;
    url::init_url(ctx, &mut global)?;
    fetch::init_fetch(ctx, global)?;
    base64::init_encoding(ctx, global)?;
    structured_clone::init_structured_clone(ctx, global)?;
    crypto::init_crypto(ctx, global)?;
    #[cfg(feature = "fetch_cors_cookie")]
    cookie_store::install_cookie_store(ctx, global)?;

    Ok(())
}
