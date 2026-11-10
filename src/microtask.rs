// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WHATWG HTML Standard §8.8 "Microtask queuing": global `queueMicrotask`.
//!
//! Per spec, `queueMicrotask(callback)` queues a microtask that invokes
//! `callback` with no arguments once the JavaScript execution stack is next
//! empty (before control returns to the event loop). A non-callable callback
//! throws a TypeError (Web IDL `VoidFunction` conversion); a callback that
//! throws is reported rather than propagated, and does not disturb the rest of
//! the microtask queue.

use zuqe::{CallContext, Callback, JSResult, JSValue, Object, ScopedContext};

/// `queueMicrotask(callback)` — queue a microtask to invoke `callback`.
///
/// Uses the engine's one-shot microtask queue (`queue_oneshot_job`); the
/// callback is passed as the job's GC trace node, so it stays alive while
/// pending with no `thread_local` state of its own.
fn js_queue_microtask(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let callback = cc.arg(0).ensure_callable(ctx)?;

    ctx.queue_oneshot_job(
        move |cx| {
            if callback.call(cx, JSValue::UNDEFINED, &[]).is_err() {
                let msg = cx.take_exception().to_text(cx);
                eprintln!("queueMicrotask callback error: {}", msg.message);
            }
            Ok(())
        },
        JSValue::from(callback), // GC-trace the callback while it sits in the microtask queue
    );

    Ok(JSValue::UNDEFINED)
}

pub(crate) fn init_microtask(ctx: &mut ScopedContext, mut global: Object) -> Result<(), i32> {
    let f =
        ctx.create_native_function(Callback::Func(js_queue_microtask), "queueMicrotask", 1, 0)?;
    global.define_property_value_str(ctx, "queueMicrotask", f.into(), zuqe::JS_PROP_C_W_E)?;

    Ok(())
}
