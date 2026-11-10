// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WHATWG Timers Standard: setTimeout, setInterval, clearTimeout, clearInterval.
//!
//! Timer state is **per-runtime**, stored on `WhatwgState`: each runtime's
//! pending timers live in its own list and are driven by a polling job queued in
//! that runtime's own context, so a child runtime's timer callbacks are always
//! invoked with the child's context. The list is kept sorted by `deadline`
//! ascending, so `entries[0]` is the nearest deadline; one self-requeuing JS
//! job per runtime fires due timers in that order.

use std::time::{Duration, Instant};

use zuqe::{
    CallContext, Callback, Exception, JS_PROP_C_W_E, JSResult, JSValue, JobState, Object,
    ScopedContext, gc_lite::GcTrace,
};

use crate::state::WhatwgState;

// ---------------------------------------------------------------------------
// Per-runtime timer entries
// ---------------------------------------------------------------------------

#[derive(GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
struct TimerEntry {
    /// Stable id returned to JS and used by clearTimeout/clearInterval. Never
    /// reused, so a stale clear can't hit a later timer that recycled the id.
    id: u32,
    /// JS function callback — must be GC-traced
    callback: Object,
    /// None for setTimeout; Some(ms) for setInterval
    interval_ms: Option<u64>,
    /// Absolute deadline captured at registration (and on every re-arm for
    /// intervals). The `entries` vec is kept sorted by this, so firing order is
    /// deterministic and `entries[0]` is always the nearest deadline.
    #[gc(skip)]
    deadline: Instant,
}

/// Per-runtime timer queue, stored on `WhatwgState`.
#[derive(Default, GcTrace)]
#[gc(crate_path = zuqe::gc_lite)]
pub(crate) struct TimerState {
    /// Pending timers, sorted by `deadline` ascending.
    entries: Vec<TimerEntry>,
    /// Whether a polling job is currently queued for this runtime.
    job_active: bool,
}

fn next_timer_id(ctx: &mut ScopedContext) -> u32 {
    let n = &mut WhatwgState::of(ctx).timer_serial;
    let id = *n;
    *n = id + 1;
    id
}

/// Insert an entry keeping the runtime's `entries` sorted by deadline.
fn insert_sorted(entries: &mut Vec<TimerEntry>, entry: TimerEntry) {
    let pos = entries.partition_point(|e| e.deadline <= entry.deadline);
    entries.insert(pos, entry);
}

// ---------------------------------------------------------------------------
// The self-requeuing polling job (one per active runtime)
// ---------------------------------------------------------------------------

/// Enqueue the polling job for `runtime_id` (caller has set `job_active`).
fn start_timer_task(ctx: &mut ScopedContext) {
    ctx.queue_job(
        move |cx| {
            let now = Instant::now();

            // Fast path: nearest deadline not due yet (or no timers) → bail.
            let nearest = WhatwgState::of(cx)
                .timers
                .entries
                .first()
                .map(|e| e.deadline);
            match nearest {
                None => {
                    WhatwgState::of(cx).timers.job_active = false;
                    return Ok(JobState::Done);
                }
                Some(t) if now < t => {
                    cx.set_poll_hint(t);
                    return Ok(JobState::Block);
                }
                Some(_) => {}
            }

            // At least one timer is due: fire every elapsed timer in order.
            loop {
                let step: Option<(Object, Option<u64>, u32)> = {
                    let s = &mut WhatwgState::of(cx).timers;
                    let Some(e) = s.entries.first_mut() else {
                        break;
                    };
                    if e.deadline > now {
                        break;
                    }
                    let cb = e.callback;
                    let id = e.id;
                    match e.interval_ms {
                        // One-shot: drop it before invoking (a clearTimeout
                        // inside the callback is then a no-op).
                        None => {
                            s.entries.remove(0);
                            Some((cb, None, id))
                        }
                        // Interval: keep the entry; re-arm after the callback.
                        Some(ms) => Some((cb, Some(ms), id)),
                    }
                };

                let (cb, interval_ms, id) = match step {
                    Some(x) => x,
                    None => break,
                };

                if cb.call(cx, JSValue::UNDEFINED, &[]).is_err() {
                    // Take the exception FIRST so cur_exception is cleared before
                    // any further JS runs (to_text).
                    let _exc = cx.take_exception();
                    #[cfg(debug_assertions)]
                    {
                        let msg = _exc.to_text(cx);
                        eprintln!("timer callback error: {}", msg.message);
                    }
                }

                if let Some(ms) = interval_ms {
                    let new_deadline = Instant::now() + Duration::from_millis(ms);
                    let s = &mut WhatwgState::of(cx).timers;
                    if let Some(pos) = s.entries.iter().position(|e| e.id == id) {
                        let mut e = s.entries.remove(pos);
                        e.deadline = new_deadline;
                        insert_sorted(&mut s.entries, e);
                    }
                }
            }

            // ES §9.5: a handler must not leave a pending exception behind.
            if let Exception::Error(_) = cx.take_exception() {
                // already reported above; just discard.
            }

            let next = WhatwgState::of(cx)
                .timers
                .entries
                .first()
                .map(|e| e.deadline);
            match next {
                Some(d) => {
                    if d > now {
                        cx.set_poll_hint(d);
                    }
                    Ok(JobState::Block)
                }
                None => {
                    WhatwgState::of(cx).timers.job_active = false;
                    Ok(JobState::Done)
                }
            }
        },
        (),
    );
}

// ---------------------------------------------------------------------------
// Register / clear
// ---------------------------------------------------------------------------

fn register_timer(ctx: &mut ScopedContext, cc: CallContext, is_interval: bool) -> JSResult {
    let callback = cc.arg(0).ensure_callable(ctx)?;
    let delay_ms = if cc.length() >= 2 {
        cc.arg(1).to_number(ctx)?.to_i32().max(0) as u64
    } else {
        0
    };

    let deadline = Instant::now() + Duration::from_millis(delay_ms);
    let id = next_timer_id(ctx);
    let need_start = {
        let s = &mut WhatwgState::of(ctx).timers;
        insert_sorted(
            &mut s.entries,
            TimerEntry {
                id,
                callback,
                interval_ms: if is_interval { Some(delay_ms) } else { None },
                deadline,
            },
        );
        let need = !s.job_active;
        s.job_active = true;
        need
    };

    if need_start {
        start_timer_task(ctx);
    }

    Ok(JSValue::from(id as i32))
}

fn clear_timer(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let id = cc.arg(0).to_number(ctx)?.to_i32();
    if id <= 0 {
        return Ok(JSValue::UNDEFINED);
    }
    let id = id as u32;

    let s = &mut WhatwgState::of(ctx).timers;
    if let Some(pos) = s.entries.iter().position(|e| e.id == id) {
        s.entries.remove(pos);
    }

    Ok(JSValue::UNDEFINED)
}

/// Register a one-shot timer that invokes the JS callable `callback` after
/// `ms` milliseconds, reusing the runtime timer queue. Used by
/// `AbortSignal.timeout()` and host helpers such as `Aike.sleep`.
pub fn register_timer_once(ctx: &mut ScopedContext, callback: JSValue, ms: u64) -> Result<(), i32> {
    let callback = callback.ensure_callable(ctx)?;
    let deadline = Instant::now() + Duration::from_millis(ms);
    let id = next_timer_id(ctx);
    let need_start = {
        let s = &mut WhatwgState::of(ctx).timers;
        insert_sorted(
            &mut s.entries,
            TimerEntry {
                id,
                callback,
                interval_ms: None,
                deadline,
            },
        );
        let need = !s.job_active;
        s.job_active = true;
        need
    };

    if need_start {
        start_timer_task(ctx);
    }

    Ok(())
}

const MAGIC_SET_TIMEOUT: i16 = 0;
const MAGIC_SET_INTERVAL: i16 = 1;
const MAGIC_CLEAR: i16 = 2; // clearTimeout and clearInterval share the same impl

fn js_timeout(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    match cc.magic() {
        m if m == MAGIC_SET_TIMEOUT as i32 => register_timer(ctx, cc, false),
        m if m == MAGIC_SET_INTERVAL as i32 => register_timer(ctx, cc, true),
        _ => clear_timer(ctx, cc), // MAGIC_CLEAR
    }
}

pub fn init_timeout(ctx: &mut ScopedContext, mut global: Object) -> Result<(), i32> {
    let f = ctx.create_native_function(
        Callback::Func(js_timeout),
        "setTimeout",
        2,
        MAGIC_SET_TIMEOUT,
    )?;
    global.define_property_value_str(ctx, "setTimeout", f.into(), JS_PROP_C_W_E)?;

    let f = ctx.create_native_function(
        Callback::Func(js_timeout),
        "setInterval",
        2,
        MAGIC_SET_INTERVAL,
    )?;
    global.define_property_value_str(ctx, "setInterval", f.into(), JS_PROP_C_W_E)?;

    let f =
        ctx.create_native_function(Callback::Func(js_timeout), "clearTimeout", 1, MAGIC_CLEAR)?;
    global.define_property_value_str(ctx, "clearTimeout", f.into(), JS_PROP_C_W_E)?;

    let f =
        ctx.create_native_function(Callback::Func(js_timeout), "clearInterval", 1, MAGIC_CLEAR)?;
    global.define_property_value_str(ctx, "clearInterval", f.into(), JS_PROP_C_W_E)?;

    Ok(())
}
