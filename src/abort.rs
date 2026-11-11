// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WHATWG DOM Standard — AbortController and AbortSignal implementations.
//!
//! Provides `AbortController` and `AbortSignal` for cooperative cancellation
//! of asynchronous operations, following the WHATWG spec.

use std::{
    cell::RefCell,
    collections::VecDeque,
    rc::{Rc, Weak},
    sync::Arc,
};

use tokio::sync::Notify;
use zuqe::{
    CallContext, ClassCtorDef, Exception, FieldDef, GcBind, JSResult, JSValue, Object,
    ScopedContext, WriteBarrier, WriteBarrierVec, def_native_object,
    gc_lite::{GcTrace, GcTraceCtx},
};

use crate::dom::make_dom_exception;

// ===========================================================================
// Shared signal state (Rc<RefCell<>> so both Controller and Signal see updates)
// ===========================================================================

/// One registered listener: a local element type for `WriteBarrierVec` (the
/// tuple `(String, JSValue)` is foreign, so it cannot `impl GcBind`, E0117).
/// Only `cb` is a GC leaf.
struct AbortListener {
    type_name: String,
    cb: JSValue,
}

impl GcBind for AbortListener {
    fn bind_node(&self, ctx: &ScopedContext, owner: std::ptr::NonNull<zuqe::gc_lite::GcHead>) {
        GcBind::bind_node(&self.cb, ctx, owner)
    }
}

struct SignalInner {
    aborted: bool,
    reason: WriteBarrier<JSValue>,
    // The associated AbortController (for follow signal to find controller)
    controller: WriteBarrier<Option<Object>>,
    /// This signal's own JS object, used as the `abort` event's `target`.
    /// A back-ref inside the object graph is fine for mark-sweep GC (a
    /// self-loop never keeps an unreachable object alive).
    signal: WriteBarrier<Option<Object>>,
    /// Notifies waiters (e.g. an in-flight fetch) when this signal aborts.
    notify: Arc<Notify>,
    /// Whether this signal was created by `AbortSignal.any()` (a dependent).
    dependent: bool,
    /// Source signals a dependent flattens onto (spec: source signals).
    /// Weak refs: the source is kept alive by its owner, never by the
    /// dependent, so no Rc cycle is formed.
    sources: Vec<Weak<RefCell<SignalInner>>>,
    /// Dependent signals aborted together with this one (spec: dependent
    /// signals, also used for `Request`'s "follow" semantics). Strong refs:
    /// per spec a non-aborted dependent must not be GC'd while its sources
    /// are alive. Rc cycle is avoided because dependents only hold Weak refs
    /// back to their sources.
    dependents: Vec<Rc<RefCell<SignalInner>>>,
    /// Event listeners registered via `addEventListener` (EventTarget subset).
    /// Only the `abort` event type is meaningful for AbortSignal.
    listeners: WriteBarrierVec<AbortListener>,
}

// ===========================================================================
// AbortSignal
// ===========================================================================

pub(crate) struct AbortSignalPayload {
    inner: Rc<RefCell<SignalInner>>,
}

impl GcTrace for AbortSignalPayload {
    fn trace(&self, gcx: &mut GcTraceCtx) {
        // Custom trace: traverses `dependents` (strong Rc refs) with careful borrow
        // discipline (clone vec, drop borrow, then trace each dependent's GC fields)
        // so dependent signals/listeners/reasons stay alive per spec while avoiding
        // borrow conflicts; not expressible as a plain field-wise derive.
        let inner = self.inner.borrow();
        inner.reason.trace(gcx);
        inner.signal.trace(gcx);
        inner.controller.trace(gcx);
        for l in inner.listeners.iter() {
            l.cb.trace(gcx);
        }

        // Dependents are held by strong Rc refs but their JS payloads
        // (signal object/reason/listeners) still need tracing; per spec a
        // non-aborted dependent must not be GC'd while its source is alive.
        // The dependent's `signal` (its own JS object) is traced so the
        // `abort` event's `target` can never dangle.
        let dependents = inner.dependents.clone();
        drop(inner);

        for dep in dependents {
            let d = dep.borrow();
            d.signal.trace(gcx);
            d.reason.trace(gcx);
            d.controller.trace(gcx);
            for l in d.listeners.iter() {
                l.cb.trace(gcx);
            }
        }
    }
}

fn get_signal<'a>(
    ctx: &mut ScopedContext,
    val: &'a JSValue,
) -> Result<&'a AbortSignalPayload, i32> {
    JSAbortSignal::payload_of(val)
        .ok_or_else(|| ctx.throw_internal_error("not an AbortSignal instance"))
}

fn js_signal_constructor(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    // Per spec: AbortSignal constructor is not directly callable from JS.
    // Users obtain signals via AbortController.signal or static methods.
    Err(ctx.throw_type_error(
        "Illegal constructor: use AbortController or AbortSignal.abort()/timeout()",
    ))
}

fn js_signal_aborted_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let signal = get_signal(ctx, &this)?;
    Ok(JSValue::from(signal.inner.borrow().aborted))
}

fn js_signal_reason_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let signal = get_signal(ctx, &this)?;
    let inner = signal.inner.borrow();
    if inner.aborted {
        Ok(inner.reason.get())
    } else {
        Ok(JSValue::UNDEFINED)
    }
}

fn js_signal_throw_if_aborted(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let signal = get_signal(ctx, &this)?;
    let inner = signal.inner.borrow();
    if inner.aborted {
        // Throw the signal's abort reason (per spec, e.g. a DOMException
        // "AbortError" or whatever reason was passed to abort()).
        let reason = inner.reason.get();
        ctx.throw(Exception::Error(reason));
        Err(-1)
    } else {
        Ok(JSValue::UNDEFINED)
    }
}

/// Fire all `abort` event listeners registered on `inner`. Callers must drop
/// any borrow of `inner` before calling this (the listener callbacks may
/// re-enter the signal).
fn fire_abort_events(ctx: &mut ScopedContext, inner: &Rc<RefCell<SignalInner>>) {
    let (listeners, target) = {
        let i = inner.borrow();
        let listeners: Vec<JSValue> = i
            .listeners
            .iter()
            // Both `addEventListener("abort")` and the `onabort` event handler
            // IDL attribute (whose event handler type is "abort") fire.
            .filter(|l| l.type_name == "abort" || l.type_name == "onabort")
            .map(|l| l.cb)
            .collect();
        (listeners, i.signal.get())
    };
    if listeners.is_empty() {
        return;
    }
    let mut event = match ctx.create_base_object() {
        Ok(e) => e,
        Err(_) => return,
    };
    let type_val = JSValue::make_string(ctx.create_string_from_utf8(b"abort".to_vec()).unwrap());
    let _ = event.set_property_str(ctx, "type", type_val);
    let _ = event.set_property_str(
        ctx,
        "target",
        target.map(|o| o.into()).unwrap_or(JSValue::UNDEFINED),
    );
    let _ = event.set_property_str(ctx, "bubbles", JSValue::from(false));
    let _ = event.set_property_str(ctx, "cancelable", JSValue::from(false));
    let _ = event.set_property_str(ctx, "isTrusted", JSValue::from(true));

    for cb in listeners {
        if cb.is_callable() && cb.call(ctx, JSValue::UNDEFINED, &[event.into()]).is_err() {
            let exc = ctx.take_exception();
            #[cfg(debug_assertions)]
            crate::helpers::print_exc(ctx, exc);
        }
    }
}

fn js_signal_add_event_listener(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let signal = get_signal(ctx, &this)?;
    if cc.length() < 1 {
        return Ok(JSValue::UNDEFINED);
    }

    let event = cc.arg(0);
    let type_name = event
        .to_string(ctx)?
        .content()
        .encode_utf8(false)
        .to_string();

    let cb = if cc.length() > 1 {
        cc.arg(1)
    } else {
        JSValue::UNDEFINED
    };
    if cb.is_callable() {
        // The guard's push records the barrier (signal may be old, cb young).
        signal
            .inner
            .borrow_mut()
            .listeners
            .push(ctx, this, AbortListener { type_name, cb });
    }
    Ok(JSValue::UNDEFINED)
}

fn js_signal_remove_event_listener(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let signal = get_signal(ctx, &this)?;
    if cc.length() < 2 {
        return Ok(JSValue::UNDEFINED);
    }

    let event = cc.arg(0);
    let type_name = event
        .to_string(ctx)?
        .content()
        .encode_utf8(false)
        .to_string();

    let cb = cc.arg(1);
    signal
        .inner
        .borrow_mut()
        .listeners
        .retain(|l| !(l.type_name == type_name && l.cb == cb));
    Ok(JSValue::UNDEFINED)
}

fn js_signal_dispatch_event(_: &mut ScopedContext, _: CallContext) -> JSResult {
    // AbortSignal only meaningfully dispatches `abort`; we don't support arbitrary
    // event dispatch here. Spec-compliant no-op for non-abort events.
    Ok(JSValue::TRUE)
}

fn js_signal_onabort_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let signal = get_signal(ctx, &this)?;
    let inner = signal.inner.borrow();
    for l in inner.listeners.iter() {
        if l.type_name == "onabort" {
            return Ok(l.cb);
        }
    }
    Ok(JSValue::UNDEFINED)
}

fn js_signal_onabort_setter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let signal = get_signal(ctx, &this)?;
    let cb = cc.arg(0);
    let mut inner = signal.inner.borrow_mut();
    inner.listeners.retain(|l| l.type_name != "onabort");
    if !cb.is_undefined_or_null() {
        // The guard's push records the barrier (signal may be old, cb young).
        inner.listeners.push(
            ctx,
            this,
            AbortListener {
                type_name: "onabort".to_string(),
                cb,
            },
        );
    }
    Ok(JSValue::UNDEFINED)
}

/// Create an `AbortSignal` JS object for `inner` and back-fill `inner.signal`
/// (used as the `abort` event's `target`).
fn new_signal(ctx: &mut ScopedContext, inner: Rc<RefCell<SignalInner>>) -> JSResult {
    let signal = JSAbortSignal::new_instance(
        ctx,
        JSValue::UNDEFINED,
        AbortSignalPayload {
            inner: inner.clone(),
        },
    )?;
    // The instance was just created and is still young, but the guard keeps the
    // edge structural (signal is the owner of its own back-ref).
    inner
        .borrow_mut()
        .signal
        .set(ctx, signal.into(), Some(signal.0));
    Ok(signal.into())
}

/// Static method: AbortSignal.abort(reason?)
fn js_signal_static_abort(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    // Spec: `AbortSignal.abort(reason = new DOMException('...', 'AbortError'))`.
    // An explicitly passed `undefined` still triggers the default.
    let reason = if cc.length() > 0 && !cc.arg(0).is_undefined() {
        cc.arg(0)
    } else {
        make_dom_exception(ctx, "AbortError", "The operation was aborted.")?
    };

    let inner = Rc::new(RefCell::new(SignalInner {
        aborted: true,
        reason: WriteBarrier::new(reason),
        controller: WriteBarrier::new(None),
        signal: WriteBarrier::new(None),
        notify: Arc::new(Notify::new()),
        dependent: false,
        sources: Vec::new(),
        dependents: Vec::new(),
        listeners: WriteBarrierVec::new(),
    }));
    inner.borrow().notify.notify_waiters();

    new_signal(ctx, inner)
}
///
/// Returns a non-aborted signal that aborts with a "TimeoutError"
/// DOMException after `milliseconds`. The signal is kept alive for the
/// duration by the timer callback's GC-traced binding data (spec: a strong
/// reference is required while the timeout is pending).
fn js_signal_static_timeout(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let ms = cc.arg(0).to_number(ctx)?.to_i32().max(0) as u64;

    let signal_val = make_default_signal(ctx)?;

    let fire_fn = ctx.create_native_function_with_data(
        zuqe::Callback::Func(js_signal_timeout_fire),
        "signal-timeout",
        0,
        0,
        Box::new([signal_val]),
    )?;
    crate::timeout::register_timer_once(ctx, fire_fn.into(), ms)?;

    Ok(signal_val)
}

/// Timer callback for `AbortSignal.timeout()`: aborts the bound signal with a
/// "TimeoutError" DOMException (spec: queue a task to signal abort).
fn js_signal_timeout_fire(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let signal_val = cc.data(0);
    let reason = make_dom_exception(ctx, "TimeoutError", "The operation timed out.")?;
    if let Some(p) = JSAbortSignal::payload_of(&signal_val) {
        do_signal_abort(ctx, &p.inner, signal_val, reason);
    }
    Ok(JSValue::UNDEFINED)
}

/// Static method: AbortSignal.any(signals)
///
/// Returns a new signal aborted with the same reason as soon as any of
/// `signals` aborts. Per the spec it is a "dependent" signal that flattens
/// onto the non-dependent source signals, so nesting (`any([any([s])])`)
/// keeps every dependency one hop deep and abort events fire in registration
/// order.
fn js_signal_static_any(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let signals_val = cc.arg(0);
    if !signals_val.is_object() {
        return Err(ctx.throw_type_error("`signals` must be a sequence of AbortSignal"));
    }
    let obj = signals_val.as_object().unwrap();
    let len = obj
        .get_property_str(ctx, "length")?
        .to_number(ctx)?
        .to_i32()
        .max(0) as u32;
    let mut signals: Vec<JSValue> = Vec::with_capacity(len as usize);
    for i in 0..len {
        signals.push(obj.get_property_u32(ctx, i)?);
    }

    // Spec: if any input is already aborted, adopt the first one's reason and
    // return immediately (the result is already aborted). The reason is found
    // before `result_inner` exists, so it can be stored through the guard's
    // initializing constructor (unborn instance, no edge to record yet).
    let mut first_aborted: Option<JSValue> = None;
    for s in &signals {
        let Some(p) = JSAbortSignal::payload_of(s) else {
            return Err(ctx.throw_type_error("`signals` must be a sequence of AbortSignal"));
        };
        if p.is_aborted() {
            first_aborted = Some(p.inner.borrow().reason.get());
            break;
        }
    }

    let aborted = first_aborted.is_some();
    let result_inner = Rc::new(RefCell::new(SignalInner {
        aborted,
        reason: WriteBarrier::new(first_aborted.unwrap_or(JSValue::UNDEFINED)),
        controller: WriteBarrier::new(None),
        signal: WriteBarrier::new(None),
        notify: Arc::new(Notify::new()),
        dependent: true,
        sources: Vec::new(),
        dependents: Vec::new(),
        listeners: WriteBarrierVec::new(),
    }));
    if aborted {
        result_inner.borrow().notify.notify_waiters();
        return new_signal(ctx, result_inner);
    }

    // Spec: flatten sources — a dependent's own sources are linked directly,
    // never the intermediate dependent.
    for s in &signals {
        let Some(p) = JSAbortSignal::payload_of(s) else {
            return Err(ctx.throw_type_error("`signals` must be a sequence of AbortSignal"));
        };
        let s_inner = p.inner.clone();
        let s_sources: Vec<Rc<RefCell<SignalInner>>> = {
            let si = s_inner.borrow();
            if si.dependent {
                si.sources.iter().filter_map(|w| w.upgrade()).collect()
            } else {
                vec![s_inner.clone()]
            }
        };
        for source in s_sources {
            result_inner
                .borrow_mut()
                .sources
                .push(Rc::downgrade(&source));
            let mut sr = source.borrow_mut();
            if !sr.dependents.iter().any(|d| Rc::ptr_eq(d, &result_inner)) {
                sr.dependents.push(result_inner.clone());
                // Adding a dependent extends this source's GC-traced reach
                // (gc_trace walks each dependent's fields). Mark old source dirty
                // for minor GC (remembered-set re-scan) so it re-traces dependents.
                if let Some(src_obj) = sr.signal.get() {
                    ctx.gc_set_minor_dirty_value(src_obj.into());
                }
            }
        }
    }

    new_signal(ctx, result_inner)
}

// ===========================================================================
// AbortController
// ===========================================================================

pub(crate) struct AbortControllerPayload {
    signal: Object,
    inner: Rc<RefCell<SignalInner>>,
}

impl GcTrace for AbortControllerPayload {
    fn trace(&self, gcx: &mut GcTraceCtx) {
        // Custom trace: traces only `signal` (the controller→signal GC edge). The
        // shared `inner` state is traced through `AbortSignalPayload`; deriving would
        // also trace `inner` (and requires `SignalInner` to be derivable), changing
        // semantics.
        //
        // Keep the associated signal alive: the controller→signal link is the
        // only GC-traceable edge into the shared signal state for a signal
        // referenced solely via `AbortController.signal`.
        self.signal.trace(gcx);
    }
}

fn get_controller<'a>(
    ctx: &mut ScopedContext,
    val: &'a JSValue,
) -> Result<&'a AbortControllerPayload, i32> {
    JSAbortController::payload_of(val)
        .ok_or_else(|| ctx.throw_internal_error("not an AbortController instance"))
}

fn js_controller_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let new_target = cc.this();

    let inner = Rc::new(RefCell::new(SignalInner {
        aborted: false,
        reason: WriteBarrier::new(JSValue::UNDEFINED),
        controller: WriteBarrier::new(None),
        signal: WriteBarrier::new(None),
        notify: Arc::new(Notify::new()),
        dependent: false,
        sources: Vec::new(),
        dependents: Vec::new(),
        listeners: WriteBarrierVec::new(),
    }));

    let signal = JSAbortSignal::new_instance(
        ctx,
        JSValue::UNDEFINED,
        AbortSignalPayload {
            inner: inner.clone(),
        },
    )?;
    inner
        .borrow_mut()
        .signal
        .set(ctx, signal.into(), Some(signal.0));

    let payload = AbortControllerPayload {
        signal: signal.0,
        inner: inner.clone(),
    };

    let controller = JSAbortController::new_instance(ctx, new_target, payload)?;

    // Link signal back to controller
    inner
        .borrow_mut()
        .controller
        .set(ctx, controller.into(), Some(controller.0));

    Ok(controller.into())
}

fn js_controller_signal_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let controller = get_controller(ctx, &this)?;
    Ok(controller.signal.into())
}

fn js_controller_abort(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let controller = get_controller(ctx, &this)?;

    // Spec: `AbortController.abort(reason = new DOMException('...', 'AbortError'))`.
    // An explicitly passed `undefined` still triggers the default.
    let reason = if cc.length() > 0 && !cc.arg(0).is_undefined() {
        cc.arg(0)
    } else {
        make_dom_exception(ctx, "AbortError", "The operation was aborted.")?
    };
    // The reason lands in the shared `SignalInner`, whose GC edges are traced
    // by the *signal* payload — the barrier owner must be the node that
    // directly reports the child (a remembered re-trace only walks the
    // master's direct children; the controller's own trace reports only the
    // signal object, which is already old).
    do_signal_abort(
        ctx,
        &controller.inner,
        JSValue::from(controller.signal),
        reason,
    );

    Ok(JSValue::UNDEFINED)
}

/// Spec "signal abort" on an `AbortSignal`'s shared state: mark it (and all
/// non-aborted dependents) as aborted with `reason`, then run the abort steps
/// — fire `abort` events for this signal first, then for each dependent in
/// registration order. Dependents are marked aborted *before* any event fires
/// so listeners observe a consistent aborted state.
/// Mark a signal (and all non-aborted dependents) as aborted with `reason`.
///
/// `owner` is the instance the abort was initiated on: `reason` may be young
/// while an owner's payload is already old, so the edge is recorded for the
/// generational GC on the object that actually owns/traces the field.
fn do_signal_abort(
    ctx: &mut ScopedContext,
    inner: &Rc<RefCell<SignalInner>>,
    owner: JSValue,
    reason: JSValue,
) {
    let dependents: Vec<Rc<RefCell<SignalInner>>> = {
        let mut i = inner.borrow_mut();
        if i.aborted {
            return;
        }
        i.aborted = true;
        // The guard slot records the barrier (owner may already be old).
        i.reason.set(ctx, owner, reason);
        i.notify.notify_waiters();
        i.dependents.clone()
    };
    // Mark all *non-aborted* dependents aborted first (spec step 3), walking
    // the whole dependent chain BFS so `Request`'s nested "follow" signals
    // (controller → request.signal → clone.signal) propagate too. `any()`
    // flattens its dependencies, so there the walk is a single hop and the
    // spec's registration-order event firing is preserved. A dependent already
    // aborted (e.g. reentrantly by another source) is left untouched and does
    // not get its event re-fired.
    let mut queue: VecDeque<Rc<RefCell<SignalInner>>> = dependents.into();
    let mut to_fire: Vec<Rc<RefCell<SignalInner>>> = Vec::new();
    while let Some(cur) = queue.pop_front() {
        let children = {
            let mut d = cur.borrow_mut();
            if d.aborted {
                continue;
            }
            d.aborted = true;
            // Record the barrier on the dependent signal's own JS object (the
            // GC node that traces this `reason` field), not the source owner.
            let dep_owner = d.signal.get().map(JSValue::from).unwrap_or(owner);
            d.reason.set(ctx, dep_owner, reason);
            d.notify.notify_waiters();
            d.dependents.clone()
        };
        to_fire.push(cur);
        queue.extend(children);
    }

    // Then run abort steps: source first, dependents in order (spec steps 4-6).
    fire_abort_events(ctx, inner);
    for dep in to_fire {
        fire_abort_events(ctx, &dep);
    }
}

// ===========================================================================
// Registration: AbortSignal
// ===========================================================================

const CLASS_SIGNAL_PROTO: &[FieldDef] = &[
    FieldDef::GETSET_ENUM("aborted", Some(js_signal_aborted_getter), None, 0),
    FieldDef::GETSET_ENUM("reason", Some(js_signal_reason_getter), None, 0),
    FieldDef::GETSET_ENUM(
        "onabort",
        Some(js_signal_onabort_getter),
        Some(js_signal_onabort_setter),
        0,
    ),
    FieldDef::FUNC_ENUM("throwIfAborted", 0, js_signal_throw_if_aborted, 0),
    // EventTarget subset (AbortSignal is an EventTarget per WHATWG).
    FieldDef::FUNC_ENUM("addEventListener", 0, js_signal_add_event_listener, 0),
    FieldDef::FUNC_ENUM("removeEventListener", 0, js_signal_remove_event_listener, 0),
    FieldDef::FUNC_ENUM("dispatchEvent", 0, js_signal_dispatch_event, 0),
    // WebIDL class string (`Object.prototype.toString` -> "[object AbortSignal]").
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "AbortSignal",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "AbortSignal",
    JSAbortSignal,
    AbortSignalPayload,
    CLASS_SIGNAL_PROTO,
    Some(ClassCtorDef::new(js_signal_constructor, 0, true).expose_to_global())
);

// ===========================================================================
// Registration: AbortController
// ===========================================================================

const CLASS_CONTROLLER_PROTO: &[FieldDef] = &[
    FieldDef::GETSET_ENUM("signal", Some(js_controller_signal_getter), None, 0),
    FieldDef::FUNC_ENUM("abort", 1, js_controller_abort, 0),
    // WebIDL class string (`Object.prototype.toString` -> "[object AbortController]").
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "AbortController",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "AbortController",
    JSAbortController,
    AbortControllerPayload,
    CLASS_CONTROLLER_PROTO,
    Some(ClassCtorDef::new(js_controller_constructor, 0, true).expose_to_global())
);

impl AbortSignalPayload {
    pub(crate) fn is_aborted(&self) -> bool {
        self.inner.borrow().aborted
    }

    pub(crate) fn notify(&self) -> Arc<Notify> {
        self.inner.borrow().notify.clone()
    }
}

/// Get the abort `Notify` for a JS `AbortSignal` value, if it is one.
pub fn signal_notify(val: &JSValue) -> Option<Arc<Notify>> {
    JSAbortSignal::payload_of(val).map(|p| p.notify())
}

/// Whether a value is a genuine `AbortSignal` instance.
pub fn is_abort_signal(val: &JSValue) -> bool {
    JSAbortSignal::payload_of(val).is_some()
}

/// Whether a JS `AbortSignal` value is already aborted.
pub fn signal_is_aborted(val: &JSValue) -> bool {
    JSAbortSignal::payload_of(val)
        .map(|p| p.is_aborted())
        .unwrap_or(false)
}

/// The abort reason of a JS `AbortSignal` value, if it is aborted.
///
/// Per the Fetch spec, a fetch cancelled by a signal must reject with the
/// signal's `reason` (e.g. a DOMException "AbortError" or whatever was passed
/// to `abort()`), not a freshly-constructed error.
pub fn signal_reason(val: &JSValue) -> Option<JSValue> {
    let p = JSAbortSignal::payload_of(val)?;
    if p.is_aborted() {
        Some(p.inner.borrow().reason.get())
    } else {
        None
    }
}

/// Make `child` a "follower" of `parent`: when `parent` aborts, `child` aborts
/// with the same reason. If `parent` is already aborted, `child` is aborted
/// immediately. Used by `Request` to implement WHATWG "follow" signal semantics
/// (`request.signal` is never the same object as the signal passed to it).
pub(crate) fn signal_attach_follower(ctx: &mut ScopedContext, parent: &JSValue, child: &JSValue) {
    let Some(parent_p) = JSAbortSignal::payload_of(parent) else {
        return;
    };
    let Some(child_p) = JSAbortSignal::payload_of(child) else {
        return;
    };
    let parent_inner = parent_p.inner.clone();
    let child_inner = child_p.inner.clone();
    if parent_inner.borrow().aborted {
        // Already aborted: mirror the state onto the child right now.
        let reason = parent_inner.borrow().reason.get();
        do_signal_abort(ctx, &child_inner, *child, reason);
    } else {
        let mut pi = parent_inner.borrow_mut();
        pi.dependents.push(child_inner);
        // Adding a dependent extends the parent's GC-traced reach (gc_trace
        // walks each dependent's fields). Mark old parent dirty for minor GC
        // (remembered-set re-scan) so it re-traces dependents.
        if let Some(parent_obj) = pi.signal.get() {
            ctx.gc_set_minor_dirty_value(parent_obj.into());
        }
    }
}

/// Mark a (non-aborted) `AbortSignal` value as aborted with `reason`:
/// set `aborted`/`reason`, notify waiters, and fire `abort` event listeners.
/// Used by `WritableStream`/`WritableStreamDefaultWriter` `abort()` to
/// synchronously signal the controller's `signal` per the Streams spec.
///
/// Per the DOM spec's `AbortController.abort()`, when no reason is given
/// the default is `new DOMException("The operation was aborted.",
/// "AbortError")`.
pub(crate) fn abort_signal(
    ctx: &mut ScopedContext,
    signal_val: JSValue,
    reason: JSValue,
) -> Result<(), i32> {
    if let Some(payload) = JSAbortSignal::payload_of(&signal_val) {
        // Per DOM AbortController.abort(): if reason is not given, create
        // a default DOMException.
        let reason = if reason.is_undefined() || reason.is_null() {
            make_dom_exception(ctx, "AbortError", "The operation was aborted.")?
        } else {
            reason
        };
        do_signal_abort(ctx, &payload.inner, signal_val, reason);
    }
    Ok(())
}

/// Create a fresh, non-aborted `AbortSignal` value. Used as the default
/// `request.signal` when none is supplied to `Request`.
pub(crate) fn make_default_signal(ctx: &mut ScopedContext) -> JSResult {
    let inner = Rc::new(RefCell::new(SignalInner {
        aborted: false,
        reason: WriteBarrier::new(JSValue::UNDEFINED),
        controller: WriteBarrier::new(None),
        signal: WriteBarrier::new(None),
        notify: Arc::new(Notify::new()),
        dependent: false,
        sources: Vec::new(),
        dependents: Vec::new(),
        listeners: WriteBarrierVec::new(),
    }));
    new_signal(ctx, inner)
}

pub fn init_abort_signal_statics(ctx: &mut ScopedContext, global: &mut Object) -> Result<(), i32> {
    // Register AbortSignal.abort() static method
    let abort_fn =
        ctx.create_native_function(zuqe::Callback::Func(js_signal_static_abort), "abort", 1, 0)?;

    // Get the AbortSignal constructor from global
    let ctor_val = global.get_property_str(ctx, "AbortSignal")?;
    if let Some(mut ctor) = ctor_val.as_object() {
        ctor.define_property_value_str(ctx, "abort", abort_fn.into(), zuqe::JS_PROP_C_W_E)?;
    }

    // Register AbortSignal.timeout() static method
    let timeout_fn = ctx.create_native_function(
        zuqe::Callback::Func(js_signal_static_timeout),
        "timeout",
        1,
        0,
    )?;

    let ctor_val = global.get_property_str(ctx, "AbortSignal")?;
    if let Some(mut ctor) = ctor_val.as_object() {
        ctor.define_property_value_str(ctx, "timeout", timeout_fn.into(), zuqe::JS_PROP_C_W_E)?;
    }

    // Register AbortSignal.any() static method
    let any_fn =
        ctx.create_native_function(zuqe::Callback::Func(js_signal_static_any), "any", 1, 0)?;

    let ctor_val = global.get_property_str(ctx, "AbortSignal")?;
    if let Some(mut ctor) = ctor_val.as_object() {
        ctor.define_property_value_str(ctx, "any", any_fn.into(), zuqe::JS_PROP_C_W_E)?;
    }

    Ok(())
}
