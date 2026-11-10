//! Minimal runtime state shim for zuqe-whatwg (ported/adapted from aike).
//! Provides the `AikeRuntimeState` type expected by WHATWG modules.

use std::{collections::HashMap, time::Instant};

use zuqe::{
    JSValue, RuntimeUserState, ScopedContext,
    gc_lite::{GcTrace, GcTraceCtx},
};

pub struct AikeRuntimeState {
    /// `console.group` indentation level.
    pub(crate) console_group_indent: usize,
    /// `console.count(label)` counters.
    pub(crate) console_counters: HashMap<String, usize>,
    /// `console.time(label)` start instants.
    pub(crate) console_timers: HashMap<String, Instant>,

    /// Pending setTimeout/setInterval timers.
    pub(crate) timers: crate::timeout::TimerState,
    /// Auto-increment timer id counter.
    pub(crate) timer_serial: u32,

    /// Channel-backed readable streams being polled.
    pub(crate) channel_streams: crate::stream::ChannelStreamState,
    /// Active `ReadableStream.tee()` splits.
    pub(crate) tee_streams: crate::stream::TeeStreamState,

    /// In-flight fetch abort signals kept alive across GC.
    pub(crate) fetch_signals: HashMap<usize, JSValue>,
    /// Auto-increment id for `fetch_signals`.
    pub(crate) fetch_signal_next_id: usize,
    /// Whether `fetch()` skips TLS certificate validation.
    pub(crate) fetch_allow_insecure_tls: bool,
}

impl GcTrace for AikeRuntimeState {
    fn trace(&self, gcx: &mut GcTraceCtx) {
        self.timers.trace(gcx);
        self.channel_streams.trace(gcx);
        self.tee_streams.trace(gcx);
        for v in self.fetch_signals.values() {
            v.trace(gcx);
        }
    }
}

impl Default for AikeRuntimeState {
    fn default() -> Self {
        Self {
            console_group_indent: 0,
            console_counters: HashMap::new(),
            console_timers: HashMap::new(),
            timers: Default::default(),
            timer_serial: 1,
            channel_streams: crate::stream::ChannelStreamState::new(),
            tee_streams: crate::stream::TeeStreamState::new(),
            fetch_signals: HashMap::new(),
            fetch_signal_next_id: 1,
            fetch_allow_insecure_tls: false,
        }
    }
}

impl AikeRuntimeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn of<'a, 'c>(ctx: &'a mut ScopedContext<'c>) -> &'a mut Self {
        ctx.rt_mut().user_state_mut::<Self>()
    }
}

impl RuntimeUserState for AikeRuntimeState {}

/// Ensure the runtime state is installed (call when creating context/runtime if needed).
#[allow(dead_code)]
pub(crate) fn ensure_state(_ctx: &mut ScopedContext) {
    // state is accessed via user_state_mut which requires it to be installed on runtime;
    // wpt_runtime / host must install `AikeRuntimeState::new()` via Runtime::create_with or similar.
}
