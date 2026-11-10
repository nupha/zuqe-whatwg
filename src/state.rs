// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! Per-runtime WHATWG state and host hooks, owned by the host runtime.
//!
//! The zuqe engine stores exactly one `RuntimeUserState` per runtime. Hosts
//! that already use their own state type embed [`WhatwgState`] as a field and
//! register [`install_state_accessor`] so the WHATWG modules can reach it from
//! a context without a second user-state slot. [`install_output_sink`] lets the
//! host route `console` output through its REPL/MCP-aware writer.

use std::{borrow::Cow, cell::Cell, collections::HashMap, sync::OnceLock, time::Instant};

use zuqe::{
    JSValue, ScopedContext,
    gc_lite::{GcTrace, GcTraceCtx},
};

/// WHATWG per-runtime state.
pub struct WhatwgState {
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

impl GcTrace for WhatwgState {
    fn trace(&self, gcx: &mut GcTraceCtx) {
        self.timers.trace(gcx);
        self.channel_streams.trace(gcx);
        self.tee_streams.trace(gcx);
        for v in self.fetch_signals.values() {
            v.trace(gcx);
        }
    }
}

impl Default for WhatwgState {
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

impl WhatwgState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow the host's WHATWG state for the current context.
    pub(crate) fn of<'a, 'c>(ctx: &'a mut ScopedContext<'c>) -> &'a mut Self {
        let accessor = STATE_ACCESSOR
            .with(|a| a.get())
            .expect("zuqe-whatwg: state accessor not installed; call install_state_accessor");
        accessor(ctx)
    }
}

/// Resolves the host's [`WhatwgState`] from the current context.
///
/// The accessor receives the context, so one registration per thread is enough
/// even when the thread hosts multiple runtimes (root and children).
pub type StateAccessor = for<'a, 'c> fn(&'a mut ScopedContext<'c>) -> &'a mut WhatwgState;

thread_local! {
    static STATE_ACCESSOR: Cell<Option<StateAccessor>> = const { Cell::new(None) };
}

/// Install the accessor used by every WHATWG module.
///
/// Call once per thread before creating runtimes; a host whose runtime state
/// embeds [`WhatwgState`] passes a function that returns that field.
pub fn install_state_accessor(accessor: StateAccessor) {
    STATE_ACCESSOR.with(|a| a.set(Some(accessor)));
}

/// Host-provided console output writer.
pub type OutputSink = for<'a> fn(Cow<'a, str>);

static OUTPUT_SINK: OnceLock<OutputSink> = OnceLock::new();

/// Route subsequent console output through `sink`.
///
/// Call once per process; later calls are ignored so two runtimes cannot
/// clobber each other's routing. Without a sink, output goes to stdout.
pub fn install_output_sink(sink: OutputSink) {
    let _ = OUTPUT_SINK.set(sink);
}

pub(crate) fn print_output(msg: Cow<'_, str>) {
    match OUTPUT_SINK.get() {
        Some(sink) => sink(msg),
        None => println!("{msg}"),
    }
}
