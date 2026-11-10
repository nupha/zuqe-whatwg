// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

use std::fmt::Display;

use zuqe::{Exception, ScopedContext};

#[derive(Clone, Copy)]
pub(crate) enum Color {
    CyanFg,
    GreenFg,
    YellowFg,
    RedFg,
    Reset,
}

fn ansi_code(c: Color) -> &'static str {
    match c {
        Color::CyanFg => "36",
        Color::GreenFg => "32",
        Color::YellowFg => "33",
        Color::RedFg => "31",
        Color::Reset => "39",
    }
}

/// Wrap text with ANSI color codes, returning a colored string.
pub(crate) fn colorize<T: Display>(text: T, color: Color) -> String {
    format!("\x1b[{}m{}\x1b[0m", ansi_code(color), text)
}

/// Print a taken exception's message (+ traceback).
#[cold]
#[cfg(debug_assertions)]
pub(crate) fn print_exc(ctx: &mut ScopedContext, exc: Exception) {
    if matches!(exc, Exception::No) {
        return;
    }
    let msg = ctx.with_new_scope(|cx| match exc {
        Exception::OutOfMemory => Ok::<_, i32>(Some("out of memory".to_string())),
        Exception::TooManyAtoms => Ok(Some("too many atoms".to_string())),
        Exception::Error(err) => Ok(err
            .to_string(cx)
            .map(|s| s.encode_utf8(false).into_owned())
            .ok()),
        _ => Ok(None),
    });
    match msg {
        Ok(Some(s)) => eprintln!("[cleared-exc] {s}"),
        _ => eprintln!("[cleared-exc] (exception)"),
    }
}
#[cold]
#[cfg(not(debug_assertions))]
pub(crate) const fn print_exc(_ctx: &mut ScopedContext, _exc: Exception) {}

/// Report an uncaught exception to the host: invoke the global `reportError`
/// when it is available (the WPT runner uses it to fire `error` events on the
/// global EventTarget), otherwise print it in debug builds.
#[cold]
pub(crate) fn report_exception(ctx: &mut ScopedContext, exc: Exception) {
    if matches!(exc, Exception::No) {
        return;
    }
    if let Exception::Error(err) = exc {
        let g = ctx.global_obj();
        let gv = zuqe::JSValue::from(g);
        if let Ok(f) = g.get_property_str(ctx, "reportError")
            && f.is_callable()
        {
            let _ = f.call(ctx, gv, &[err]);
            // Listener errors must not leak into the caller's exception state.
            let _ = ctx.take_exception();
            return;
        }
        let _ = ctx.take_exception();
        #[cfg(debug_assertions)]
        print_exc(ctx, Exception::Error(err));
        return;
    }
    #[cfg(debug_assertions)]
    print_exc(ctx, exc);
}
