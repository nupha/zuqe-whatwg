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

/// Print a colored line to stderr.
pub(crate) fn colorize_println<T: Display>(text: T, color: Color) {
    eprintln!("\x1b[{}m{}\x1b[0m", ansi_code(color), text);
}

/// Print a taken exception's message (+ traceback).
#[cold]
#[cfg(debug_assertions)]
pub(crate) fn print_exc(ctx: &mut ScopedContext, exc: Exception) {
    if matches!(exc, Exception::No) {
        return;
    }
    let msg = ctx.with_new_scope(|mut cx| match exc {
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
