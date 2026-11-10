// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

use std::fmt::Display;

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
