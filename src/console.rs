// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

use std::time::Instant;

use zuqe::{CallContext, FieldDef, JSResult, JSValue, Object, ScopedContext};

use crate::{
    aike::AikeRuntimeState,
    color::{Color, colorize},
    inspect_value::js_inspect,
};

#[inline(always)]
fn console_println(msg: String) {
    crate::repl::print_output(msg.into());
}

/// Format a value for `console.log`/... output. Top-level strings are printed
/// raw (no quoting), matching Node's `console.log("hello") === hello`.
/// Other values fall back to inspect (which quotes nested strings).
fn console_format_arg(ctx: &mut ScopedContext, val: JSValue) -> String {
    if val.is_string() {
        val.as_string(false)
            .map(|s| s.encode_utf8(false).into_owned())
            .unwrap_or_default()
    } else {
        js_inspect(ctx, val)
    }
}

fn js_console_print(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let magic = cc.magic();
    let clr = || match magic {
        1 => Color::CyanFg,
        2 => Color::GreenFg,
        3 => Color::YellowFg,
        4 => Color::RedFg,
        _ => Color::Reset,
    };

    let mut out = String::new();
    let indent = AikeRuntimeState::of(ctx).console_group_indent;
    for _ in 0..indent {
        out.push_str(&colorize("  ", clr()));
    }

    for i in 0..cc.length() {
        if i > 0 {
            out.push_str(&colorize(" ", clr()));
        }
        let arg = cc.arg(i);
        out.push_str(&colorize(console_format_arg(ctx, arg), clr()));
    }

    if magic == 4 {
        // error
        eprintln!("{}", out);
    } else {
        console_println(out);
    }

    Ok(JSValue::UNDEFINED)
}

fn js_console_assert(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() == 0 || !cc.arg(0).to_bool()? {
        let mut out = String::new();
        let indent = AikeRuntimeState::of(ctx).console_group_indent;
        for _ in 0..indent {
            out.push_str(&colorize("  ", Color::RedFg));
        }

        out.push_str(&colorize("Assertion failed", Color::RedFg));
        for i in 1..cc.length() {
            out.push_str(&colorize(" ", Color::RedFg));
            out.push_str(&colorize(js_inspect(ctx, cc.arg(i)), Color::RedFg));
        }

        eprintln!("{}", out);
    }

    Ok(JSValue::UNDEFINED)
}

fn js_console_trace(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let indent = AikeRuntimeState::of(ctx).console_group_indent;
    let mut out = String::new();
    for _ in 0..indent {
        out.push_str(&colorize("  ", Color::Reset));
    }

    out.push_str(&colorize("Trace", Color::Reset));
    if cc.length() > 0 {
        out.push_str(&colorize(":", Color::Reset));
        for i in 0..cc.length() {
            out.push_str(&colorize(" ", Color::Reset));
            out.push_str(&colorize(js_inspect(ctx, cc.arg(i)), Color::Reset));
        }
    }
    console_println(out);

    // Append the current call stack. `backtrace()` walks the live frame chain
    // directly (no `Error` object, no eval through the `stack` getter).
    if let Some(stack) = ctx.backtrace() {
        for line in stack.lines() {
            let mut out = String::new();
            for _ in 0..indent {
                out.push_str(&colorize("  ", Color::Reset));
            }
            out.push_str(&colorize(line, Color::Reset));
            console_println(out);
        }
    }

    Ok(JSValue::UNDEFINED)
}

fn js_console_dir(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let indent = AikeRuntimeState::of(ctx).console_group_indent;
    let mut out = String::new();
    for _ in 0..indent {
        out.push_str(&colorize("  ", Color::Reset));
    }
    if cc.length() > 0 {
        out.push_str(&js_inspect(ctx, cc.arg(0)));
    }
    console_println(out);
    Ok(JSValue::UNDEFINED)
}

fn js_console_count(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let label = if cc.length() > 0 && !cc.arg(0).is_undefined() {
        cc.arg(0).to_string(ctx)?.to_string()
    } else {
        "default".to_string()
    };

    let count = {
        let n = AikeRuntimeState::of(ctx)
            .console_counters
            .entry(label.clone())
            .or_insert(0);
        *n += 1;
        *n
    };

    let mut out = String::new();
    let indent = AikeRuntimeState::of(ctx).console_group_indent;
    for _ in 0..indent {
        out.push_str(&colorize("  ", Color::Reset));
    }
    out.push_str(&colorize(format!("{label}: {count}"), Color::Reset));
    console_println(out);

    Ok(JSValue::UNDEFINED)
}

fn js_console_count_reset(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let label = if cc.length() > 0 && !cc.arg(0).is_undefined() {
        cc.arg(0).to_string(ctx)?.to_string()
    } else {
        "default".to_string()
    };

    AikeRuntimeState::of(ctx).console_counters.remove(&label);

    Ok(JSValue::UNDEFINED)
}

fn js_console_time(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let label = if cc.length() > 0 && !cc.arg(0).is_undefined() {
        cc.arg(0).to_string(ctx)?.to_string()
    } else {
        "default".to_string()
    };

    if AikeRuntimeState::of(ctx)
        .console_timers
        .contains_key(&label)
    {
        let mut out = String::new();
        let indent = AikeRuntimeState::of(ctx).console_group_indent;
        for _ in 0..indent {
            out.push_str(&colorize("  ", Color::YellowFg));
        }
        out.push_str(&colorize(
            format!("Timer '{label}' already exists"),
            Color::YellowFg,
        ));
        console_println(out);
    } else {
        AikeRuntimeState::of(ctx)
            .console_timers
            .insert(label, Instant::now());
    }

    Ok(JSValue::UNDEFINED)
}

fn js_console_time_log(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let label = if cc.length() > 0 && !cc.arg(0).is_undefined() {
        cc.arg(0).to_string(ctx)?.to_string()
    } else {
        "default".to_string()
    };

    let elapsed_ms = AikeRuntimeState::of(ctx)
        .console_timers
        .get(&label)
        .map(|start| start.elapsed().as_secs_f64() * 1000.0);

    let mut out = String::new();
    let indent = AikeRuntimeState::of(ctx).console_group_indent;
    for _ in 0..indent {
        out.push_str(&colorize("  ", Color::Reset));
    }

    match elapsed_ms {
        Some(ms) => {
            out.push_str(&colorize(format!("{label}: {ms:.1} ms"), Color::Reset));
            for i in 1..cc.length() {
                out.push_str(&colorize(" ", Color::Reset));
                out.push_str(&colorize(js_inspect(ctx, cc.arg(i)), Color::Reset));
            }
            console_println(out);
        }
        None => {
            out.push_str(&colorize(
                format!("Timer '{label}' does not exist"),
                Color::YellowFg,
            ));
            console_println(out);
        }
    }

    Ok(JSValue::UNDEFINED)
}

fn js_console_time_end(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let label = if cc.length() > 0 && !cc.arg(0).is_undefined() {
        cc.arg(0).to_string(ctx)?.to_string()
    } else {
        "default".to_string()
    };

    let elapsed = AikeRuntimeState::of(ctx)
        .console_timers
        .remove(&label)
        .map(|start| start.elapsed().as_secs_f64() * 1000.0);

    let mut out = String::new();
    let indent = AikeRuntimeState::of(ctx).console_group_indent;
    for _ in 0..indent {
        out.push_str(&colorize("  ", Color::Reset));
    }

    match elapsed {
        Some(ms) => {
            out.push_str(&colorize(format!("{label}: {ms:.1} ms"), Color::Reset));
            console_println(out);
        }
        None => {
            out.push_str(&colorize(
                format!("Timer '{label}' does not exist"),
                Color::YellowFg,
            ));
            console_println(out);
        }
    }

    Ok(JSValue::UNDEFINED)
}

fn js_console_group(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    AikeRuntimeState::of(ctx).console_group_indent += 1;
    Ok(JSValue::UNDEFINED)
}

fn js_console_group_end(ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    let indent = &mut AikeRuntimeState::of(ctx).console_group_indent;
    *indent = indent.saturating_sub(1);
    Ok(JSValue::UNDEFINED)
}

fn js_console_clear(_ctx: &mut ScopedContext, _cc: CallContext) -> JSResult {
    // ANSI clear screen + home cursor
    console_println(colorize("\x1b[2J\x1b[H", Color::Reset));
    Ok(JSValue::UNDEFINED)
}

fn js_console_table(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    if cc.length() == 0 {
        console_println(String::new());
        return Ok(JSValue::UNDEFINED);
    }

    let data = cc.arg(0);
    if data.is_undefined() {
        console_println("undefined".to_string());
        return Ok(JSValue::UNDEFINED);
    }
    if data.is_null() {
        console_println("null".to_string());
        return Ok(JSValue::UNDEFINED);
    }

    // Fallback: inspect-print the value
    console_println(js_inspect(ctx, data));
    Ok(JSValue::UNDEFINED)
}

/// Create and register the `console` object on globalThis.
pub(crate) fn init_console(ctx: &mut ScopedContext, global: &mut Object) -> Result<(), i32> {
    // `console` is a namespace object: its methods are own properties, and its
    // [[Prototype]] is an empty object whose own [[Prototype]] is %ObjectPrototype%.
    // WPT requires getPrototypeOf(console) to have no own properties.
    let proto = ctx.create_base_object()?;
    let mut console = ctx.create_base_object_with_proto(Some(proto))?;

    console.install_fields(
        ctx,
        &[
            FieldDef::FUNC_ENUM("log", 0, js_console_print, 0),
            FieldDef::FUNC_ENUM("debug", 0, js_console_print, 1),
            FieldDef::FUNC_ENUM("info", 0, js_console_print, 2),
            FieldDef::FUNC_ENUM("warn", 0, js_console_print, 3),
            FieldDef::FUNC_ENUM("error", 0, js_console_print, 4),
            FieldDef::FUNC_ENUM("assert", 0, js_console_assert, 0),
            FieldDef::FUNC_ENUM("trace", 0, js_console_trace, 0),
            FieldDef::FUNC_ENUM("dir", 0, js_console_dir, 0),
            FieldDef::FUNC_ENUM("dirxml", 0, js_console_dir, 0),
            FieldDef::FUNC_ENUM("count", 0, js_console_count, 0),
            FieldDef::FUNC_ENUM("countReset", 0, js_console_count_reset, 0),
            FieldDef::FUNC_ENUM("time", 0, js_console_time, 0),
            FieldDef::FUNC_ENUM("timeLog", 0, js_console_time_log, 0),
            FieldDef::FUNC_ENUM("timeEnd", 0, js_console_time_end, 0),
            FieldDef::FUNC_ENUM("group", 0, js_console_group, 0),
            FieldDef::FUNC_ENUM("groupCollapsed", 0, js_console_group, 0),
            FieldDef::FUNC_ENUM("groupEnd", 0, js_console_group_end, 0),
            FieldDef::FUNC_ENUM("clear", 0, js_console_clear, 0),
            FieldDef::FUNC_ENUM("table", 0, js_console_table, 0),
            FieldDef::STR(
                "[Symbol.toStringTag]",
                "console",
                zuqe::JS_PROP_CONFIGURABLE,
            ),
        ],
    )?;

    global.define_property_value_str(
        ctx,
        "console",
        console.into(),
        zuqe::JS_PROP_CONFIGURABLE | zuqe::JS_PROP_WRITABLE,
    )?;

    Ok(())
}
