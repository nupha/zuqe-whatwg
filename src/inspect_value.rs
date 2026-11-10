// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

use zuqe::{
    Atom, JS_GPN_ENUM_ONLY, JS_GPN_STR_OR_INT_MASK, JS_GPN_SYMBOL_MASK, JS_PROP_GETSET, JSValue,
    Object, ScopedContext,
};

/// Recursion depth before values collapse to `[Object]`/`[Array]` markers.
const MAX_DEPTH: usize = 2;
/// Max entries to expand for arrays/Map/Set.
const MAX_ARRAY_LENGTH: usize = 100;
/// String truncation limit.
const MAX_STRING_LENGTH: usize = 10000;

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn format_float(f: f64) -> String {
    if f.is_nan() {
        "NaN".to_string()
    } else if f.is_infinite() {
        (if f < 0.0 { "-Infinity" } else { "Infinity" }).to_string()
    } else if f == 0.0 && f.is_sign_negative() {
        "-0".to_string()
    } else {
        format!("{}", f)
    }
}

// ---- string escaping / quoting (Node style) ----

/// Choose the quote: single by default; switch to double if the string contains more single quotes (minimize escaping).
fn choose_quote(s: &str) -> char {
    let sq = s.chars().filter(|&c| c == '\'').count();
    let dq = s.chars().filter(|&c| c == '"').count();
    if sq > dq { '"' } else { '\'' }
}

fn escape_char(ch: char, q: char, out: &mut String) {
    match ch {
        '\\' => out.push_str("\\\\"),
        '\'' if ch == q => out.push_str("\\'"),
        '"' if ch == q => out.push_str("\\\""),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        '\u{08}' => out.push_str("\\b"),
        '\u{0c}' => out.push_str("\\f"),
        '\u{0b}' => out.push_str("\\v"),
        c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
            out.push_str(&format!("\\x{:02x}", c as u32));
        }
        c => out.push(c),
    }
}

fn quote_string(s: &str, budget: usize) -> String {
    let len = s.chars().count();
    let q = choose_quote(s);
    let mut out = String::new();
    out.push(q);
    let limit = if len <= budget { len } else { budget };

    for (shown, ch) in s.chars().enumerate() {
        if shown >= limit {
            break;
        }
        escape_char(ch, q, &mut out);
    }
    if len > budget {
        out.push_str(&format!("... {} more characters", len - budget));
    }
    out.push(q);
    out
}

fn get_str_opt(ctx: &mut ScopedContext, obj: &Object, key: &str) -> Option<String> {
    obj.get_property_str(ctx, key)
        .ok()
        .and_then(|v| v.as_string(false))
        .map(|s| s.encode_utf8(false).into_owned())
}

/// Lay out a group of entries as `open ... close` on a single line (compact default).
fn format_block(open: &str, entries: &[String], close: &str) -> String {
    format!("{}{}{}", open, entries.join(", "), close)
}

fn key_display(ctx: &mut ScopedContext, atom: &Atom) -> String {
    if let Some(i) = atom.to_small_int() {
        return format!("{i}");
    }

    if let Ok(kv) = atom.to_value(ctx)
        && kv.is_symbol()
    {
        let d = kv
            .as_symbol(false)
            .map(|x| x.encode_utf8(false).into_owned())
            .unwrap_or_default();
        return format!("Symbol({})", d);
    }
    ctx.clear_exception();

    let s = atom.to_utf8(ctx.rt()).to_string();
    quote_string(&s, MAX_STRING_LENGTH)
}

// ---- custom inspect hook ----

fn try_custom_inspect(
    ctx: &mut ScopedContext,
    val: JSValue,
    obj: &mut Object,
    level: usize,
) -> Option<String> {
    let syms = obj
        .get_own_property_names(ctx, JS_GPN_SYMBOL_MASK)
        .ok()?
        .to_vec();

    for pk in syms {
        let desc = obj.get_own_property(ctx, pk.atom).ok().flatten()?;
        if desc.flags & JS_PROP_GETSET != 0 {
            continue;
        }
        if !desc.value.is_callable() {
            continue;
        }
        let d = pk
            .atom
            .to_value(ctx)
            .ok()
            .and_then(|kv| kv.as_symbol(false))
            .map(|x| x.encode_utf8(false).into_owned())
            .unwrap_or_default();
        if d == "nodejs.util.inspect.custom" {
            let depth_arg = JSValue::from(MAX_DEPTH as i32);
            match desc.value.call(
                ctx,
                val,
                &[depth_arg, JSValue::UNDEFINED, JSValue::UNDEFINED],
            ) {
                Ok(r) => {
                    if r.is_string() {
                        return Some(
                            r.as_string(false)
                                .map(|s| s.encode_utf8(false).into_owned())
                                .unwrap_or_default(),
                        );
                    }
                    // custom method returned a non-string: re-format with default rules (fresh stack to avoid false circular detection)
                    let mut fresh = Vec::new();
                    return Some(inspect(ctx, r, level, &mut fresh));
                }
                Err(_) => {
                    ctx.clear_exception();
                    return None;
                }
            }
        }
    }
    None
}

// ---- accessor rendering (getters are never evaluated) ----

fn read_prop_value(
    ctx: &mut ScopedContext,
    obj: &mut Object,
    atom: Atom,
    level: usize,
    stack: &mut Vec<Object>,
) -> String {
    match obj.get_own_property(ctx, atom) {
        Ok(Some(desc)) if desc.flags & JS_PROP_GETSET != 0 => {
            let has_g = !desc.getter.is_undefined();
            let has_s = !desc.setter.is_undefined();
            if has_g && has_s {
                "[Getter/Setter]".to_string()
            } else if has_g {
                "[Getter]".to_string()
            } else {
                "[Setter]".to_string()
            }
        }
        Ok(Some(desc)) => inspect(ctx, desc.value, level + 1, stack),
        _ => {
            ctx.clear_exception();
            "?".to_string()
        }
    }
}

// ---- container formatting ----

fn format_object(
    ctx: &mut ScopedContext,
    obj: &mut Object,
    level: usize,
    stack: &mut Vec<Object>,
) -> String {
    let keys = match obj.get_own_property_names(
        ctx,
        JS_GPN_ENUM_ONLY | JS_GPN_STR_OR_INT_MASK | JS_GPN_SYMBOL_MASK,
    ) {
        Ok(k) => k.to_vec(),
        Err(_) => {
            ctx.clear_exception();
            Vec::new()
        }
    };

    let mut entries: Vec<String> = Vec::new();
    stack.push(*obj);
    for pk in keys {
        let key = key_display(ctx, &pk.atom);
        let value = read_prop_value(ctx, obj, pk.atom, level, stack);
        entries.push(format!("{}: {}", key, value));
    }
    stack.pop();

    format_block("{ ", &entries, " }")
}

/// Index entries shared by Array and TypedArray formatting: sparse runs
/// collapse to `<N empty items>`, capped at MAX_ARRAY_LENGTH with a tail note.
fn collect_index_entries(
    ctx: &mut ScopedContext,
    obj: &mut Object,
    len: usize,
    level: usize,
    stack: &mut Vec<Object>,
) -> Vec<String> {
    let mut entries: Vec<String> = Vec::new();
    let mut empty_run: usize = 0;
    let mut i = 0usize;
    let mut truncated = false;

    stack.push(*obj);
    while i < len {
        if entries.len() >= MAX_ARRAY_LENGTH {
            truncated = true;
            break;
        }
        let atom = Atom::from_small_int(i as u32);
        let has = obj.has_property(ctx, atom).unwrap_or(false);
        if has {
            if empty_run > 0 {
                entries.push(format!("<{} empty item{}>", empty_run, plural(empty_run)));
                empty_run = 0;
            }
            let v = obj.get_property(ctx, atom).unwrap_or(JSValue::UNDEFINED);
            entries.push(inspect(ctx, v, level + 1, stack));
        } else {
            empty_run += 1;
        }
        i += 1;
    }
    if empty_run > 0 {
        entries.push(format!("<{} empty item{}>", empty_run, plural(empty_run)));
    }
    if truncated {
        let more = len - i;
        if more > 0 {
            entries.push(format!("... {} more item{}", more, plural(more)));
        }
    }
    stack.pop();

    entries
}

fn format_array(
    ctx: &mut ScopedContext,
    obj: &mut Object,
    level: usize,
    stack: &mut Vec<Object>,
) -> String {
    let len = obj.get_length_prop(ctx).unwrap_or(0).max(0) as usize;
    let entries = collect_index_entries(ctx, obj, len, level, stack);
    format_block("[", &entries, "]")
}

fn format_typed_array(
    ctx: &mut ScopedContext,
    obj: &mut Object,
    level: usize,
    stack: &mut Vec<Object>,
) -> String {
    let count = obj.payload_typed_array().map_or(0, |ta| ta.count());
    let entries = collect_index_entries(ctx, obj, count, level, stack);
    let block = format_block("[", &entries, "]");
    format!("{}({})", obj.class_name_str(), block)
}

fn format_mapset(
    ctx: &mut ScopedContext,
    obj: &mut Object,
    level: usize,
    stack: &mut Vec<Object>,
) -> String {
    let cn = obj.class_name_str();
    let Some(ms) = obj.payload_mapset() else {
        return format!("{} {{}}", cn);
    };
    if ms.is_weak() {
        return format!("{} {{ <items unknown> }}", cn);
    }
    let is_set = cn == "Set";
    let mut entries: Vec<String> = Vec::new();
    stack.push(*obj);

    for e in ms.iter() {
        if is_set {
            // Set elements are stored in key() (value() is always undefined)
            entries.push(inspect(ctx, e.key(), level + 1, stack));
        } else {
            let k = inspect(ctx, e.key(), level + 1, stack);
            let v = inspect(ctx, e.value(), level + 1, stack);
            entries.push(format!("{} => {}", k, v));
        }
    }
    stack.pop();

    let mut head = String::new();
    head.push_str(cn);
    head.push('(');
    head.push_str(&ms.len().to_string());
    head.push_str(") {");
    format_block(&head, &entries, "}")
}

fn format_error(ctx: &mut ScopedContext, obj: &mut Object) -> String {
    // Node: inspect(Error) prints err.stack (of the form "Name: message\n    at ...").
    let name = get_str_opt(ctx, obj, "name")
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| obj.class_name_str().to_string());

    let msg = get_str_opt(ctx, obj, "message").unwrap_or_default();
    let mut s = if msg.is_empty() {
        name
    } else {
        format!("{}: {}", name, msg)
    };
    if let Some(stack) = get_str_opt(ctx, obj, "stack") {
        let stack = stack.trim_end();
        if !stack.is_empty() {
            s.push('\n');
            s.push_str(stack);
        }
    }
    s
}

fn inspect(ctx: &mut ScopedContext, val: JSValue, level: usize, stack: &mut Vec<Object>) -> String {
    if val.is_undefined() {
        return "undefined".to_string();
    }
    if val.is_null() {
        return "null".to_string();
    }
    if val.is_bool() {
        return val.as_bool().unwrap().to_string();
    }
    if val.is_int() {
        return val.as_int().unwrap().to_string();
    }
    if val.is_float64() {
        return format_float(val.as_float().unwrap());
    }
    if val.is_string() {
        let s = val
            .as_string(false)
            .map(|x| x.encode_utf8(false).into_owned())
            .unwrap_or_default();
        return quote_string(&s, MAX_STRING_LENGTH);
    }
    if val.is_symbol() {
        let d = val
            .as_symbol(false)
            .map(|x| x.encode_utf8(false).into_owned())
            .unwrap_or_default();
        return format!("Symbol({})", d);
    }
    if val.is_callable() {
        let name = val
            .as_bytecode()
            .map(|bc| bc.func_name(ctx.rt()))
            .or_else(|| val.as_object().and_then(|o| get_str_opt(ctx, &o, "name")));
        let label = match name {
            Some(n) if !n.is_empty() => format!("[Function: {}]", n),
            _ => "[Function (anonymous)]".to_string(),
        };
        return label;
    }
    if val.as_module().is_some() {
        return "[Module]".to_string();
    }

    let Some(mut obj) = val.as_object() else {
        return "[unknown]".to_string();
    };

    // circular reference
    if stack.contains(&obj) {
        return "[Circular]".to_string();
    }

    // depth collapse
    if level > MAX_DEPTH {
        return match obj.class_name_str() {
            "Object" => "[Object]".to_string(),
            "Array" => "[Array]".to_string(),
            _ => {
                format!("[{}]", obj.class_name_str())
            }
        };
    }
    // custom inspect hook
    if let Some(s) = try_custom_inspect(ctx, val, &mut obj, level) {
        return s;
    }

    // Proxy (engine does not directly expose target/handler)
    match obj.class_name_str() {
        "Proxy" => {
            return "[Proxy]".to_string();
        }
        "RegExp" if let Ok(s) = val.to_string(ctx) => {
            return s.encode_utf8(false).into_owned();
        }
        "Date" if let Ok(s) = val.to_string(ctx) => {
            return s.encode_utf8(false).into_owned();
        }
        "Error" => {
            return format_error(ctx, &mut obj);
        }
        n if n.ends_with("Error") => {
            return format_error(ctx, &mut obj);
        }
        _ => {
            // TypedArray
            if obj.payload_typed_array().is_some() {
                return format_typed_array(ctx, &mut obj, level, stack);
            }
            // Array
            if obj.payload_array().is_some() {
                return format_array(ctx, &mut obj, level, stack);
            }
            // Map / Set
            if obj.payload_mapset().is_some() {
                return format_mapset(ctx, &mut obj, level, stack);
            }
        }
    }

    // if cn == "Proxy" {
    //     return "[Proxy]".to_string();
    // }
    // // RegExp
    // if cn == "RegExp" {
    //     if let Ok(s) = val.to_string(ctx) {
    //         return s.encode_utf8(false).into_owned();
    //     }
    // }
    // // Date
    // if cn == "Date" {
    //     if let Ok(s) = val.to_string(ctx) {
    //         return s.encode_utf8(false).into_owned();
    //     }
    // }
    // // Error
    // if cn.ends_with("Error") || cn == "Error" {
    //     return format_error(ctx, &mut obj);
    // }

    // plain object
    format_object(ctx, &mut obj, level, stack)
}

/// Format an arbitrary JS value per Node `util.inspect` semantics (default options).
pub(crate) fn js_inspect(ctx: &mut ScopedContext, val: JSValue) -> String {
    let mut stack = Vec::new();
    inspect(ctx, val, 0, &mut stack)
}
