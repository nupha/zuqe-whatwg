// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WHATWG HTML §2.7 "Safe passing of structured data" — global `structuredClone`.
//!
//! `structuredClone(value, options?)` deep-clones a value per the structured
//! clone algorithm: primitives pass through, containers (Object/Array/Map/Set)
//! are copied recursively (cycles and duplicate references preserved via a
//! memory map), Date/RegExp/Error/ArrayBuffer/TypedArray/DataView and the
//! Boolean/Number/String wrappers are cloned. Symbols, functions, promises,
//! WeakMap/WeakSet and other exotic/native objects throw a `DataCloneError`
//! DOMException. `options.transfer` transfers (copies then detaches) the listed
//! `ArrayBuffer`s instead of cloning them.

use std::collections::{HashMap, HashSet};

use zuqe::{
    Array, CallContext, Callback, Exception, JS_CLASS_ARRAY, JS_CLASS_ARRAY_BUFFER,
    JS_CLASS_BOOLEAN, JS_CLASS_DATE, JS_CLASS_ERROR, JS_CLASS_MAP, JS_CLASS_NUMBER,
    JS_CLASS_OBJECT, JS_CLASS_REGEXP, JS_CLASS_SET, JS_CLASS_SHARED_ARRAY_BUFFER, JS_CLASS_STRING,
    JS_CLASS_WEAKMAP, JS_CLASS_WEAKSET, JS_GPN_ENUM_ONLY, JS_GPN_STR_OR_INT_MASK, JSResult,
    JSValue, Object, ScopedContext, builtins::array_buffer::ArrayBuffer,
};

use super::dom::make_dom_exception;

/// Throw a `DataCloneError` DOMException synchronously.
fn throw_data_clone(ctx: &mut ScopedContext, message: &str) -> i32 {
    match make_dom_exception(ctx, "DataCloneError", message) {
        Ok(v) => {
            ctx.throw(Exception::Error(v));
            -1
        }
        Err(code) => code,
    }
}

/// Fetch a global constructor (e.g. `Date`, `Map`) and return it as a callable.
fn global_ctor(ctx: &mut ScopedContext, name: &str) -> Result<Object, i32> {
    ctx.global_obj()
        .get_property_str(ctx, name)?
        .ensure_callable(ctx)
}

/// `structuredClone(value, options?)` — deep clone via the structured clone
/// algorithm (WHATWG HTML §2.7.10).
pub(super) fn js_structured_clone(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let value = cc.arg(0);

    // options — optional object; only `transfer` is defined.
    let mut transfer: HashSet<JSValue> = HashSet::new();
    if cc.length() > 1 && !cc.arg(1).is_undefined() {
        let Some(opts) = cc.arg(1).as_object() else {
            return Err(ctx.throw_type_error("options must be an object"));
        };
        let tr = opts.get_property_str(ctx, "transfer")?;
        if !tr.is_undefined() {
            let Some(arr) = tr.as_object_Array() else {
                return Err(ctx.throw_type_error("`transfer` must be an array"));
            };
            for v in arr.payload().values() {
                // Only a non-shared ArrayBuffer is transferable in aike.
                let is_buffer = v
                    .as_object_ArrayBuffer()
                    .is_some_and(|ab| ab.class_id() == JS_CLASS_ARRAY_BUFFER);
                if !is_buffer {
                    return Err(throw_data_clone(ctx, "A transferable could not be cloned."));
                }
                transfer.insert(*v);
            }
        }
    }

    let mut memory: HashMap<JSValue, JSValue> = HashMap::new();
    clone_value(ctx, value, &mut memory, &transfer)
}

/// Core recursive clone. `memory` maps a source object to its clone so cycles
/// and duplicate references resolve to the same target (spec §2.7.3 memory).
fn clone_value(
    ctx: &mut ScopedContext,
    value: JSValue,
    memory: &mut HashMap<JSValue, JSValue>,
    transfer: &HashSet<JSValue>,
) -> Result<JSValue, i32> {
    // Primitives (including BigInt) pass through; Symbols are not serializable.
    if !value.is_object() {
        if value.is_symbol() {
            return Err(throw_data_clone(ctx, "A Symbol cannot be cloned."));
        }
        return Ok(value);
    }

    // Already cloned (cycle or duplicate reference).
    if let Some(clone) = memory.get(&value) {
        return Ok(*clone);
    }

    let obj = value
        .as_object()
        .ok_or_else(|| ctx.throw_internal_error("not an object"))?;

    if let Some(ab) = value.as_object_ArrayBuffer() {
        let clone = clone_array_buffer(ctx, value, ab, transfer)?;
        memory.insert(value, clone);
        return Ok(clone);
    }
    if let Some(ta) = value.as_object_TypedArray() {
        return clone_typed_array(ctx, value, ta, memory, transfer);
    }
    if let Some(dv) = value.as_object_DataView() {
        return clone_data_view(ctx, value, dv, memory, transfer);
    }

    match obj.class_id() {
        JS_CLASS_ARRAY => clone_container(ctx, value, memory, transfer, true),
        JS_CLASS_MAP => clone_map(ctx, value, memory, transfer),
        JS_CLASS_SET => clone_set(ctx, value, memory, transfer),
        JS_CLASS_WEAKMAP | JS_CLASS_WEAKSET => {
            Err(throw_data_clone(ctx, "A WeakMap/WeakSet cannot be cloned."))
        }
        JS_CLASS_DATE => clone_date(ctx, value),
        JS_CLASS_REGEXP => clone_regexp(ctx, value),
        JS_CLASS_ERROR => clone_error(ctx, value),
        JS_CLASS_BOOLEAN => clone_wrapper(ctx, value, "Boolean"),
        JS_CLASS_NUMBER => clone_wrapper(ctx, value, "Number"),
        JS_CLASS_STRING => clone_wrapper(ctx, value, "String"),
        JS_CLASS_OBJECT => clone_container(ctx, value, memory, transfer, false),
        _ => Err(throw_data_clone(ctx, "This value is not cloneable.")),
    }
}

/// Clone an ArrayBuffer, or transfer it when listed in `transfer`.
fn clone_array_buffer(
    ctx: &mut ScopedContext,
    value: JSValue,
    ab: ArrayBuffer,
    transfer: &HashSet<JSValue>,
) -> Result<JSValue, i32> {
    if ab.class_id() == JS_CLASS_SHARED_ARRAY_BUFFER {
        return Err(throw_data_clone(
            ctx,
            "A SharedArrayBuffer cannot be cloned.",
        ));
    }

    let len = ab.payload().byte_length();
    let mut bytes = Vec::with_capacity(len);
    let mut ab_mut = ab;
    ab_mut.payload_mut().with_bytes_mut(|b| bytes = b.to_vec());

    let mut clone = ArrayBuffer::create(ctx, false, len)?;
    clone
        .payload_mut()
        .with_bytes_mut(|b| b.copy_from_slice(&bytes));

    // Transfer: the original is detached (data ownership moves to the clone).
    if transfer.contains(&value) {
        ab_mut.detatch(ctx);
    }

    Ok(clone.into())
}

/// Clone an ArrayBufferView (TypedArray or DataView): clone the backing buffer
/// (registered in `memory` by its own identity), then re-create the view.
fn clone_typed_array(
    ctx: &mut ScopedContext,
    value: JSValue,
    ta: zuqe::builtins::typed_array::TypedArray,
    memory: &mut HashMap<JSValue, JSValue>,
    transfer: &HashSet<JSValue>,
) -> Result<JSValue, i32> {
    let payload = ta.payload();
    let buffer = payload.array_buffer();
    // Read offset/count *before* cloning the buffer: a transferred buffer is
    // detached, which zeroes this view's length.
    let offset = value
        .get_property_str(ctx, "byteOffset")?
        .to_number(ctx)?
        .to_f64() as u32;
    let count = payload.count();
    let buffer_clone = clone_value(ctx, buffer.into(), memory, transfer)?;

    // Same element type via the global constructor, e.g. `new Uint8Array(buf, o, n)`.
    let ctor = {
        let o = value
            .as_object()
            .ok_or_else(|| ctx.throw_internal_error("not an object"))?;
        global_ctor(ctx, o.class_name_str())?
    };

    let clone = ctor.call_ctor(
        ctx,
        &[
            buffer_clone,
            JSValue::from(offset as i32),
            JSValue::from(count as i32),
        ],
    )?;
    memory.insert(value, clone);

    Ok(clone)
}

fn clone_data_view(
    ctx: &mut ScopedContext,
    value: JSValue,
    dv: zuqe::builtins::typed_array::DataView,
    memory: &mut HashMap<JSValue, JSValue>,
    transfer: &HashSet<JSValue>,
) -> Result<JSValue, i32> {
    let payload = dv.payload();
    let buffer = payload.array_buffer();
    let offset = value
        .get_property_str(ctx, "byteOffset")?
        .to_number(ctx)?
        .to_f64() as u32;
    let byte_length = payload.view_byte_length();
    let buffer_clone = clone_value(ctx, buffer.into(), memory, transfer)?;

    let ctor = global_ctor(ctx, "DataView")?;
    let clone = ctor.call_ctor(
        ctx,
        &[
            buffer_clone,
            JSValue::from(offset as i32),
            JSValue::from(byte_length as i32),
        ],
    )?;
    memory.insert(value, clone);
    Ok(clone)
}

/// Clone a Date via `new Date(timestamp)`.
fn clone_date(ctx: &mut ScopedContext, value: JSValue) -> Result<JSValue, i32> {
    let ts = value
        .as_object()
        .and_then(|p| {
            p.payload_datetime().map(|dt| {
                if dt.is_invalid() {
                    f64::NAN
                } else {
                    dt.timestamp() as f64
                }
            })
        })
        .ok_or_else(|| ctx.throw_internal_error("not a Date"))?;

    let ctor = global_ctor(ctx, "Date")?;
    ctor.call_ctor(ctx, &[JSValue::from(ts)])
}

/// Clone a RegExp via `new RegExp(source, flags)`, preserving `lastIndex`.
fn clone_regexp(ctx: &mut ScopedContext, value: JSValue) -> Result<JSValue, i32> {
    let source = value.get_property_str(ctx, "source")?;
    let flags = value.get_property_str(ctx, "flags")?;
    let last_index = value.get_property_str(ctx, "lastIndex")?;

    let ctor = global_ctor(ctx, "RegExp")?;
    let clone = ctor.call_ctor(ctx, &[source, flags])?;
    if !last_index.is_undefined_or_null() {
        clone
            .as_object()
            .ok_or_else(|| ctx.throw_internal_error("not a RegExp"))?
            .set_property_str(ctx, "lastIndex", last_index)?;
    }
    Ok(clone)
}

/// Clone an Error: name/message, with the prototype matching the name.
fn clone_error(ctx: &mut ScopedContext, value: JSValue) -> Result<JSValue, i32> {
    let name = value.get_property_str(ctx, "name")?.to_string(ctx)?;
    let name_str = name.content().encode_utf8(false).to_string();
    let msg = value.get_property_str(ctx, "message")?;
    let msg_str = if msg.is_undefined() {
        String::new()
    } else {
        msg.to_string(ctx)?.content().encode_utf8(false).to_string()
    };

    let clone = match name_str.as_str() {
        "EvalError" => ctx.create_error_object(zuqe::ErrorKind::Eval, &msg_str, false),
        "RangeError" => ctx.create_error_object(zuqe::ErrorKind::Range, &msg_str, false),
        "ReferenceError" => ctx.create_error_object(zuqe::ErrorKind::Reference, &msg_str, false),
        "SyntaxError" => ctx.create_error_object(zuqe::ErrorKind::Syntax, &msg_str, false),
        "TypeError" => ctx.create_error_object(zuqe::ErrorKind::Type, &msg_str, false),
        "URIError" => ctx.create_error_object(zuqe::ErrorKind::Uri, &msg_str, false),
        // Plain Error (or any other name → "Error" per spec).
        _ => {
            let msg_js = ctx.create_string_from_utf8(msg_str.as_bytes().to_vec())?;
            let ctor = global_ctor(ctx, "Error")?;
            return ctor.call_ctor(ctx, &[JSValue::make_string(msg_js)]);
        }
    };
    clone
        .map(JSValue::from)
        .ok_or_else(|| ctx.throw_internal_error("failed to clone error"))
}

/// Clone a Boolean/Number/String wrapper object via its constructor.
fn clone_wrapper(ctx: &mut ScopedContext, value: JSValue, ctor_name: &str) -> Result<JSValue, i32> {
    let arg = value.to_string_or_symbol(ctx)?;
    let ctor = global_ctor(ctx, ctor_name)?;
    ctor.call_ctor(ctx, &[arg])
}

/// Clone a Map, preserving entries (keys and values cloned recursively).
fn clone_map(
    ctx: &mut ScopedContext,
    value: JSValue,
    memory: &mut HashMap<JSValue, JSValue>,
    transfer: &HashSet<JSValue>,
) -> Result<JSValue, i32> {
    let entries: Vec<(JSValue, JSValue)> = value
        .as_object()
        .and_then(|o| {
            o.payload_mapset()
                .map(|s| s.iter().map(|e| (e.key(), e.value())).collect())
        })
        .unwrap_or_default();

    let ctor = global_ctor(ctx, "Map")?;
    let clone = ctor.call_ctor(ctx, &[])?;
    // Register before recursing so cycles resolve to this clone.
    memory.insert(value, clone);

    let clone_obj = clone
        .as_object()
        .ok_or_else(|| ctx.throw_internal_error("not a Map"))?;
    let set_fn = clone_obj.get_property_str(ctx, "set")?;
    for (k, v) in entries {
        let ck = clone_value(ctx, k, memory, transfer)?;
        let cv = clone_value(ctx, v, memory, transfer)?;
        set_fn.call(ctx, clone, &[ck, cv])?;
    }
    Ok(clone)
}

/// Clone a Set (each element cloned recursively).
fn clone_set(
    ctx: &mut ScopedContext,
    value: JSValue,
    memory: &mut HashMap<JSValue, JSValue>,
    transfer: &HashSet<JSValue>,
) -> Result<JSValue, i32> {
    let elements: Vec<JSValue> = value
        .as_object()
        .and_then(|o| {
            o.payload_mapset()
                .map(|s| s.iter().map(|e| e.key()).collect())
        })
        .unwrap_or_default();

    let ctor = global_ctor(ctx, "Set")?;
    let clone = ctor.call_ctor(ctx, &[])?;
    memory.insert(value, clone);

    let clone_obj = clone
        .as_object()
        .ok_or_else(|| ctx.throw_internal_error("not a Set"))?;
    let add_fn = clone_obj.get_property_str(ctx, "add")?;
    for e in elements {
        let ce = clone_value(ctx, e, memory, transfer)?;
        add_fn.call(ctx, clone, &[ce])?;
    }
    Ok(clone)
}

/// Clone an Array or a plain Object: own enumerable string-keyed properties are
/// copied onto a fresh container (cycles resolve via `memory`). For arrays the
/// `length` is preserved.
fn clone_container(
    ctx: &mut ScopedContext,
    value: JSValue,
    memory: &mut HashMap<JSValue, JSValue>,
    transfer: &HashSet<JSValue>,
    is_array: bool,
) -> Result<JSValue, i32> {
    let mut obj = value
        .as_object()
        .ok_or_else(|| ctx.throw_internal_error("not an object"))?;

    let clone: JSValue = if is_array {
        let mut arr = Array::create(ctx)?;
        let len = obj.get_length_prop(ctx)?.max(0) as u32;
        arr.set_length(ctx, len, true)?;
        arr.into()
    } else {
        ctx.create_base_object()?.into()
    };
    // Register before recursing so self-references resolve to this clone.
    memory.insert(value, clone);

    let clone_obj = clone
        .as_object()
        .ok_or_else(|| ctx.throw_internal_error("failed to create clone"))?;
    let keys = obj.get_own_property_names(ctx, JS_GPN_ENUM_ONLY | JS_GPN_STR_OR_INT_MASK)?;
    for pk in keys.iter() {
        let val = obj.get_property(ctx, pk.atom)?;
        let cloned = clone_value(ctx, val, memory, transfer)?;
        let key_js = pk.atom.to_value(ctx)?;
        let prop = key_js.to_atom(ctx)?;
        clone_obj.set_property(ctx, prop, cloned)?;
    }

    Ok(clone)
}

/// Install the global `structuredClone`.
pub(crate) fn init_structured_clone(
    ctx: &mut ScopedContext,
    mut global: Object,
) -> Result<(), i32> {
    let f =
        ctx.create_native_function(Callback::Func(js_structured_clone), "structuredClone", 2, 0)?;
    global.define_property_value_str(ctx, "structuredClone", f.into(), zuqe::JS_PROP_C_W_E)?;
    Ok(())
}
