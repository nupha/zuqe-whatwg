// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! WHATWG DOM Standard — `DOMException` implementation.
//!
//! `DOMException` carries a `name`, `message` and legacy `code`. Fetch/abort
//! use it for `AbortError` (code 20) and `TimeoutError` (code 23), which WPT's
//! `promise_rejects_dom` / `assert_throws_dom` assert against via
//! `e.constructor === self.DOMException`, `e.name` and `e.code`.

use zuqe::{
    CallContext, ClassCtorDef, FieldDef, JSResult, JSValue, ScopedContext, def_native_object,
};

pub(crate) struct DOMExceptionPayload {
    name: String,
    message: String,
    code: i32,
}

zuqe::gc_lite::unsafe_empty_gc_trace!(DOMExceptionPayload);

/// Legacy `DOMException` error-name → code mapping (WebIDL DOMExceptionError).
fn dom_exception_code(name: &str) -> i32 {
    match name {
        "IndexSizeError" => 1,
        "HierarchyRequestError" => 3,
        "WrongDocumentError" => 4,
        "InvalidCharacterError" => 5,
        "NoModificationAllowedError" => 7,
        "NotFoundError" => 8,
        "NotSupportedError" => 9,
        "InUseAttributeError" => 10,
        "InvalidStateError" => 11,
        "SyntaxError" => 12,
        "InvalidModificationError" => 13,
        "NamespaceError" => 14,
        "InvalidAccessError" => 15,
        "TypeMismatchError" => 17,
        "SecurityError" => 18,
        "NetworkError" => 19,
        "AbortError" => 20,
        "URLMismatchError" => 21,
        "QuotaExceededError" => 22,
        "TimeoutError" => 23,
        "DataCloneError" => 25,
        "EncodingError" => 26,
        "NotReadableError" => 27,
        "UnknownError" => 28,
        "ConstraintError" => 29,
        "DataError" => 30,
        "TransactionInactiveError" => 31,
        _ => 0,
    }
}

fn js_dom_exception_constructor(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let new_target = cc.this();

    let message = if cc.length() > 0 {
        cc.arg(0)
            .to_string(ctx)?
            .content()
            .encode_utf8(false)
            .to_string()
    } else {
        String::new()
    };
    let name = if cc.length() > 1 {
        cc.arg(1)
            .to_string(ctx)?
            .content()
            .encode_utf8(false)
            .to_string()
    } else {
        String::from("Error")
    };

    let payload = DOMExceptionPayload {
        code: dom_exception_code(&name),
        message,
        name,
    };

    JSDOMException::new_instance(ctx, new_target, payload).map(JSValue::from)
}

fn js_dom_exception_name_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSDOMException::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("Illegal invocation: not a DOMException instance"))?;
    ctx.create_string_from_utf8(p.name.as_bytes().to_vec())
        .map(JSValue::make_string)
}

fn js_dom_exception_message_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSDOMException::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("Illegal invocation: not a DOMException instance"))?;
    ctx.create_string_from_utf8(p.message.as_bytes().to_vec())
        .map(JSValue::make_string)
}

fn js_dom_exception_code_getter(ctx: &mut ScopedContext, cc: CallContext) -> JSResult {
    let this = cc.this();
    let p = JSDOMException::payload_of(&this)
        .ok_or_else(|| ctx.throw_type_error("Illegal invocation: not a DOMException instance"))?;
    Ok(JSValue::from(p.code))
}

const CLASS_PROTO: &[FieldDef] = &[
    FieldDef::GETSET_ENUM("name", Some(js_dom_exception_name_getter), None, 0),
    FieldDef::GETSET_ENUM("message", Some(js_dom_exception_message_getter), None, 0),
    FieldDef::GETSET_ENUM("code", Some(js_dom_exception_code_getter), None, 0),
    FieldDef::STR(
        "[Symbol.toStringTag]",
        "DOMException",
        zuqe::JS_PROP_CONFIGURABLE,
    ),
];

def_native_object!(
    "DOMException",
    JSDOMException,
    DOMExceptionPayload,
    CLASS_PROTO,
    Some(ClassCtorDef::new(js_dom_exception_constructor, 2, true).expose_to_global())
);

/// Build a `DOMException` with the given error name and message.
///
/// Used by abort/fetch to produce a real `AbortError`/`TimeoutError` whose
/// `code`, `name` and `constructor` satisfy WPT's DOMException assertions.
pub fn make_dom_exception(ctx: &mut ScopedContext, name: &str, message: &str) -> JSResult {
    let payload = DOMExceptionPayload {
        code: dom_exception_code(name),
        message: message.to_string(),
        name: name.to_string(),
    };
    JSDOMException::new_instance(ctx, JSValue::UNDEFINED, payload).map(JSValue::from)
}
