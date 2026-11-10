//! Helpers ported/adapted for zuqe-whatwg.
use zuqe::{Exception, ScopedContext};

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
            .to_string(&mut cx)
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
pub(crate) fn print_exc(_ctx: &mut ScopedContext, _exc: Exception) {}
