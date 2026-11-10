//! Minimal REPL/output helpers ported for zuqe-whatwg console.
use std::borrow::Cow;

pub(crate) fn print_output(msg: Cow<'_, str>) {
    println!("{}", msg);
}
