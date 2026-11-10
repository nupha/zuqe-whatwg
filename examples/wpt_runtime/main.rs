// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 John Ray <996351336@qq.com>

//! Minimal JS runtime for zuqe-whatwg that can run WPT `*.any.js` testharness tests.
//!
//! Usage:
//!   wpt_runtime [--root <wpt-root>] [--testharness <path>] [--timeout-ms N] <file|dir>...
//!   wpt_runtime <script.js>

use std::{
    collections::HashSet,
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use futures_util::FutureExt;

use clap::Parser;
use zuqe::{
    Callback, EvalFlags, EvalName, EvalType, Exception, ExitStatus, JSValue, ModuleDef, Runtime,
    RuntimeUserState, ScopedContext,
    gc_lite::{GcTrace, GcTraceCtx},
};

/// Host runtime state for the example: owns the WHATWG per-runtime state.
struct WptState {
    whatwg: zuqe_whatwg::WhatwgState,
}

impl GcTrace for WptState {
    fn trace(&self, gcx: &mut GcTraceCtx) {
        self.whatwg.trace(gcx);
    }
}

impl RuntimeUserState for WptState {}

fn whatwg_state<'a, 'c>(ctx: &'a mut ScopedContext<'c>) -> &'a mut zuqe_whatwg::WhatwgState {
    &mut ctx.rt_mut().user_state_mut::<WptState>().whatwg
}

#[derive(Debug, Parser)]
#[command(about = "Minimal zuqe-whatwg runtime / WPT runner")]
struct Args {
    #[arg(long, env = "WPT_ROOT")]
    root: Option<PathBuf>,
    #[arg(long, env = "WPT_TESTHARNESS")]
    testharness: Option<PathBuf>,
    #[arg(long, default_value_t = 10000u64)]
    timeout_ms: u64,
    /// Base URL of the running wpt server, used to give each test its served
    /// document URL (relative fetch()/location resolve against it).
    #[arg(
        long,
        env = "WPT_SERVER_URL",
        default_value = "http://web-platform.test:8000"
    )]
    server: String,
    /// Enable GC stress (debug + gc_generations builds) to catch young/old GC issues.
    #[arg(long, default_value_t = false)]
    gc_stress: bool,
    #[arg(required = true)]
    inputs: Vec<PathBuf>,
}

fn is_wpt_test(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|n| n.ends_with(".any.js"))
}

fn collect_tests(inputs: &[PathBuf], root: Option<&Path>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for input in inputs {
        let p = if input.is_absolute() || input.exists() {
            input.clone()
        } else if let Some(r) = root {
            r.join(input)
        } else {
            input.clone()
        };
        if p.is_dir() {
            let mut stack = vec![p];
            while let Some(dir) = stack.pop() {
                let Ok(rd) = std::fs::read_dir(&dir) else {
                    continue;
                };
                let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
                entries.sort_by_key(|e| e.path());
                for e in entries.into_iter().rev() {
                    let ep = e.path();
                    if ep.is_dir() {
                        stack.push(ep);
                    } else if is_wpt_test(&ep) && !ep.to_string_lossy().contains("idlharness") {
                        out.push(ep);
                    }
                }
            }
        } else if p.is_file() {
            out.push(p);
        } else {
            eprintln!("wpt_runtime: not found: {}", p.display());
        }
    }
    out.sort();
    out
}

/// The URL a browser would load the test file from: the local path mapped
/// under the running wpt server. `.https.`/`.h2.` tests live on the TLS
/// server (port 8443 by default).
fn test_document_url(file: &Path, root: Option<&Path>, server: &str) -> url::Url {
    let rel = root
        .and_then(|r| file.strip_prefix(r).ok())
        .unwrap_or(file)
        .to_string_lossy()
        .replace('\\', "/");
    let rel = rel.trim_start_matches('/');
    let base = url::Url::parse(server)
        .unwrap_or_else(|_| url::Url::parse("http://web-platform.test:8000").unwrap());
    let mut u = base.join(rel).unwrap_or(base);
    if rel.contains(".h2.") {
        // WPT's HTTP/2 server listens on the h2 port (9000 by default).
        let _ = u.set_scheme("https");
        let _ = u.set_port(Some(9000));
    } else if rel.contains(".https.") {
        let _ = u.set_scheme("https");
        let _ = u.set_port(Some(8443));
    }
    u
}

fn escape_js_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// GET a served WPT file. Returns `None` on any failure so callers can fall
/// back to the local checkout.
async fn fetch_source(http: &reqwest::Client, url: &url::Url) -> Option<String> {
    let resp = http.get(url.as_str()).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.text().await.ok()
}

/// Expose `location` plus the `__wptClientUrl`/`__wptClientOrigin` fallbacks
/// that `fetch` uses for same-origin checks and the default referrer.
fn location_setup_script(doc_url: &url::Url) -> String {
    let href = escape_js_string(doc_url.as_str());
    let origin = escape_js_string(&doc_url.origin().ascii_serialization());
    let protocol = format!("{}:", doc_url.scheme());
    let host = escape_js_string(doc_url.host_str().unwrap_or(""));
    let port = doc_url.port().map(|p| p.to_string()).unwrap_or_default();
    let pathname = escape_js_string(doc_url.path());
    let search = doc_url
        .query()
        .map(|q| escape_js_string(&format!("?{q}")))
        .unwrap_or_default();
    format!(
        r#"(function(){{
  var G = globalThis;
  G.location = {{
    href: "{href}", origin: "{origin}", protocol: "{protocol}",
    host: "{host}", hostname: "{host}", port: "{port}",
    pathname: "{pathname}", search: "{search}", hash: "",
    toString: function() {{ return this.href; }}
  }};
  G.__wptClientUrl = "{href}";
  G.__wptClientOrigin = "{origin}";
}})();
"#
    )
}

/// Parse the leading `// META: script=...` block of a `.any.js` file.
fn parse_meta_scripts(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in code.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix("//") else {
            break;
        };
        let rest = rest.trim_start();
        let Some(meta) = rest.strip_prefix("META:") else {
            break;
        };
        let meta = meta.trim_start();
        if let Some(v) = meta.strip_prefix("script=") {
            out.push(v.trim().to_string());
        }
    }
    out
}

/// Resolve and recursively collect `META: script=` dependencies. Dependencies
/// listed by a dependency are evaluated before it, matching browser script
/// order. Missing files are reported instead of aborting the run.
fn collect_meta_scripts(
    file: &Path,
    root: Option<&Path>,
    seen: &mut HashSet<PathBuf>,
    out: &mut Vec<PathBuf>,
    missing: &mut Vec<String>,
) {
    let Ok(code) = std::fs::read_to_string(file) else {
        return;
    };
    for rel in parse_meta_scripts(&code) {
        let p = if let Some(stripped) = rel.strip_prefix('/') {
            root.map(|r| r.join(stripped))
                .unwrap_or_else(|| PathBuf::from(stripped))
        } else {
            file.parent().unwrap_or(Path::new(".")).join(&rel)
        };
        let key = p.canonicalize().unwrap_or_else(|_| p.clone());
        if !seen.insert(key) {
            continue;
        }
        if !p.is_file() {
            missing.push(rel);
            continue;
        }
        collect_meta_scripts(&p, root, seen, out, missing);
        out.push(p);
    }
}

fn setup_wpt_globals(cx: &mut ScopedContext) -> Result<(), i32> {
    let mut global = cx.global_obj();
    let gval = JSValue::from(global);
    global.set_property_str(cx, "self", gval)?;
    global.set_property_str(cx, "window", gval)?;
    global.set_property_str(cx, "globalThis", gval)?;
    let mut gobj = cx.create_base_object()?;
    let true_fn = cx.create_native_function(
        Callback::Func(|_, _| Ok(JSValue::from(true))),
        "isWindow",
        0,
        0,
    )?;
    let false_fn = cx.create_native_function(
        Callback::Func(|_, _| Ok(JSValue::from(false))),
        "isWorker",
        0,
        1,
    )?;
    let false_fn2 = cx.create_native_function(
        Callback::Func(|_, _| Ok(JSValue::from(false))),
        "isShadowRealm",
        0,
        2,
    )?;
    gobj.set_property_str(cx, "isWindow", true_fn.into())?;
    gobj.set_property_str(cx, "isWorker", false_fn.into())?;
    gobj.set_property_str(cx, "isShadowRealm", false_fn2.into())?;
    global.set_property_str(cx, "GLOBAL", gobj.into())?;
    Ok(())
}

fn js_module_loader(
    ctx: &mut ScopedContext,
    file_name: &url::Url,
    _attrs: JSValue,
) -> Result<ModuleDef, i32> {
    let path = match zuqe::url_to_abspath(file_name) {
        Some(p) => p,
        None => {
            return Err(ctx.throw_reference_error(&format!(
                "could not load module '{file_name}': not a file:// URL"
            )));
        }
    };
    match std::fs::read_to_string(&path) {
        Ok(content) => ctx.compile_module(content.as_bytes(), file_name, false),
        Err(_) => Err(ctx.throw_reference_error(&format!("could not load module '{file_name}'"))),
    }
}

fn eval_script(cx: &mut ScopedContext, code: &str, name: &str) -> Result<(), String> {
    eval_script_at(cx, code, name, None)
}

/// Evaluate a global script. When `base` is set the script's document/base URL
/// is that URL, so relative `fetch()`/`URL` resolution matches a browser.
fn eval_script_at(
    cx: &mut ScopedContext,
    code: &str,
    name: &str,
    base: Option<&url::Url>,
) -> Result<(), String> {
    let eval_name = match base {
        Some(u) => EvalName::BaseUrl(u.clone()),
        None => EvalName::Name(name.to_string()),
    };
    match cx.eval(
        code.as_bytes(),
        &eval_name,
        EvalType::Global,
        EvalFlags::empty(),
    ) {
        Ok(_) => Ok(()),
        Err(_) => Err(take_exc_string(cx)),
    }
}

fn take_exc_string(cx: &mut ScopedContext) -> String {
    match cx.take_exception() {
        Exception::No => "no exception".to_string(),
        Exception::OutOfMemory => "out of memory".to_string(),
        Exception::TooManyAtoms => "too many atoms".to_string(),
        Exception::Error(err) => {
            let mut out = String::from("error: ");
            if let Ok(name) = err.get_property_str(cx, "name") {
                if let Some(s) = name.as_string(false) {
                    out.push_str(&s.encode_utf8(false));
                    out.push_str(": ");
                }
            }
            if let Ok(msg) = err.get_property_str(cx, "message") {
                if let Some(s) = msg.as_string(false) {
                    out.push_str(&s.encode_utf8(false));
                }
            } else if let Ok(s) = err.to_string(cx) {
                out.push_str(&s.encode_utf8(false));
            }
            if let Ok(st) = err.get_property_str(cx, "stack") {
                if let Some(s) = st.as_string(false) {
                    out.push('\n');
                    out.push_str(&s.encode_utf8(false));
                }
            }
            out
        }
        e => format!("{e:?}"),
    }
}

fn get_global_bool(cx: &mut ScopedContext, name: &str) -> bool {
    cx.global_obj()
        .get_property_str(cx, name)
        .ok()
        .is_some_and(|v| v.to_bool().unwrap_or(false))
}

async fn run_wpt_file(
    rt: &mut Runtime,
    http: &reqwest::Client,
    testharness: &str,
    file: &Path,
    root: Option<&Path>,
    server: &str,
    timeout: Duration,
    gc_stress: bool,
) -> (u32, u32, Vec<String>) {
    let doc_url = test_document_url(file, root, server);
    // Prefer the server's copy: wptserve performs `.sub.` substitutions
    // (`{{host}}`, `{{ports[http][0]}}`, ...) that the on-disk file keeps raw.
    // Fall back to disk when the server is unreachable.
    let code = match fetch_source(http, &doc_url).await {
        Some(c) => c,
        None => match std::fs::read_to_string(file) {
            Ok(c) => c,
            Err(e) => return (0, 1, vec![format!("read {}: {e}", file.display())]),
        },
    };
    let mut meta_scripts = Vec::new();
    let mut missing_meta = Vec::new();
    collect_meta_scripts(
        file,
        root,
        &mut HashSet::new(),
        &mut meta_scripts,
        &mut missing_meta,
    );
    for m in &missing_meta {
        println!("# missing META script {m} for {}", file.display());
    }
    // Fetch dependency sources up front: the scope closure below is sync.
    let mut dep_sources: Vec<(String, String)> = Vec::new();
    for dep in &meta_scripts {
        let dep_url = test_document_url(dep, root, server);
        let dep_code = match fetch_source(http, &dep_url).await {
            Some(c) => c,
            None => match std::fs::read_to_string(dep) {
                Ok(c) => c,
                Err(e) => {
                    println!("# cannot read META script {}: {e}", dep.display());
                    continue;
                }
            },
        };
        dep_sources.push((dep.display().to_string(), dep_code));
    }

    let setup = r#"
var G = (typeof globalThis !== 'undefined') ? globalThis : self;
G.__wpt_results = [];
G.__wpt_done = false;
G.__wpt_result_cbs = [];
G.__wpt_complete_cbs = [];
G.add_result_callback = function(cb){
  var wrapped = function(test){
    try {
      var pass = (test.status === 0);
      G.__wpt_results.push({name:String(test.name||''), pass:!!pass, msg:String(test.message||'')});
    } catch(e){}
    try { cb(test); } catch(e){}
  };
  G.__wpt_result_cbs.push(wrapped);
  return wrapped;
};
G.add_completion_callback = function(cb){
  var wrapped = function(){
    try { G.__wpt_done = true; } catch(e){}
    try { cb(); } catch(e){}
  };
  G.__wpt_complete_cbs.push(wrapped);
  return wrapped;
};
G.add_start_callback = function(cb){};
"#;
    let hook2 = r#"
(function(){
  var G = (typeof globalThis !== 'undefined') ? globalThis : self;
  try {
    if (typeof add_result_callback === 'function') {
      add_result_callback(function(test){
        var pass = (test.status === 0);
        G.__wpt_results.push({name:String(test.name||''), pass:!!pass, msg:String(test.message||'')});
      });
    }
    if (typeof add_completion_callback === 'function') {
      add_completion_callback(function(){ G.__wpt_done = true; });
    }
  } catch(e) { G.__wpt_hook_err = String(e); }
})();
"#;
    let finish = r#"
try { if (typeof done === 'function') done(); } catch(e){}
var Gf = (typeof globalThis!=='undefined')?globalThis:self;
Gf.__wpt_done = Gf.__wpt_done || (Gf.__wpt_results.length > 0);
"#;

    let file_name = file.to_string_lossy().to_string();

    // Fresh context per file to avoid cross-file global redeclarations (closer to aike runner).
    let mut ctx = match rt.create_context(|cx| {
        ScopedContext::ECMA_CONTEXT_SETUP(cx)?;
        #[cfg(debug_assertions)]
        if gc_stress {
            cx.rt_mut().gc_set_stress(true);
        }
        #[cfg(not(debug_assertions))]
        let _ = gc_stress;
        let global = cx.global_obj();
        zuqe_whatwg::init_whatwg(cx, global)?;
        setup_wpt_globals(cx)?;
        Ok::<(), i32>(())
    }) {
        Ok(c) => c,
        Err(_) => {
            return (
                0,
                1,
                vec![format!("{}: failed to create context", file.display())],
            );
        }
    };

    let eval_err = ctx.with_root_scope(|mut cx| -> Result<(), String> {
        eval_script(&mut cx, setup, "<wpt-setup>").map_err(|e| format!("setup: {e}"))?;
        eval_script(&mut cx, testharness, "<testharness>")
            .map_err(|e| format!("testharness: {e}"))?;
        eval_script(&mut cx, hook2, "<wpt-hook2>").map_err(|e| format!("hook2: {e}"))?;
        eval_script(&mut cx, &location_setup_script(&doc_url), "<wpt-location>")
            .map_err(|e| format!("location: {e}"))?;
        // The WPT TLS fixtures use a self-signed certificate.
        eval_script(
            &mut cx,
            "try { fetch.allowInsecureTLS = true; } catch (e) {}",
            "<wpt-fetch-config>",
        )
        .map_err(|e| format!("fetch config: {e}"))?;
        for (label, dep_code) in &dep_sources {
            eval_script_at(&mut cx, dep_code, label, Some(&doc_url))
                .map_err(|e| format!("meta {label}: {e}"))?;
        }
        eval_script_at(&mut cx, &format!("{code}\n"), &file_name, Some(&doc_url))
            .map_err(|e| format!("test: {e}"))?;
        eval_script(&mut cx, finish, "<wpt-finish>").map_err(|e| format!("finish: {e}"))?;
        Ok(())
    });
    if let Err(e) = eval_err {
        return (0, 1, vec![format!("{}: {e}", file.display())]);
    }

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let _ = rt.tick();
        if ctx.with_root_scope(|mut cx| get_global_bool(&mut cx, "__wpt_done")) {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    for _ in 0..100 {
        let _ = rt.tick();
        if ctx.with_root_scope(|mut cx| get_global_bool(&mut cx, "__wpt_done")) {
            break;
        }
        tokio::task::yield_now().await;
    }

    ctx.with_root_scope(|mut cx| {
        let mut pass = 0u32;
        let mut fail = 0u32;
        let mut failures = Vec::new();
        let g = cx.global_obj();
        if let Ok(arr_val) = g.get_property_str(&mut cx, "__wpt_results") {
            if let Some(obj) = arr_val.as_object() {
                let len = obj
                    .get_property_str(&mut cx, "length")
                    .ok()
                    .and_then(|v| v.to_number(&mut cx).ok().map(|n| n.to_u32()))
                    .unwrap_or(0);
                for i in 0..len {
                    if let Ok(item) = obj.get_property_value(&mut cx, JSValue::from(i as i32)) {
                        if let Some(it) = item.as_object() {
                            let ok = it
                                .get_property_str(&mut cx, "pass")
                                .ok()
                                .is_some_and(|v| v.to_bool().unwrap_or(false));
                            let name = it
                                .get_property_str(&mut cx, "name")
                                .ok()
                                .and_then(|v| v.as_string(false))
                                .map(|s| s.encode_utf8(false).into_owned())
                                .unwrap_or_default();
                            let msg = it
                                .get_property_str(&mut cx, "msg")
                                .ok()
                                .and_then(|v| v.as_string(false))
                                .map(|s| s.encode_utf8(false).into_owned())
                                .unwrap_or_default();
                            if ok {
                                pass += 1;
                            } else {
                                fail += 1;
                                failures.push(format!("FAIL {}: {} {}", file.display(), name, msg));
                            }
                        }
                    }
                }
            }
        }
        let done = get_global_bool(&mut cx, "__wpt_done");
        if !done && pass == 0 && fail == 0 {
            failures.push(format!("TIMEOUT/INCOMPLETE: {}", file.display()));
            fail += 1;
        }
        (pass, fail, failures)
    })
}

async fn run_script_file(rt: &mut Runtime, file: &Path, gc_stress: bool) -> ExitCode {
    let code = match std::fs::read_to_string(file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("wpt_runtime: can't read {}: {e}", file.display());
            return ExitCode::FAILURE;
        }
    };
    let mut ctx = match rt.create_context(|cx| {
        ScopedContext::ECMA_CONTEXT_SETUP(cx)?;
        #[cfg(debug_assertions)]
        if gc_stress {
            cx.rt_mut().gc_set_stress(true);
        }
        #[cfg(not(debug_assertions))]
        let _ = gc_stress;
        let global = cx.global_obj();
        zuqe_whatwg::init_whatwg(cx, global)?;
        setup_wpt_globals(cx)?;
        Ok::<(), i32>(())
    }) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("wpt_runtime: failed to create context");
            return ExitCode::FAILURE;
        }
    };
    let is_module = file.extension().and_then(|e| e.to_str()) == Some("mjs")
        || ModuleDef::detect_module(code.as_bytes());
    let url_str = file.to_string_lossy();
    let url = zuqe::path_to_url(url_str.as_ref())
        .unwrap_or_else(|_| url::Url::parse("file:///script.js").unwrap());
    let status = ctx
        .eval_wait(
            code.as_bytes(),
            &EvalName::BaseUrl(url),
            if is_module {
                EvalType::Module
            } else {
                EvalType::Global
            },
            EvalFlags::empty(),
        )
        .await;
    match status {
        ExitStatus::Value(_) => ExitCode::SUCCESS,
        ExitStatus::Interrupted(c) => c,
        ExitStatus::Exception(Exception::Error(err)) => {
            ctx.with_root_scope(|mut cx| {
                if let Ok(s) = err.to_string(&mut cx) {
                    eprintln!("{}", s.encode_utf8(false));
                }
            });
            ExitCode::FAILURE
        }
        ExitStatus::Exception(Exception::OutOfMemory) => {
            eprintln!("out of memory");
            ExitCode::FAILURE
        }
        other => {
            eprintln!("error: {other:?}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();

    // WPT's testharness and the engine's native call trampolines consume a lot
    // of native stack; the default Windows main-thread stack (1 MiB) makes the
    // engine's C-stack guard fire inside otherwise-shallow assertions. Run the
    // whole workload on a dedicated thread with plenty of stack.
    match std::thread::Builder::new()
        .name("wpt-runtime".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            match rt {
                Ok(rt) => rt.block_on(run(args)),
                Err(e) => {
                    eprintln!("wpt_runtime: failed to create tokio runtime: {e}");
                    ExitCode::FAILURE
                }
            }
        }) {
        Ok(handle) => handle.join().unwrap_or(ExitCode::FAILURE),
        Err(e) => {
            eprintln!("wpt_runtime: failed to spawn thread: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> ExitCode {
    zuqe_whatwg::install_state_accessor(whatwg_state);
    let mut rt = match Runtime::create_with(WptState {
        whatwg: zuqe_whatwg::WhatwgState::new(),
    }) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("wpt_runtime: failed to create runtime");
            return ExitCode::FAILURE;
        }
    };
    rt.set_module_loader(js_module_loader);

    let looks_wpt = args.inputs.iter().any(|p| {
        p.to_string_lossy().contains(".any.")
            || p.is_dir()
            || args.testharness.is_some()
            || args.root.is_some()
    });

    if !looks_wpt && args.inputs.len() == 1 && args.inputs[0].is_file() {
        return run_script_file(&mut rt, &args.inputs[0], args.gc_stress).await;
    }

    let testharness_path = if let Some(p) = args.testharness.clone() {
        p
    } else if let Some(r) = args.root.as_ref() {
        r.join("resources/testharness.js")
    } else if let Ok(r) = std::env::var("WPT_ROOT") {
        PathBuf::from(r).join("resources/testharness.js")
    } else {
        PathBuf::from("resources/testharness.js")
    };
    let testharness = match std::fs::read_to_string(&testharness_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "wpt_runtime: cannot read testharness.js at {}: {e}",
                testharness_path.display()
            );
            return ExitCode::FAILURE;
        }
    };

    let tests = collect_tests(&args.inputs, args.root.as_deref());
    if tests.is_empty() {
        eprintln!("wpt_runtime: no .any.js tests found");
        return ExitCode::FAILURE;
    }

    let mut total_pass = 0u32;
    let mut total_fail = 0u32;
    let mut all_failures = Vec::new();
    let timeout = Duration::from_millis(args.timeout_ms);
    // WPT's TLS server uses a self-signed certificate; fetching test sources
    // over https must not validate it.
    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    for t in &tests {
        println!("# running {}", t.display());
        let run = AssertUnwindSafe(run_wpt_file(
            &mut rt,
            &http,
            &testharness,
            t,
            args.root.as_deref(),
            &args.server,
            timeout,
            args.gc_stress,
        ))
        .catch_unwind();
        let (p, f, fails) = match run.await {
            Ok(r) => r,
            Err(payload) => {
                let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "non-string panic payload".to_string()
                };
                (0, 1, vec![format!("PANIC {}: {msg}", t.display())])
            }
        };
        total_pass += p;
        total_fail += f;
        all_failures.extend(fails);
        let status = if f == 0 { "PASS" } else { "FAIL" };
        println!("{status} {} ({} passed, {} failed)", t.display(), p, f);
    }
    println!(
        "\n# TOTAL: {} passed, {} failed, {} files",
        total_pass,
        total_fail,
        tests.len()
    );
    for f in &all_failures {
        println!("{f}");
    }
    if total_fail == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
