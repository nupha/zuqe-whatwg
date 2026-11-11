# zuqe-whatwg

WHATWG / Web-platform API implementations for the [Zuqe](../zhuque) JavaScript
runtime.

This crate is not a browser. It implements the platform APIs that make sense for
an embeddable, host-driven JavaScript runtime: Fetch, Streams, URL, Encoding,
Blob, WebCrypto, Abort, timers, structured clone, `console`, and a few related
interfaces. DOM, HTML parsing, CSS, workers, service workers and other
document-centric facilities are out of scope.

The implementation is validated against [web-platform-tests][wpt] through
`examples/wpt_runtime` (a small testharness.js runner).

[wpt]: https://github.com/web-platform-tests/wpt

## Cargo features

| Feature             | Effect                                                                                                                     |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| _(none)_            | Lean HTTP client. `fetch` works, but browser CORS/cookie behavior is not enforced and `caches`/`cookieStore` are absent.   |
| `fetch_cors_cookie` | Browser fetch semantics: CORS checks/preflights, shared cookie jar, `cookieStore`, `fetch.allowInsecureTLS`.               |
| `fetch_cache`       | HTTP cache (freshness, revalidation, `Vary`, range/partial handling) plus the `caches` / `CacheStorage` / `Cache` globals. |

The WPT runner example requires both features:

```sh
cargo build --example wpt_runtime --features "fetch_cors_cookie fetch_cache"
```

## Specification coverage

Legend: ✅ implemented, ⚠️ partial, ❌ not implemented. **substantial** = usable end-to-end with only edge-case gaps;
**partial** = core APIs exist but important algorithms/modes are missing;
**minimal** = only the small surface needed by other components.

| Specification                              | Module                               | Status         | Scope and known gaps                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------------------------ | ------------------------------------ | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Fetch Standard][fetch]                    | `fetch/`                             | ✅ substantial | ✅ **Implemented:** `fetch`, `Request`, `Response`, `Headers`, body mixins (`arrayBuffer`, `bytes`, `blob`, `json`, `text`, `formData`), `data:` / `blob:` / `http(s):` URLs, manual redirect following with per-hop referrer/origin recomputation, `AbortSignal`, SRI `integrity`, stream request bodies (`duplex: "half"`), `FormData` upload. With `fetch_cors_cookie`: CORS, preflight/response validation, credentials and shared cookies. With `fetch_cache`: HTTP cache and `caches`.<br>❌ **Not implemented:** HTTP/1.1 only (no HTTP/2 or HTTP/3), `keepalive` is validated but has no network-lifetime guarantee, no Service Worker interception, no ORB/opaque-response range blocking, no `priority`, no `navigator.sendBeacon`, no document/navigation modes. |
| [Streams Standard][streams]                | `stream/`                            | ✅ substantial | ✅ **Implemented:** `ReadableStream` (default, byte, owning-type plumbing), `WritableStream`, `TransformStream`, readers/writers, default/byte/transform controllers, BYOB reads, `tee`, `pipeTo`/`pipeThrough` with backpressure/abort/error propagation, `ReadableStream.from`, async iteration (`values`, `Symbol.asyncIterator`), `CountQueuingStrategy`, `ByteLengthQueuingStrategy`.<br>❌ **Not implemented:** transferable streams over `postMessage` are not implemented (no cross-realm transfer), and owning-type transfer depends on the transferables the host provides.                                                                                                                                                                                       |
| [URL Standard][url]                        | `url/`                               | ⚠️ partial     | ✅ **Implemented:** `URL`, `URLSearchParams`, `URL.createObjectURL` / `revokeObjectURL` for Blob. Parsing/serialization is delegated to the Rust `url` crate.<br>❌ **Not implemented:** no `URLPattern`; WPT `url-constructor`/`url-origin`/`IdnaTestV2` conformance is incomplete (IDNA and parser edge cases).                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| [Encoding Standard][encoding]              | `text_encoder.rs`, `text_decoder.rs` | ⚠️ partial     | ✅ **Implemented:** `TextEncoder` (UTF-8, `encodeInto`); `TextDecoder` with streaming, `fatal`, `ignoreBOM`; supported encodings: UTF-8, UTF-16LE, UTF-16BE, ISO-8859-1 (labels are matched literally; WHATWG alias/replacement semantics are incomplete).<br>❌ **Not implemented:** no legacy single-byte / multi-byte encodings (Windows-125x, Shift_JIS, GBK, EUC-JP, ISO-2022-JP, …); no `TextEncoderStream` / `TextDecoderStream`.                                                                                                                                                                                                                                                                                                                                    |
| [File API][fileapi]                        | `blob.rs`                            | ⚠️ partial     | ✅ **Implemented:** `Blob` (constructor, `slice`, `size`, `type`, `arrayBuffer`, `bytes`, `text`, `stream`) and object URLs.<br>❌ **Not implemented:** `File`, `FileReader`, `FileList` and `URL.createObjectURL` for media streams are not implemented by the crate. The WPT runner supplies a minimal `File extends Blob` shim so that structured-clone tests can run.                                                                                                                                                                                                                                                                                                                                                                                                   |
| [FormData][xhr]                            | `form_data.rs`                       | ✅ substantial | ✅ **Implemented:** `FormData` with `append`/`set`/`get`/`getAll`/`has`/`delete`, `forEach`, and key/value/entry iterators; Blob values are preserved; usable as a fetch request body.<br>❌ **Not implemented:** HTML form-element integration (there is no DOM).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| [Web Cryptography API][webcrypto]          | `crypto/`                            | ⚠️ partial     | ✅ **Implemented:** `crypto.getRandomValues`, `crypto.randomUUID`; `subtle.digest` (SHA-1/256/384/512), `subtle.sign`/`verify` (HMAC), `subtle.encrypt`/`decrypt` (AES-GCM), `importKey`/`exportKey` for raw and JWK (HMAC, AES-GCM).<br>❌ **Not implemented:** no PBKDF2, HKDF, RSA (OAEP/PSS), ECDSA/ECDH, AES-CBC/CTR/KW, `deriveKey`/`deriveBits`, `wrapKey`/`unwrapKey`, or certificate APIs.                                                                                                                                                                                                                                                                                                                                                                         |
| [DOM Abort][abort]                         | `abort.rs`                           | ✅ substantial | ✅ **Implemented:** `AbortController`, `AbortSignal` (`aborted`, `reason`, `throwIfAborted`, listeners/`dispatchEvent`), statics `AbortSignal.abort`, `AbortSignal.timeout`, `AbortSignal.any`; integrates with `fetch` and streams.<br>❌ **Not implemented:** No `onabort` event-handler attribute.                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| [HTML: microtask queuing][microtask]       | `microtask.rs`                       | ✅ substantial | ✅ **Implemented:** `queueMicrotask`; uncaught callback exceptions are reported through the host `reportError` hook (the WPT runner turns this into an `error` event).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| [HTML: timers][timers]                     | `timeout.rs`                         | ✅ substantial | ✅ **Implemented:** `setTimeout`, `setInterval`, `clearTimeout`, `clearInterval`; function and string handlers; host event loop implemented as a self-requeuing runtime job; per-runtime timer list reset hook for isolated test contexts.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| [HTML: structured clone][structured-clone] | `structured_clone.rs`                | ✅ substantial | ✅ **Implemented:** `structuredClone` for primitives, Arrays/Objects, Map/Set, Date, RegExp (lastIndex reset), Error (message/cause), Blob, ArrayBuffer (including resizable), TypedArray/DataView (including length-tracking views), Boolean/Number/String/BigInt wrappers, cycles and duplicate references; `transfer` for ArrayBuffer.<br>❌ **Not implemented:** no `MessagePort`, `ImageBitmap`, `OffscreenCanvas`, or `ReadableStream` transfer/clone; SharedArrayBuffer cloning is rejected.                                                                                                                                                                                                                                                                         |
| [Console Standard][console]                | `console.rs`                         | ✅ substantial | ✅ **Implemented:** `log`, `debug`, `info`, `warn`, `error`, `assert`, `trace`, `dir`/`dirxml`, `count`/`countReset`, `time`/`timeLog`/`timeEnd`, `group`/`groupCollapsed`/`groupEnd`, `clear`, `table`. Output goes through the host output sink.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| [HTML: base64][base64-spec]                | `base64.rs`                          | ✅ substantial | ✅ **Implemented:** `btoa`/`atob` with forgiving-base64 decode; host extensions `bytesToBase64`, `base64ToBytes`, `bytesToHex`, `hexToBytes`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| [Web IDL / DOMException][domexception]     | `dom.rs`                             | ✅ minimal     | ✅ **Implemented:** `DOMException` with the standard name/code/message behavior, used by Fetch, Streams and structured clone.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| [Cookie Store API][cookiestore]            | `cookie_store.rs`                    | ⚠️ partial     | ✅ **Implemented:** `cookieStore.get`, `getAll`, `set`, `delete`; shares the fetch cookie jar.<br>❌ **Not implemented:** no `subscribe`/`CookieStoreManager`, no `change` events, no service-worker integration.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| [Service Workers: Cache API][cache-api]    | `cache_storage.rs`                   | ⚠️ partial     | ✅ **Implemented:** With `fetch_cache`: `caches.open/has/delete/keys`; `Cache.put/match/matchAll/delete/keys`. In-memory only (no persistence).<br>❌ **Not implemented:** no service-worker integration.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |

[fetch]: https://fetch.spec.whatwg.org/
[streams]: https://streams.spec.whatwg.org/
[url]: https://url.spec.whatwg.org/
[encoding]: https://encoding.spec.whatwg.org/
[fileapi]: https://w3c.github.io/FileAPI/
[xhr]: https://xhr.spec.whatwg.org/#interface-formdata
[webcrypto]: https://w3c.github.io/webcrypto/
[abort]: https://dom.spec.whatwg.org/#interface-abortcontroller
[microtask]: https://html.spec.whatwg.org/multipage/webappapis.html#microtask-queuing
[timers]: https://html.spec.whatwg.org/multipage/timers-and-user-prompts.html#timers
[structured-clone]: https://html.spec.whatwg.org/multipage/structured-data.html#structuredserializeinternal
[console]: https://console.spec.whatwg.org/
[base64-spec]: https://html.spec.whatwg.org/multipage/webappapis.html#atob
[domexception]: https://webidl.spec.whatwg.org/#idl-DOMException
[cookiestore]: https://wicg.github.io/cookie-store/
[cache-api]: https://w3c.github.io/ServiceWorker/#cache-interface

## WPT status

Last measured against the WPT checkout under `../wpt` with the
`wpt_runtime` example. Counts are individual `test()` / `promise_test()` cases,
not assertions.

| Suite                                | Passed | Failed | Notes                                                                                                                                                                                                                                                                                                                     |
| ------------------------------------ | -----: | -----: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fetch/`                             |   2380 |    184 | Most failures require missing host facilities (`XMLHttpRequest`, `document`, HTTP/2, `WebAssembly`, `MessageChannel`/`VideoFrame`), optional cache features (`no-vary-search`, cache partitioning, POST `Content-Location`), or transport-level limits (header-name casing/control bytes, CORS redirect-after-preflight). |
| `streams/`                           |    679 |     11 | Remaining failures need `WebAssembly`, `MessageChannel` or `VideoFrame` (owning-type transfer tests).                                                                                                                                                                                                                     |
| `html/webappapis/atob/`              |    285 |      0 |                                                                                                                                                                                                                                                                                                                           |
| `html/webappapis/microtask-queuing/` |      6 |      0 |                                                                                                                                                                                                                                                                                                                           |
| `html/webappapis/timers/`            |     12 |      0 |                                                                                                                                                                                                                                                                                                                           |
| `html/webappapis/structured-clone/`  |    128 |      9 | Remaining failures need `MessageChannel`/`OffscreenCanvas`/`WebAssembly`, or exercise the engine-internal OOB TypedArray flag.                                                                                                                                                                                            |
| `console/`                           |     23 |      0 |                                                                                                                                                                                                                                                                                                                           |
| `dom/abort/`                         |     32 |      0 |                                                                                                                                                                                                                                                                                                                           |

The `wpt_runtime` example is not a full WPT harness. It skips
`*.idlharness.*`, uses a minimal global `EventTarget`, a `File extends Blob`
shim, and provides `location` / `__wptClientUrl` / `__wptClientOrigin` so that
fetch tests resolve relative URLs against the wpt server. Tests that need DOM,
workers, WebAssembly, `XMLHttpRequest`, `MessageChannel`, `VideoFrame`,
`OffscreenCanvas`, or HTTP/2 are not implementation targets.

## Running the WPT suites

Start a WPT server (the default ports are 8000, 8443 and 9000 for HTTP/2):

```sh
cd ../wpt
python wpt.py --skip-venv-setup --venv _venv3 serve
```

Then run the example:

```sh
cd ../zuqe-whatwg
cargo build --example wpt_runtime --features "fetch_cors_cookie fetch_cache"
target/debug/examples/wpt_runtime \
  --root ../wpt \
  --timeout-ms 5000 \
  fetch streams
```

`wpt_runtime` also accepts individual `.any.js` files or directories, and
`--server http://web-platform.test:8000` to point at a different server.

## Embedding

See `examples/wpt_runtime/main.rs` for a complete host setup. In short:

1. Install a host state accessor and create the runtime with
   `WhatwgState` in the user state.
2. Call `zuqe_whatwg::init_whatwg(cx, global)` while creating each context.
3. Drive the runtime's job queue from the host event loop; timers and fetch
   completions are delivered as runtime jobs.
4. Provide an output sink for `console` if you want console output.

Optional runtime switches/extensions:

- `fetch.allowInsecureTLS = true` skips TLS certificate validation (self-signed
  WPT servers, development).
- `crypto.sha256Hex`, `bytesToBase64`, `base64ToBytes`, `bytesToHex`,
  `hexToBytes`, and `Response/Request.textStream()` are host extensions, not
  standard APIs.

## Known gaps

- ❌ HTTP/2 and HTTP/3.
- ❌ DOM, HTML parsing, CSS, workers, service workers, `XMLHttpRequest`.
- ❌ Legacy text encodings and `TextEncoderStream` / `TextDecoderStream`.
- ❌ `File` / `FileReader` / `FileList` in the crate (the WPT runner shims `File`).
- ❌ WebCrypto algorithms beyond SHA/HMAC/AES-GCM, and key derivation/wrapping.
- ❌ `MessagePort`, `ImageBitmap`, `OffscreenCanvas` and transferable streams.
- ❌ Persistent Cache API storage; CookieStore change events/subscriptions.
- ❌ `URLPattern` and full IDNA conformance.

## License

Apache-2.0.
