// Shared WPT testharness setup for Aike and zuqe-whatwg
// Comprehensive harness shims for *.any.js tests

(function () {
  var G = typeof globalThis !== "undefined" ? globalThis : self;
  if (!G) return;

  // Aliases
  try {
    G.self = G;
  } catch (e) {}
  try {
    G.window = G;
  } catch (e) {}
  try {
    G.globalThis = G;
  } catch (e) {}

  // Result/complete tracking
  G.__wpt_results = G.__wpt_results || [];
  G.__wpt_done = G.__wpt_done || false;
  G.__wpt_result_cbs = G.__wpt_result_cbs || [];
  G.__wpt_complete_cbs = G.__wpt_complete_cbs || [];

  // GLOBAL scope info
  G.GLOBAL = G.GLOBAL || {
    isWindow: function () {
      return true;
    },
    isWorker: function () {
      return false;
    },
    isShadowRealm: function () {
      return false;
    },
  };

  // EventTarget shim
  G.__wpt_listeners = G.__wpt_listeners || Object.create(null);
  if (typeof G.addEventListener !== "function") {
    G.addEventListener = function (type, cb) {
      if (
        !cb ||
        (typeof cb !== "function" && typeof cb.handleEvent !== "function")
      )
        return;
      (G.__wpt_listeners[type] || (G.__wpt_listeners[type] = [])).push(cb);
    };
  }
  if (typeof G.removeEventListener !== "function") {
    G.removeEventListener = function (type, cb) {
      var a = G.__wpt_listeners[type];
      if (!a) return;
      var i = a.indexOf(cb);
      if (i >= 0) a.splice(i, 1);
    };
  }
  if (typeof G.dispatchEvent !== "function") {
    G.dispatchEvent = function (ev) {
      var t = ev && ev.type;
      var a = G.__wpt_listeners[t];
      var ok = true;
      if (a) {
        a = a.slice();
        for (var i = 0; i < a.length; i++) {
          try {
            var cb = a[i];
            if (typeof cb === "function") cb.call(G, ev);
            else if (cb && typeof cb.handleEvent === "function")
              cb.handleEvent(ev);
          } catch (e) {
            try {
              console.error(e);
            } catch (_) {}
          }
        }
      }
      if (t === "error" && typeof G.onerror === "function") {
        try {
          if (
            G.onerror(
              ev.message,
              ev.filename,
              ev.lineno,
              ev.colno,
              ev.error,
            ) === false
          )
            ok = false;
        } catch (e) {}
      }
      return ok;
    };
  }
  if (typeof G.reportError !== "function") {
    G.reportError = function (err) {
      try {
        G.dispatchEvent({
          type: "error",
          error: err,
          message:
            err && err.message !== undefined
              ? String(err.message)
              : String(err),
          filename: "",
          lineno: 0,
          colno: 0,
          cancelable: true,
        });
      } catch (e) {}
    };
  }

  // File constructor minimal
  if (typeof G.File === "undefined" && typeof G.Blob !== "undefined") {
    try {
      G.File = (function (Blob) {
        function File(bits, name, opts) {
          var o = opts || {};
          Blob.call(this, bits, o);
          this.name = String(name == null ? "" : name);
          this.lastModified =
            o.lastModified !== undefined ? Number(o.lastModified) : Date.now();
        }
        if (Blob.prototype) {
          File.prototype = Object.create(Blob.prototype);
          File.prototype.constructor = File;
        }
        return File;
      })(G.Blob);
    } catch (e) {}
  }

  // Callback registration helpers
  if (typeof G.add_result_callback !== "function") {
    G.add_result_callback = function (cb) {
      var wrapped = function (test) {
        try {
          var pass = test && test.status === 0;
          G.__wpt_results.push({
            name: String((test && test.name) || ""),
            pass: !!pass,
            msg: String((test && test.message) || ""),
          });
        } catch (e) {}
        try {
          if (typeof cb === "function") cb(test);
        } catch (e) {}
      };
      G.__wpt_result_cbs.push(wrapped);
      return wrapped;
    };
  } else {
    // wrap existing to also record
    var _arc = G.add_result_callback;
    G.add_result_callback = function (cb) {
      var wrapped = function (test) {
        try {
          var pass = test && test.status === 0;
          G.__wpt_results.push({
            name: String((test && test.name) || ""),
            pass: !!pass,
            msg: String((test && test.message) || ""),
          });
        } catch (e) {}
        try {
          if (typeof cb === "function") cb(test);
        } catch (e) {}
      };
      try {
        _arc(wrapped);
      } catch (e) {
        try {
          _arc(cb);
        } catch (_) {}
      }
      return wrapped;
    };
  }

  if (typeof G.add_completion_callback !== "function") {
    G.add_completion_callback = function (cb) {
      var wrapped = function () {
        try {
          G.__wpt_done = true;
        } catch (e) {}
        try {
          if (typeof cb === "function") cb();
        } catch (e) {}
      };
      G.__wpt_complete_cbs.push(wrapped);
      return wrapped;
    };
  } else {
    var _acc = G.add_completion_callback;
    G.add_completion_callback = function (cb) {
      var wrapped = function () {
        try {
          G.__wpt_done = true;
        } catch (e) {}
        try {
          if (typeof cb === "function") cb();
        } catch (e) {}
      };
      try {
        _acc(wrapped);
      } catch (e) {
        try {
          _acc(cb);
        } catch (_) {}
      }
      return wrapped;
    };
  }

  if (typeof G.add_start_callback !== "function") {
    G.add_start_callback = function (cb) {};
  }

  // structured clone fallback
  if (typeof G.structured_clone !== "function") {
    G.structured_clone = function (v) {
      try {
        return JSON.parse(JSON.stringify(v));
      } catch (e) {
        return v;
      }
    };
  }

  // Fetch config hints
  try {
    if (typeof fetch !== "undefined") {
      if (fetch.cors === undefined) {
        try {
          fetch.cors = true;
        } catch (e) {}
      }
      if (fetch.cookie === undefined) {
        try {
          fetch.cookie = true;
        } catch (e) {}
      }
      try {
        fetch.allowInsecureTLS = true;
      } catch (e) {}
    }
  } catch (e) {}

  // Setup shim
  if (typeof G.setup !== "function") {
    G.setup = function () {};
  }
  if (typeof G.done !== "function") {
    G.done = function () {
      try {
        G.__wpt_done = true;
      } catch (e) {}
    };
  }
})();

// Shared hook2 fallback (safe to call after testharness loads)
if (typeof globalThis.__wpt_hook2_fallback !== "function") {
  globalThis.__wpt_hook2_fallback = function () {
    try {
      var G2 = typeof globalThis !== "undefined" ? globalThis : self;
      if (typeof G2.add_result_callback === "function") {
        try {
          G2.add_result_callback(function (t) {
            try {
              var p = t && t.status === 0;
              G2.__wpt_results = G2.__wpt_results || [];
              G2.__wpt_results.push({
                name: String((t && t.name) || ""),
                pass: !!p,
                msg: String((t && t.message) || ""),
              });
            } catch (e) {}
          });
        } catch (e) {}
      }
      if (typeof G2.add_completion_callback === "function") {
        try {
          G2.add_completion_callback(function () {
            try {
              G2.__wpt_done = true;
            } catch (e) {}
          });
        } catch (e) {}
      }
    } catch (e) {}
  };
}

// Shared finish
if (typeof globalThis.__wpt_finish !== "function") {
  globalThis.__wpt_finish = function () {
    try {
      if (typeof globalThis.done === "function") {
        try {
          globalThis.done();
        } catch (e) {}
      }
    } catch (e) {}
    try {
      var Gf = typeof globalThis !== "undefined" ? globalThis : self;
      Gf.__wpt_done =
        Gf.__wpt_done || (Gf.__wpt_results && Gf.__wpt_results.length > 0);
    } catch (e) {}
  };
}

try {
  if (typeof globalThis.__wpt_hook2_fallback === "function")
    globalThis.__wpt_hook2_fallback();
} catch (e) {}
