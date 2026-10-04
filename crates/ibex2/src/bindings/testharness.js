// A minimal testharness.js, sufficient for the WPT files we have adopted.
//
// Not a reimplementation of upstream testharness — just the assertions and the
// test() shape those files actually call, so real WPT sources run unmodified.
// Results are collected for the Rust side to read.
(function (global) {
  "use strict";

  var results = [];
  var pending = 0;
  var outstandingPromiseTests = 0;
  var promiseTestTail = Promise.resolve();

  function record(name, error) {
    results.push({ name: name, ok: !error, message: error ? String(error && error.message || error) : "" });
  }

  function context(name, asynchronous) {
    var cleanups = [];
    var finished = false;
    var firstError = null;
    function cleanup(error) {
      for (var i = cleanups.length - 1; i >= 0; i--) {
        try { cleanups[i](); } catch (e) { if (!error) error = e; }
      }
      cleanups = [];
      return error;
    }
    function finish(error) {
      if (finished) return;
      finished = true;
      if (asynchronous) pending--;
      record(name, cleanup(error || firstError));
    }
    var t = {
      add_cleanup: function (fn) { cleanups.push(fn); },
      cleanup: cleanup,
      step: function (fn) {
        if (finished) return;
        try { return fn.call(t); }
        catch (error) {
          if (!firstError) firstError = error;
          if (asynchronous) finish(error);
        }
      },
      step_func: function (fn) {
        return function () {
          try { return fn.apply(t, arguments); }
          catch (error) {
            if (!firstError) firstError = error;
            if (asynchronous) finish(error);
          }
        };
      },
      step_func_done: function (fn) {
        return function () {
          try { if (fn) fn.apply(t, arguments); finish(null); }
          catch (error) { finish(error); }
        };
      },
      step_timeout: function (fn, milliseconds) {
        return setTimeout(t.step_func(fn), milliseconds);
      },
      unreached_func: function (description) {
        return t.step_func(function () { fail("reached unreachable code", description); });
      },
      done: function () { finish(null); },
      _finish: finish,
      _error: function () { return firstError; }
    };
    return t;
  }

  global.test = function (fn, name) {
    var t = context(name, false);
    var error = null;
    try {
      fn.call(t, t);
    } catch (e) {
      error = e;
    }
    record(name, t.cleanup(error || t._error()));
  };

  global.async_test = function (fn, name) {
    if (typeof fn !== "function") {
      name = fn;
      fn = null;
    }
    pending++;
    var t = context(name, true);
    if (fn) {
      try { fn.call(t, t); } catch (e) { t._finish(e); }
    }
    return t;
  };

  global.promise_test = function (fn, name) {
    pending++;
    outstandingPromiseTests++;
    var t = context(name, true);
    // WPT promise tests run in registration order. Besides matching the real
    // harness, serialization keeps tests which temporarily delete an interface
    // from perturbing unrelated cases that use it.
    promiseTestTail = promiseTestTail.then(function () {
      return fn.call(t, t);
    }).then(function () {
      t.done();
      outstandingPromiseTests--;
    }, function (e) {
      t._finish(e);
      outstandingPromiseTests--;
    });
  };

  global.done = function () {};
  global.setup = function () {};
  global.subsetTest = function (fn) {
    return fn.apply(null, Array.prototype.slice.call(arguments, 1));
  };

  function fail(message, extra) {
    throw new Error(message + (extra ? " — " + extra : ""));
  }

  global.assert_equals = function (actual, expected, description) {
    if (!Object.is(actual, expected)) {
      fail("expected " + format(expected) + " but got " + format(actual), description);
    }
  };
  global.assert_not_equals = function (actual, expected, description) {
    if (actual === expected) {
      fail("got disallowed value " + format(actual), description);
    }
  };
  global.assert_greater_than_equal = function (actual, expected, description) {
    if (!(actual >= expected)) fail(format(actual) + " is not >= " + format(expected), description);
  };
  global.assert_less_than_equal = function (actual, expected, description) {
    if (!(actual <= expected)) fail(format(actual) + " is not <= " + format(expected), description);
  };
  global.assert_less_than = function (actual, expected, description) {
    if (!(actual < expected)) fail(format(actual) + " is not < " + format(expected), description);
  };
  global.assert_true = function (value, description) {
    if (value !== true) fail("expected true but got " + format(value), description);
  };
  global.assert_false = function (value, description) {
    if (value !== false) fail("expected false but got " + format(value), description);
  };
  global.assert_array_equals = function (actual, expected, description) {
    if (actual.length !== expected.length) {
      fail("array length " + actual.length + " !== " + expected.length, description);
    }
    for (var i = 0; i < actual.length; i++) {
      if (actual[i] !== expected[i]) {
        fail("index " + i + ": " + format(actual[i]) + " !== " + format(expected[i]), description);
      }
    }
  };
  global.assert_throws_js = function (constructor, fn, description) {
    try {
      fn();
    } catch (e) {
      if (e instanceof constructor) return;
      fail("threw " + (e && e.name) + " instead of " + (constructor && constructor.name), description);
    }
    fail("did not throw", description);
  };
  global.assert_throws_exactly = function (expected, fn, description) {
    try { fn(); } catch (e) {
      if (e === expected) return;
      fail("threw " + format(e) + " instead of the exact expected value", description);
    }
    fail("did not throw", description);
  };
  global.assert_throws_dom = function (name, fn, description) {
    try { fn(); } catch (e) {
      if (e instanceof DOMException && e.name === name) return;
      fail("expected DOMException " + name + " but got " + e, description);
    }
    fail("did not throw", description);
  };
  global.promise_rejects_dom = function (_, name, promise, description) {
    return Promise.resolve(promise).then(function () {
      fail("did not reject", description);
    }, function (error) {
      if (!(error instanceof DOMException) || error.name !== name) {
        fail("expected DOMException " + name + " but got " + error, description);
      }
    });
  };
  global.promise_rejects_exactly = function (_, expected, promise, description) {
    return Promise.resolve(promise).then(function () {
      fail("did not reject", description);
    }, function (error) {
      if (error !== expected) fail("rejected with a different value", description);
    });
  };
  // The overload used by the adopted WebCrypto tests. Preserve upstream's
  // constructor, name, code, quota and requested checks.
  global.assert_throws_quotaexceedederror = function (fn, requested, quota, description) {
    let caught;
    try { fn(); } catch (e) { caught = e; }
    if (!caught) fail("did not throw", description);
    global.assert_equals(caught.constructor, QuotaExceededError, description);
    global.assert_equals(caught.name, "QuotaExceededError", description);
    global.assert_equals(caught.code, 22, description);
    global.assert_equals(caught.requested, requested, description);
    global.assert_equals(caught.quota, quota, description);
  };
  global.assert_unreached = function (description) {
    fail("reached unreachable code", description);
  };
  // WPT uses this to mark a permitted optional feature as unsupported. The
  // Rust runner turns this failure into a named exclusion for its pass/fail
  // accounting.
  global.assert_implements_optional = function (actual, description) {
    if (!actual) fail("optional feature not implemented", description);
  };
  global.assert_class_string = function (object, className, description) {
    var got = Object.prototype.toString.call(object);
    if (got !== "[object " + className + "]") {
      fail("class string " + got + " !== [object " + className + "]", description);
    }
  };

  function format(value) {
    if (typeof value === "string") return JSON.stringify(value);
    if (value === undefined) return "undefined";
    if (value === null) return "null";
    return String(value);
  }

  global.format_value = format;

  global.__ibex2_test_results = function () {
    return JSON.stringify(results);
  };
  global.__ibex2_test_outstanding = function () {
    return outstandingPromiseTests;
  };
  global.__ibex2_reset_results = function () {
    results = [];
    pending = 0;
    outstandingPromiseTests = 0;
    promiseTestTail = Promise.resolve();
  };
  global.__ibex2_pending_tests = function () { return pending; };

  // The ECDSA fixture clones plain records containing typed arrays while it
  // constructs invalid-vector variants. This test-only clone is deliberately
  // limited to that data shape; it is not the standard-library implementation.
  if (typeof global.structuredClone === "undefined") {
    global.structuredClone = function clone(value) {
      if (value === null || typeof value !== "object") return value;
      if (ArrayBuffer.isView(value)) return new value.constructor(value);
      if (value instanceof ArrayBuffer) return value.slice(0);
      if (Array.isArray(value)) return value.map(clone);
      var result = {};
      Object.keys(value).forEach(function (key) { result[key] = clone(value[key]); });
      return result;
    };
  }
})(globalThis);
