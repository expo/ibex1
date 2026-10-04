// A minimal testharness.js, sufficient for the WPT files we have adopted.
//
// Not a reimplementation of upstream testharness — just the assertions and the
// test() shape those files actually call, so real WPT sources run unmodified.
// Results are collected for the Rust side to read.
(function (global) {
  "use strict";

  var results = [];

  function record(name, error) {
    results.push({ name: name, ok: !error, message: error ? String(error && error.message || error) : "" });
  }

  function context() {
    var cleanups = [];
    return {
      add_cleanup: function (fn) { cleanups.push(fn); },
      cleanup: function (error) {
        for (var i = cleanups.length - 1; i >= 0; i--) {
          try { cleanups[i](); } catch (e) { if (!error) error = e; }
        }
        return error;
      }
    };
  }

  global.test = function (fn, name) {
    var state = context(), error = null;
    try {
      fn.call(state, state);
    } catch (e) {
      error = e;
    }
    record(name, state.cleanup(error));
  };

  global.promise_test = function (fn, name) {
    var state = context();
    try {
      var p = fn.call(state, state);
      if (p && typeof p.then === "function") {
        p.then(function () { record(name, state.cleanup(null)); },
               function (e) { record(name, state.cleanup(e)); });
      } else {
        record(name, state.cleanup(null));
      }
    } catch (e) {
      record(name, state.cleanup(e));
    }
  };

  // The adopted Blob constructor fixture has one MessageChannel async_test.
  // This small shape records its missing-engine failure without letting the
  // top-level fixture abort; the Rust runner classifies that named case as an
  // explicit exclusion.
  global.async_test = function (name) {
    var state = context(), complete = false;
    function finish(error) {
      if (complete) return;
      complete = true;
      record(name, state.cleanup(error));
    }
    state.step = function (fn) {
      if (complete) return;
      try { fn.call(state); } catch (e) { finish(e); }
    };
    state.step_func = function (fn) {
      return function () {
        if (complete) return;
        try { return fn.apply(state, arguments); } catch (e) { finish(e); }
      };
    };
    state.done = function () { finish(null); };
    return state;
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
    if (actual !== expected) {
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
    try {
      fn();
    } catch (e) {
      if (e === expected) return;
      fail("threw " + format(e) + " instead of the expected value", description);
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
  global.__ibex2_reset_results = function () {
    results = [];
  };
})(globalThis);
