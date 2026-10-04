// A minimal testharness.js, sufficient for the WPT files we have adopted.
//
// Not a reimplementation of upstream testharness — just the assertions and the
// test() shape those files actually call, so real WPT sources run unmodified.
// Results are collected for the Rust side to read.
(function (global) {
  "use strict";

  var results = [];
  var pending = 0;

  function record(name, error) {
    results.push({ name: name, ok: !error, message: error ? String(error && error.message || error) : "" });
  }

  function context(name, asynchronous) {
    var finished = false;
    var firstError = null;
    function finish(error) {
      if (finished) return;
      finished = true;
      if (asynchronous) pending--;
      record(name, error || firstError);
    }
    var t = {
      step_func: function (fn) {
        return function () {
          try { return fn.apply(this, arguments); }
          catch (error) {
            if (!firstError) firstError = error;
            if (asynchronous) finish(error);
          }
        };
      },
      step_func_done: function (fn) {
        return function () {
          try { if (fn) fn.apply(this, arguments); finish(null); }
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
      _error: function () { return firstError; }
    };
    return t;
  }

  global.test = function (fn, name) {
    var t = context(name, false);
    try {
      fn.call(t, t);
      record(name, t._error());
    } catch (e) {
      record(name, e);
    }
  };

  global.async_test = function (fn, name) {
    // WPT's common declaration-only overload is async_test(name); callbacks
    // retained from the returned object complete it later.
    if (typeof fn === "string" && name === undefined) {
      name = fn;
      fn = null;
    }
    pending++;
    var t = context(name, true);
    try { if (typeof fn === "function") fn.call(t, t); }
    catch (e) { t.step_func_done(function () { throw e; })(); }
    return t;
  };

  global.promise_test = function (fn, name) {
    pending++;
    var t = context(name, true);
    try {
      var p = fn(t);
      if (p && typeof p.then === "function") {
        p.then(function () { t.done(); },
               t.step_func_done(function (e) { throw e; }));
      } else {
        t.done();
      }
    } catch (e) {
      t.step_func_done(function () { throw e; })();
    }
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
    var legacy = {
      SYNTAX_ERR: "SyntaxError",
      INVALID_ACCESS_ERR: "InvalidAccessError",
      INVALID_STATE_ERR: "InvalidStateError"
    };
    name = legacy[name] || name;
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

  global.__ibex2_test_results = function () {
    return JSON.stringify(results);
  };
  global.__ibex2_reset_results = function () {
    results = [];
    pending = 0;
  };
  global.__ibex2_pending_tests = function () { return pending; };
})(globalThis);
