// DOM events for a worker-shaped runtime: one target, no node tree.
(function (global) {
  "use strict";

  var brand = global.__ibex2_brand || function (value) { return value; };
  var eventStates = new WeakMap();
  var targetStates = new WeakMap();
  var abortSubscribe = null;
  var nativeReport = global.__ibex2_report_error;
  delete global.__ibex2_report_error;
  var reportingException = false;

  function domString(value) {
    if (typeof value === "symbol") throw new TypeError("cannot convert a Symbol to a string");
    return String(value);
  }

  function dictionary(value) {
    return value == null ? {} : Object(value);
  }

  function eventState(event) {
    var state = eventStates.get(event);
    if (!state) throw new TypeError("Illegal invocation");
    return state;
  }

  function targetState(target) {
    var state = targetStates.get(target);
    if (!state) throw new TypeError("Illegal invocation");
    return state;
  }

  function isTrusted() {
    return eventState(this).trusted;
  }

  function initializeEvent(event, type, init) {
    init = dictionary(init);
    eventStates.set(event, {
      type: domString(type),
      bubbles: !!init.bubbles,
      cancelable: !!init.cancelable,
      composed: !!init.composed,
      canceled: false,
      stop: false,
      stopImmediate: false,
      passive: false,
      dispatching: false,
      target: null,
      currentTarget: null,
      phase: 0,
      path: [],
      trusted: false,
      timeStamp: global.performance && typeof global.performance.now === "function"
        ? global.performance.now()
        : Date.now()
    });
    // Web IDL's [LegacyUnforgeable] isTrusted is an own accessor. Keep the
    // getter shared across instances, as the platform descriptor requires.
    Object.defineProperty(event, "isTrusted", {
      get: isTrusted,
      enumerable: true
    });
    brand(event, "Event");
  }

  function Event(type, init) {
    if (!new.target) throw new TypeError("Event requires new");
    if (arguments.length === 0) throw new TypeError("Event requires a type");
    initializeEvent(this, type, init);
  }

  Object.defineProperties(Event.prototype, {
    type: { get: function () { return eventState(this).type; }, enumerable: true },
    target: { get: function () { return eventState(this).target; }, enumerable: true },
    srcElement: { get: function () { return eventState(this).target; }, enumerable: true },
    currentTarget: { get: function () { return eventState(this).currentTarget; }, enumerable: true },
    eventPhase: { get: function () { return eventState(this).phase; }, enumerable: true },
    bubbles: { get: function () { return eventState(this).bubbles; }, enumerable: true },
    cancelable: { get: function () { return eventState(this).cancelable; }, enumerable: true },
    defaultPrevented: { get: function () { return eventState(this).canceled; }, enumerable: true },
    composed: { get: function () { return eventState(this).composed; }, enumerable: true },
    timeStamp: { get: function () { return eventState(this).timeStamp; }, enumerable: true },
    cancelBubble: {
      get: function () { return eventState(this).stop; },
      set: function (value) { if (value) eventState(this).stop = true; },
      enumerable: true
    },
    returnValue: {
      get: function () { return !eventState(this).canceled; },
      set: function (value) { if (!value) this.preventDefault(); },
      enumerable: true
    }
  });
  Event.prototype.preventDefault = function () {
    var state = eventState(this);
    if (state.cancelable && !state.passive) state.canceled = true;
  };
  Event.prototype.stopPropagation = function () { eventState(this).stop = true; };
  Event.prototype.stopImmediatePropagation = function () {
    var state = eventState(this);
    state.stop = true;
    state.stopImmediate = true;
  };
  Event.prototype.composedPath = function () { return eventState(this).path.slice(); };
  Event.prototype.initEvent = function (type, bubbles, cancelable) {
    var state = eventState(this);
    if (state.dispatching) return;
    state.type = domString(type);
    state.bubbles = !!bubbles;
    state.cancelable = !!cancelable;
    state.composed = false;
    state.canceled = false;
    state.stop = false;
    state.stopImmediate = false;
    state.passive = false;
    state.target = null;
    state.currentTarget = null;
    state.phase = Event.NONE;
    state.path = [];
    state.trusted = false;
  };

  [["NONE", 0], ["CAPTURING_PHASE", 1], ["AT_TARGET", 2], ["BUBBLING_PHASE", 3]]
    .forEach(function (entry) {
      Object.defineProperty(Event, entry[0], { value: entry[1], enumerable: true });
      Object.defineProperty(Event.prototype, entry[0], { value: entry[1], enumerable: true });
    });

  function inherit(constructor) {
    constructor.prototype = Object.create(Event.prototype, {
      constructor: { value: constructor, writable: true, configurable: true }
    });
  }

  function CustomEvent(type, init) {
    if (!new.target) throw new TypeError("CustomEvent requires new");
    if (arguments.length === 0) throw new TypeError("CustomEvent requires a type");
    init = dictionary(init);
    initializeEvent(this, type, init);
    eventState(this).detail = "detail" in init ? init.detail : null;
  }
  inherit(CustomEvent);
  Object.defineProperty(CustomEvent.prototype, "detail", {
    get: function () { return eventState(this).detail; }, enumerable: true
  });
  CustomEvent.prototype.initCustomEvent = function (type, bubbles, cancelable, detail) {
    var state = eventState(this);
    if (state.dispatching) return;
    this.initEvent(type, bubbles, cancelable);
    state.detail = detail;
  };

  function ErrorEvent(type, init) {
    if (!new.target) throw new TypeError("ErrorEvent requires new");
    if (arguments.length === 0) throw new TypeError("ErrorEvent requires a type");
    init = dictionary(init);
    initializeEvent(this, type, init);
    var state = eventState(this);
    state.message = "message" in init ? domString(init.message) : "";
    state.filename = "filename" in init ? domString(init.filename) : "";
    state.lineno = "lineno" in init ? Number(init.lineno) >>> 0 : 0;
    state.colno = "colno" in init ? Number(init.colno) >>> 0 : 0;
    state.error = "error" in init ? init.error : null;
  }
  inherit(ErrorEvent);
  Object.defineProperties(ErrorEvent.prototype, {
    message: { get: function () { return eventState(this).message; }, enumerable: true },
    filename: { get: function () { return eventState(this).filename; }, enumerable: true },
    lineno: { get: function () { return eventState(this).lineno; }, enumerable: true },
    colno: { get: function () { return eventState(this).colno; }, enumerable: true },
    error: { get: function () { return eventState(this).error; }, enumerable: true }
  });

  function MessageEvent(type, init) {
    if (!new.target) throw new TypeError("MessageEvent requires new");
    if (arguments.length === 0) throw new TypeError("MessageEvent requires a type");
    init = dictionary(init);
    initializeEvent(this, type, init);
    var state = eventState(this);
    state.data = "data" in init ? init.data : null;
    state.origin = "origin" in init ? domString(init.origin) : "";
    state.lastEventId = "lastEventId" in init ? domString(init.lastEventId) : "";
    state.source = "source" in init ? init.source : null;
    state.ports = "ports" in init ? Array.from(init.ports) : [];
  }
  inherit(MessageEvent);
  Object.defineProperties(MessageEvent.prototype, {
    data: { get: function () { return eventState(this).data; }, enumerable: true },
    origin: { get: function () { return eventState(this).origin; }, enumerable: true },
    lastEventId: { get: function () { return eventState(this).lastEventId; }, enumerable: true },
    source: { get: function () { return eventState(this).source; }, enumerable: true },
    ports: { get: function () { return eventState(this).ports.slice(); }, enumerable: true }
  });
  MessageEvent.prototype.initMessageEvent = function (
      type, bubbles, cancelable, data, origin, lastEventId, source, ports) {
    var state = eventState(this);
    if (state.dispatching) return;
    this.initEvent(type, bubbles, cancelable);
    state.data = data;
    state.origin = domString(origin);
    state.lastEventId = domString(lastEventId);
    state.source = source == null ? null : source;
    state.ports = ports == null ? [] : Array.from(ports);
  };

  function CloseEvent(type, init) {
    if (!new.target) throw new TypeError("CloseEvent requires new");
    if (arguments.length === 0) throw new TypeError("CloseEvent requires a type");
    init = dictionary(init);
    initializeEvent(this, type, init);
    var state = eventState(this);
    state.wasClean = !!init.wasClean;
    state.code = "code" in init ? Number(init.code) & 0xffff : 0;
    state.reason = "reason" in init ? domString(init.reason) : "";
  }
  inherit(CloseEvent);
  Object.defineProperties(CloseEvent.prototype, {
    wasClean: { get: function () { return eventState(this).wasClean; }, enumerable: true },
    code: { get: function () { return eventState(this).code; }, enumerable: true },
    reason: { get: function () { return eventState(this).reason; }, enumerable: true }
  });

  function PromiseRejectionEvent(type, init) {
    if (!new.target) throw new TypeError("PromiseRejectionEvent requires new");
    if (arguments.length < 2 || init == null || !("promise" in Object(init))) {
      throw new TypeError("PromiseRejectionEvent requires a promise");
    }
    init = Object(init);
    initializeEvent(this, type, init);
    var state = eventState(this);
    state.promise = init.promise;
    state.reason = init.reason;
  }
  inherit(PromiseRejectionEvent);
  Object.defineProperties(PromiseRejectionEvent.prototype, {
    promise: { get: function () { return eventState(this).promise; }, enumerable: true },
    reason: { get: function () { return eventState(this).reason; }, enumerable: true }
  });

  function EventTarget() {
    if (!new.target) throw new TypeError("EventTarget requires new");
    targetStates.set(this, { listeners: [] });
    brand(this, "EventTarget");
  }

  function captureOf(options) {
    return typeof options === "boolean" ? options : !!(options && options.capture);
  }

  function removeEntry(target, entry) {
    var listeners = targetState(target).listeners;
    var index = listeners.indexOf(entry);
    if (index < 0) return;
    entry.removed = true;
    listeners.splice(index, 1);
    if (entry.abortRelease) {
      var release = entry.abortRelease;
      entry.abortRelease = null;
      release();
    }
  }

  EventTarget.prototype.addEventListener = function (type, callback, options) {
    var target = this;
    var state = targetState(target);
    type = domString(type);
    var capture = captureOf(options);
    var once = !!(options && typeof options !== "boolean" && options.once);
    var passive = !!(options && typeof options !== "boolean" && options.passive);
    var signal = options && typeof options !== "boolean" ? options.signal : undefined;
    if (signal !== undefined) {
      if (typeof global.AbortSignal !== "function" || !(signal instanceof global.AbortSignal)) {
        throw new TypeError("signal is not an AbortSignal");
      }
      if (signal.aborted) return;
    }
    if (callback == null) return;
    if (typeof callback !== "function" && typeof callback !== "object") {
      throw new TypeError("event listener must be a function or object");
    }
    if (state.listeners.some(function (entry) {
      return !entry.removed && entry.type === type && entry.callback === callback && entry.capture === capture;
    })) return;
    var entry = { type: type, callback: callback, capture: capture, once: once,
      passive: passive, abortRelease: null, removed: false };
    state.listeners.push(entry);
    if (signal !== undefined) {
      if (typeof abortSubscribe !== "function") {
        removeEntry(target, entry);
        throw new TypeError("AbortSignal hooks are unavailable");
      }
      // @ref LLP 0057.000#l3--events-abort-and-the-second-direction — signal-bound listener removal is an abort algorithm, before abort event dispatch
      entry.abortRelease = abortSubscribe(signal, function () { removeEntry(target, entry); });
    }
  };

  EventTarget.prototype.removeEventListener = function (type, callback, options) {
    var target = this;
    var state = targetState(target);
    type = domString(type);
    var capture = captureOf(options);
    for (var i = 0; i < state.listeners.length; i++) {
      var entry = state.listeners[i];
      if (!entry.removed && entry.type === type && entry.callback === callback && entry.capture === capture) {
        removeEntry(target, entry);
        return;
      }
    }
  };

  function invoke(target, event, capture) {
    var state = eventState(event);
    var listeners = targetState(target).listeners.slice();
    for (var i = 0; i < listeners.length; i++) {
      var entry = listeners[i];
      if (state.stopImmediate) break;
      if (entry.removed || entry.type !== state.type || entry.capture !== capture) continue;
      if (entry.once) removeEntry(target, entry);
      state.passive = entry.passive;
      try {
        if (typeof entry.callback === "function") entry.callback.call(target, event);
        else {
          var handleEvent = entry.callback.handleEvent;
          if (typeof handleEvent === "function") handleEvent.call(entry.callback, event);
        }
      } catch (error) {
        reportException(error);
      }
      state.passive = false;
    }
  }

  // @ref LLP 0057.000#l3--events-abort-and-the-second-direction — only the captured host path may assert event trust
  function dispatch(target, event, trusted) {
    targetState(target);
    var state = eventState(event);
    if (state.dispatching) {
      throw new DOMException("The event is already being dispatched", "InvalidStateError");
    }
    state.trusted = trusted;
    state.dispatching = true;
    state.target = target;
    state.currentTarget = target;
    state.phase = Event.AT_TARGET;
    state.path = [target];
    try {
      invoke(target, event, true);
      // @ref LLP 0057.000#l3--events-abort-and-the-second-direction — at-target capture and bubble remain distinct propagation phases
      if (!state.stop) invoke(target, event, false);
      return !state.canceled;
    } finally {
      state.currentTarget = null;
      state.phase = Event.NONE;
      state.path = [];
      state.dispatching = false;
      state.stop = false;
      state.stopImmediate = false;
      state.passive = false;
    }
  }

  EventTarget.prototype.dispatchEvent = function (event) {
    // Public redispatch is always application dispatch, even when the event
    // was originally created and fired by the host.
    return dispatch(this, event, false);
  };

  function errorText(error) {
    try {
      if (error && typeof error.stack === "string") return error.stack;
      if (error && typeof error.message === "string") return error.message;
      return domString(error);
    } catch (_) {
      return "uncaught error";
    }
  }

  function reportException(error) {
    var text = errorText(error);
    if (reportingException) {
      nativeReport(text);
      return;
    }
    reportingException = true;
    try {
      var event = new ErrorEvent("error", {
        cancelable: true,
        message: error && typeof error.message === "string" ? error.message : text,
        error: error
      });
      if (dispatch(global, event, true)) nativeReport(text);
    } finally {
      reportingException = false;
    }
  }

  function reportError(error) {
    reportException(error);
  }

  function fireTrustedEvent(target, event) {
    return dispatch(target, event, true);
  }

  function setAbortHooks(hooks) {
    if (!hooks || typeof hooks.subscribe !== "function") {
      throw new TypeError("invalid AbortSignal hooks");
    }
    abortSubscribe = hooks.subscribe;
  }

  function defineEventHandler(name, type, errorHandler) {
    var callback = null;
    var wrapper = null;
    Object.defineProperty(global, name, {
      configurable: true,
      enumerable: true,
      get: function () { return callback; },
      set: function (value) {
        if (wrapper) EventTarget.prototype.removeEventListener.call(global, type, wrapper);
        callback = typeof value === "function" ? value : null;
        wrapper = null;
        if (!callback) return;
        wrapper = function (event) {
          var result = errorHandler
            ? callback.call(global, event.message, event.filename, event.lineno, event.colno, event.error)
            : callback.call(global, event);
          if ((errorHandler && result === true) || (!errorHandler && result === false)) {
            event.preventDefault();
          }
        };
        EventTarget.prototype.addEventListener.call(global, type, wrapper);
      }
    });
  }

  // @ref LLP 0057.000#l3--events-abort-and-the-second-direction — keep the engine global's prototype intact; only its private target record is new
  targetStates.set(global, { listeners: [] });
  global.Event = Event;
  global.EventTarget = EventTarget;
  global.CustomEvent = CustomEvent;
  global.ErrorEvent = ErrorEvent;
  global.MessageEvent = MessageEvent;
  global.CloseEvent = CloseEvent;
  global.PromiseRejectionEvent = PromiseRejectionEvent;
  global.reportError = reportError;
  global.self = global;
  global.navigator = Object.freeze({ userAgent: "Ibex/0.1.0" });
  global.addEventListener = function () {
    return EventTarget.prototype.addEventListener.apply(global, arguments);
  };
  global.removeEventListener = function () {
    return EventTarget.prototype.removeEventListener.apply(global, arguments);
  };
  global.dispatchEvent = function () {
    return EventTarget.prototype.dispatchEvent.apply(global, arguments);
  };
  defineEventHandler("onerror", "error", true);
  defineEventHandler("onunhandledrejection", "unhandledrejection", false);
  defineEventHandler("onrejectionhandled", "rejectionhandled", false);

  if (typeof Symbol === "function" && Symbol.toStringTag) {
    [[Event, "Event"], [EventTarget, "EventTarget"], [CustomEvent, "CustomEvent"],
     [ErrorEvent, "ErrorEvent"], [MessageEvent, "MessageEvent"],
     [CloseEvent, "CloseEvent"], [PromiseRejectionEvent, "PromiseRejectionEvent"]]
      .forEach(function (entry) {
        Object.defineProperty(entry[0].prototype, Symbol.toStringTag, {
          value: entry[1], configurable: true
        });
      });
  }

  return {
    reportException: reportException,
    fireTrustedEvent: fireTrustedEvent,
    setAbortHooks: setAbortHooks,
    onUnhandled: function (_, reason, promise) {
      var event = new PromiseRejectionEvent("unhandledrejection", {
        cancelable: true, promise: promise, reason: reason
      });
      if (dispatch(global, event, true)) nativeReport(errorText(reason));
    },
    onHandled: function (_, reason, promise) {
      dispatch(global,
        new PromiseRejectionEvent("rejectionhandled", { promise: promise, reason: reason }), true);
    }
  };
})(globalThis);
