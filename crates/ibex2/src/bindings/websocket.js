// WHATWG WebSocket over the Rust WebSocket library and L3 event subscription.
(function (global) {
  "use strict";

  var hooks = global.__ibex2_websocket;
  var fireTrustedEvent = global.__ibex2_fire_trusted_event;
  delete global.__ibex2_websocket;
  delete global.__ibex2_fire_trusted_event;
  if (!hooks || typeof hooks.open !== "function" ||
      typeof fireTrustedEvent !== "function") {
    throw new Error("WebSocket native hooks are unavailable");
  }

  var states = new WeakMap();
  var decoder = new TextDecoder();
  var token = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

  function domString(value) {
    if (typeof value === "symbol") throw new TypeError("cannot convert a Symbol to a string");
    return String(value);
  }

  function stateOf(socket) {
    var state = states.get(socket);
    if (!state) throw new TypeError("Illegal invocation");
    return state;
  }

  function syntax(message) {
    return new DOMException(message, "SyntaxError");
  }

  // Web IDL's [Clamp] unsigned short conversion (including ties-to-even).
  function closeCodeValue(value) {
    var number = Number(value);
    if (Number.isNaN(number) || number <= 0) return 0;
    if (number >= 65535) return 65535;
    var lower = Math.floor(number);
    var fraction = number - lower;
    if (fraction < 0.5) return lower;
    if (fraction > 0.5) return lower + 1;
    return lower % 2 === 0 ? lower : lower + 1;
  }

  function parseURL(value) {
    var parsed;
    try {
      parsed = new URL(domString(value));
    } catch (_) {
      throw syntax("The WebSocket URL is invalid");
    }
    if (parsed.protocol === "http:") parsed.protocol = "ws:";
    else if (parsed.protocol === "https:") parsed.protocol = "wss:";
    if (parsed.protocol !== "ws:" && parsed.protocol !== "wss:") {
      throw syntax("The WebSocket URL must use ws: or wss:");
    }
    if (parsed.href.indexOf("#") !== -1) {
      throw syntax("The WebSocket URL must not contain a fragment");
    }
    if (parsed.username || parsed.password) {
      throw syntax("The WebSocket URL must not contain credentials");
    }
    return parsed;
  }

  function protocolList(value, present) {
    if (!present || value === undefined) return [];
    var values = typeof value === "string" ? [value] : Array.from(value);
    var result = [];
    for (var i = 0; i < values.length; i++) {
      var protocol = domString(values[i]);
      if (!token.test(protocol)) throw syntax("A WebSocket protocol is not an HTTP token");
      if (result.some(function (other) {
        return other.toLowerCase() === protocol.toLowerCase();
      })) {
        throw syntax("WebSocket protocols must not contain duplicates");
      }
      result.push(protocol);
    }
    return result;
  }

  function text(packet, offset) {
    return decoder.decode(new Uint8Array(packet, offset));
  }

  function binary(packet) {
    return packet.slice(1);
  }

  function receive(socket, packet) {
    var state = stateOf(socket);
    var bytes = new Uint8Array(packet);
    var kind = bytes[0];
    if (kind === 0) {
      state.protocol = text(packet, 1);
      state.readyState = 1;
      fireTrustedEvent(socket, new Event("open"));
      return;
    }
    if (kind === 1) {
      fireTrustedEvent(socket, new MessageEvent("message", {
        data: text(packet, 1), origin: state.origin
      }));
      return;
    }
    if (kind === 2) {
      var data = binary(packet);
      // Blob is a later install group (LLP 0057.000 L6). Until it is selected,
      // the documented fallback for binaryType="blob" is an ArrayBuffer.
      if (state.binaryType === "blob" && typeof global.Blob === "function") {
        data = new global.Blob([data]);
      }
      fireTrustedEvent(socket, new MessageEvent("message", {
        data: data, origin: state.origin
      }));
      return;
    }
    if (kind === 3) {
      fireTrustedEvent(socket, new Event("error"));
      return;
    }
    if (kind === 4) {
      state.readyState = 3;
      fireTrustedEvent(socket, new CloseEvent("close", {
        wasClean: bytes[1] !== 0,
        code: (bytes[2] << 8) | bytes[3],
        reason: text(packet, 4)
      }));
    }
  }

  function WebSocket(url, protocols) {
    if (!new.target) throw new TypeError("WebSocket requires new");
    if (arguments.length === 0) throw new TypeError("WebSocket requires a URL");
    if (!hooks.supported) {
      throw new DOMException("WebSocket was omitted from this build", "NotSupportedError");
    }
    var parsed = parseURL(url);
    var offered = protocolList(protocols, arguments.length > 1);
    var socket = Reflect.construct(EventTarget, [], new.target);
    var state = {
      handle: 0,
      url: parsed.href,
      origin: parsed.origin,
      protocol: "",
      binaryType: "blob",
      readyState: 0,
      handlers: Object.create(null)
    };
    states.set(socket, state);
    state.handle = hooks.open(socket, function (packet) {
      receive(socket, packet);
    }, state.url, offered.join("\n"));
    return socket;
  }

  WebSocket.prototype = Object.create(EventTarget.prototype, {
    constructor: { value: WebSocket, writable: true, configurable: true },
    url: { get: function () { return stateOf(this).url; }, enumerable: true },
    readyState: {
      get: function () { return stateOf(this).readyState; }, enumerable: true
    },
    bufferedAmount: {
      get: function () {
        var state = stateOf(this);
        return hooks.bufferedAmount(state.handle);
      }, enumerable: true
    },
    extensions: { get: function () { stateOf(this); return ""; }, enumerable: true },
    protocol: { get: function () { return stateOf(this).protocol; }, enumerable: true },
    binaryType: {
      get: function () { return stateOf(this).binaryType; },
      set: function (value) {
        var state = stateOf(this);
        value = domString(value);
        if (value === "blob" || value === "arraybuffer") state.binaryType = value;
      },
      enumerable: true
    }
  });

  WebSocket.prototype.send = function (data) {
    var state = stateOf(this);
    if (state.readyState === WebSocket.CONNECTING) {
      throw new DOMException("The WebSocket is still connecting", "InvalidStateError");
    }
    if (data instanceof ArrayBuffer) {
      hooks.sendBinary(state.handle, data);
      return;
    }
    if (typeof ArrayBuffer.isView === "function" && ArrayBuffer.isView(data)) {
      hooks.sendBinary(state.handle,
        new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
      return;
    }
    if (typeof global.Blob === "function" && data instanceof global.Blob) {
      throw new DOMException("Blob WebSocket send is unavailable", "NotSupportedError");
    }
    hooks.sendText(state.handle, domString(data));
  };

  WebSocket.prototype.close = function (code, reason) {
    var state = stateOf(this);
    var closeCode = 0;
    if (arguments.length > 0 && code !== undefined) {
      closeCode = closeCodeValue(code);
      if (closeCode !== 1000 && (closeCode < 3000 || closeCode > 4999)) {
        throw new DOMException("The close code is not allowed", "InvalidAccessError");
      }
    }
    var closeReason = arguments.length > 1 ? domString(reason) : "";
    if (closeCode === 0 && closeReason !== "") {
      throw syntax("A close reason requires a close code");
    }
    if (new TextEncoder().encode(closeReason).byteLength > 123) {
      throw syntax("The close reason exceeds 123 UTF-8 bytes");
    }
    if (state.readyState === WebSocket.CLOSING || state.readyState === WebSocket.CLOSED) return;
    state.readyState = WebSocket.CLOSING;
    hooks.close(state.handle, closeCode, closeReason);
  };

  ["open", "message", "error", "close"].forEach(function (type) {
    Object.defineProperty(WebSocket.prototype, "on" + type, {
      get: function () { return stateOf(this).handlers[type] || null; },
      set: function (value) {
        var state = stateOf(this);
        var previous = state.handlers[type];
        if (previous) this.removeEventListener(type, previous);
        if (typeof value === "function") {
          state.handlers[type] = value;
          this.addEventListener(type, value);
        } else {
          delete state.handlers[type];
        }
      },
      enumerable: true,
      configurable: true
    });
  });

  [["CONNECTING", 0], ["OPEN", 1], ["CLOSING", 2], ["CLOSED", 3]]
    .forEach(function (entry) {
      Object.defineProperty(WebSocket, entry[0], { value: entry[1], enumerable: true });
      Object.defineProperty(WebSocket.prototype, entry[0], { value: entry[1], enumerable: true });
    });
  if (typeof Symbol === "function" && Symbol.toStringTag) {
    Object.defineProperty(WebSocket.prototype, Symbol.toStringTag, {
      value: "WebSocket", configurable: true
    });
  }
  global.WebSocket = WebSocket;
})(globalThis);
