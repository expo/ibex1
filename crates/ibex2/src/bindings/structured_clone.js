// The HTML structured clone algorithm over the value space Hermes exposes.
// @ref LLP 0059.000#310-atob--btoa-structuredclone-blob-customevent--pure-ungated — clone stays inside the engine and v1 refuses transfer
(function (global) {
  "use strict";

  // Capture every intrinsic the clone uses while bootstrap still owns the
  // realm. Application changes after this point cannot redirect traversal,
  // brand checks, allocation, or collection mutation.
  var FunctionCall = Function.prototype.call;
  var FunctionBind = Function.prototype.bind;
  function uncurry(fn) { return FunctionCall.call(FunctionBind, FunctionCall, fn); }

  var ObjectCtor = Object;
  var ObjectPrototype = Object.prototype;
  var objectKeys = Object.keys;
  var objectGetPrototypeOf = Object.getPrototypeOf;
  var objectDefineProperty = Object.defineProperty;
  var objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  var objectHasOwn = uncurry(Object.prototype.hasOwnProperty);
  var objectIsPrototypeOf = uncurry(Object.prototype.isPrototypeOf);

  var ArrayCtor = Array;
  var arrayIsArray = Array.isArray;
  var arrayFrom = Array.from;
  var arrayBufferIsView = ArrayBuffer.isView;

  var MapCtor = Map;
  var mapHas = uncurry(Map.prototype.has);
  var mapGet = uncurry(Map.prototype.get);
  var mapSet = uncurry(Map.prototype.set);
  var mapForEach = uncurry(Map.prototype.forEach);
  var SetCtor = Set;
  var setHas = uncurry(Set.prototype.has);
  var setAdd = uncurry(Set.prototype.add);
  var setForEach = uncurry(Set.prototype.forEach);

  var WeakMapCtor = WeakMap;
  var weakMapHas = uncurry(WeakMap.prototype.has);
  var WeakSetCtor = WeakSet;
  var weakSetHas = uncurry(WeakSet.prototype.has);
  var weakRefDeref = typeof WeakRef === "function" ? uncurry(WeakRef.prototype.deref) : null;
  var registryUnregister = typeof FinalizationRegistry === "function"
    ? uncurry(FinalizationRegistry.prototype.unregister) : null;
  var PromisePrototype = Promise.prototype;

  var ArrayBufferCtor = ArrayBuffer;
  var arrayBufferLength = uncurry(
    Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength").get
  );
  var Uint8ArrayCtor = Uint8Array;
  var typedArraySet = uncurry(Uint8Array.prototype.set);
  var TypedArrayPrototype = objectGetPrototypeOf(Uint8Array.prototype);
  var typedArrayTag = uncurry(
    Object.getOwnPropertyDescriptor(TypedArrayPrototype, Symbol.toStringTag).get
  );
  var typedArrayBuffer = uncurry(
    Object.getOwnPropertyDescriptor(TypedArrayPrototype, "buffer").get
  );
  var typedArrayOffset = uncurry(
    Object.getOwnPropertyDescriptor(TypedArrayPrototype, "byteOffset").get
  );
  var typedArrayLength = uncurry(
    Object.getOwnPropertyDescriptor(TypedArrayPrototype, "length").get
  );
  var DataViewCtor = DataView;
  var dataViewBuffer = uncurry(
    Object.getOwnPropertyDescriptor(DataView.prototype, "buffer").get
  );
  var dataViewOffset = uncurry(
    Object.getOwnPropertyDescriptor(DataView.prototype, "byteOffset").get
  );
  var dataViewLength = uncurry(
    Object.getOwnPropertyDescriptor(DataView.prototype, "byteLength").get
  );

  var typedArrayConstructors = {};
  ["Int8Array", "Uint8Array", "Uint8ClampedArray", "Int16Array",
   "Uint16Array", "Int32Array", "Uint32Array", "Float32Array",
   "Float64Array", "BigInt64Array", "BigUint64Array", "Float16Array"]
    .forEach(function (name) {
      if (typeof global[name] === "function") typedArrayConstructors[name] = global[name];
    });

  var DateCtor = Date;
  var dateValue = uncurry(Date.prototype.valueOf);
  var RegExpCtor = RegExp;
  var regexpSource = uncurry(
    Object.getOwnPropertyDescriptor(RegExp.prototype, "source").get
  );
  var regexpFlagNames = [
    ["hasIndices", "d"], ["global", "g"], ["ignoreCase", "i"],
    ["multiline", "m"], ["dotAll", "s"], ["unicode", "u"],
    ["unicodeSets", "v"], ["sticky", "y"]
  ];
  var regexpFlags = [];
  regexpFlagNames.forEach(function (entry) {
    var descriptor = Object.getOwnPropertyDescriptor(RegExp.prototype, entry[0]);
    if (descriptor && descriptor.get) regexpFlags.push([uncurry(descriptor.get), entry[1]]);
  });

  var booleanValue = uncurry(Boolean.prototype.valueOf);
  var numberValue = uncurry(Number.prototype.valueOf);
  var stringValue = uncurry(String.prototype.valueOf);
  var bigintValue = typeof BigInt === "function" ? uncurry(BigInt.prototype.valueOf) : null;
  var symbolValue = uncurry(Symbol.prototype.valueOf);

  var errorIsError = Error.isError;
  var errorConstructors = {
    Error: Error,
    EvalError: EvalError,
    RangeError: RangeError,
    ReferenceError: ReferenceError,
    SyntaxError: SyntaxError,
    TypeError: TypeError,
    URIError: URIError
  };
  var StringCtor = String;
  var DOMExceptionCtor = global.DOMException;
  var unsupportedPrototypes = [];
  function rejectPrototype(type) {
    if (typeof type === "function" && type.prototype) unsupportedPrototypes.push(type.prototype);
  }
  [Boolean, Number, String, Symbol, Date, RegExp, Map, Set, WeakMapCtor,
   WeakSetCtor, Promise, ArrayBufferCtor, DataViewCtor, Error, EvalError,
   RangeError, ReferenceError, SyntaxError, TypeError, URIError]
    .forEach(rejectPrototype);
  if (typeof BigInt === "function") rejectPrototype(BigInt);
  if (typeof WeakRef === "function") rejectPrototype(WeakRef);
  if (typeof FinalizationRegistry === "function") rejectPrototype(FinalizationRegistry);
  rejectPrototype(global.SharedArrayBuffer);
  Object.keys(typedArrayConstructors).forEach(function (name) {
    rejectPrototype(typedArrayConstructors[name]);
  });

  // These bindings use private WeakMap/WeakSet state. Their captured getters
  // and methods are the available internal-slot checks; no application-owned
  // prototype getter participates.
  var hostBrandChecks = [];
  function addGetterBrand(type, key) {
    if (typeof type !== "function") return;
    var descriptor = Object.getOwnPropertyDescriptor(type.prototype, key);
    if (descriptor && descriptor.get) {
      var get = uncurry(descriptor.get);
      hostBrandChecks.push(function (value) { get(value); });
    }
  }
  function addMethodBrand(type, key, argument) {
    if (typeof type !== "function" || typeof type.prototype[key] !== "function") return;
    var method = uncurry(type.prototype[key]);
    hostBrandChecks.push(function (value) { method(value, argument); });
  }
  addGetterBrand(global.DOMException, "message");
  addGetterBrand(global.QuotaExceededError, "quota");
  addMethodBrand(global.Headers, "has", "x-ibex-structured-clone-brand");
  addGetterBrand(global.URL, "href");
  addMethodBrand(global.URLSearchParams, "has", "x-ibex-structured-clone-brand");
  addGetterBrand(global.AbortSignal, "aborted");
  addGetterBrand(global.AbortController, "signal");
  [global.DOMException, global.QuotaExceededError, global.Headers, global.URL,
   global.URLSearchParams, global.AbortSignal, global.AbortController, global.Crypto,
   global.CryptoKey, global.Request, global.Response, global.Blob, global.File,
   global.ImageData].forEach(rejectPrototype);
  var cryptoObject = global.crypto;
  var platformTags = {
    AbortController: true, AbortSignal: true, Blob: true, Crypto: true,
    CryptoKey: true, DOMException: true, File: true, FileList: true,
    Headers: true, ImageBitmap: true, ImageData: true, Request: true,
    Response: true, URL: true, URLSearchParams: true
  };

  function dataCloneError(message) {
    throw new DOMExceptionCtor(message, "DataCloneError");
  }

  function hasBrand(check, value) {
    try { check(value); return true; } catch (_) { return false; }
  }

  function isUnsupportedHostObject(value) {
    if (value === cryptoObject) return true;
    for (var i = 0; i < hostBrandChecks.length; i++) {
      if (hasBrand(hostBrandChecks[i], value)) return true;
    }
    // Some exposed objects (notably Response) have constructors private to a
    // binding closure. Their built-in toStringTag is a data property, so walk
    // descriptors without invoking an application getter.
    var current = value;
    while (current !== null) {
      var descriptor;
      try { descriptor = objectGetOwnPropertyDescriptor(current, Symbol.toStringTag); }
      catch (_) { dataCloneError("Proxy objects cannot be cloned"); }
      if (descriptor) {
        return objectHasOwn(descriptor, "value") && platformTags[descriptor.value] === true;
      }
      try { current = objectGetPrototypeOf(current); }
      catch (_) { dataCloneError("Proxy objects cannot be cloned"); }
    }
    return false;
  }

  function copyArrayBuffer(source) {
    var result = new ArrayBufferCtor(arrayBufferLength(source));
    typedArraySet(new Uint8ArrayCtor(result), new Uint8ArrayCtor(source));
    return result;
  }

  function tryBoxed(valueOf, value) {
    if (!valueOf) return null;
    try { return { value: valueOf(value) }; } catch (_) { return null; }
  }

  function cloneError(value, memory) {
    var name = StringCtor(value.name);
    if (!objectHasOwn(errorConstructors, name)) name = "Error";
    var hasMessage = objectHasOwn(value, "message");
    var result = hasMessage
      ? new errorConstructors[name](StringCtor(value.message))
      : new errorConstructors[name]();
    mapSet(memory, value, result);
    if (objectHasOwn(value, "cause")) {
      objectDefineProperty(result, "cause", {
        value: cloneAny(value.cause, memory),
        writable: true, configurable: true
      });
    }
    if (objectHasOwn(value, "stack")) {
      objectDefineProperty(result, "stack", {
        value: StringCtor(value.stack), writable: true, configurable: true
      });
    }
    return result;
  }

  function cloneObject(value, memory) {
    if (mapHas(memory, value)) return mapGet(memory, value);

    // Values whose prototype can look ordinary but whose data lives in engine
    // slots are classified before the ordinary-object path.
    var boxed = tryBoxed(booleanValue, value);
    if (boxed) {
      var boxedBoolean = new Boolean(boxed.value);
      mapSet(memory, value, boxedBoolean);
      return boxedBoolean;
    }
    boxed = tryBoxed(numberValue, value);
    if (boxed) {
      var boxedNumber = new Number(boxed.value);
      mapSet(memory, value, boxedNumber);
      return boxedNumber;
    }
    boxed = tryBoxed(stringValue, value);
    if (boxed) {
      var boxedString = new String(boxed.value);
      mapSet(memory, value, boxedString);
      return boxedString;
    }
    boxed = tryBoxed(bigintValue, value);
    if (boxed) {
      var boxedBigInt = ObjectCtor(boxed.value);
      mapSet(memory, value, boxedBigInt);
      return boxedBigInt;
    }
    if (hasBrand(symbolValue, value)) dataCloneError("Symbol objects cannot be cloned");

    if (arrayIsArray(value)) {
      // Array.isArray also returns true for a non-revoked Proxy around an
      // array. JavaScript exposes no general Proxy predicate; those proxies
      // are the documented detection limit of this engine-side shim.
      var arrayResult = new ArrayCtor(value.length);
      mapSet(memory, value, arrayResult);
      cloneEnumerableProperties(value, arrayResult, memory);
      return arrayResult;
    }

    if (hasBrand(arrayBufferLength, value)) {
      var bufferResult = copyArrayBuffer(value);
      mapSet(memory, value, bufferResult);
      return bufferResult;
    }

    if (arrayBufferIsView(value)) {
      if (hasBrand(dataViewLength, value)) {
        var clonedDataView = new DataViewCtor(
          cloneObject(dataViewBuffer(value), memory),
          dataViewOffset(value),
          dataViewLength(value)
        );
        mapSet(memory, value, clonedDataView);
        return clonedDataView;
      }
      var tag = typedArrayTag(value);
      var Type = typedArrayConstructors[tag];
      if (!Type) dataCloneError("Unsupported typed array");
      var clonedView = new Type(
        cloneObject(typedArrayBuffer(value), memory),
        typedArrayOffset(value),
        typedArrayLength(value)
      );
      mapSet(memory, value, clonedView);
      return clonedView;
    }

    if (hasBrand(mapHas, value)) {
      var mapResult = new MapCtor();
      mapSet(memory, value, mapResult);
      mapForEach(value, function (entryValue, entryKey) {
        mapSet(mapResult, cloneAny(entryKey, memory), cloneAny(entryValue, memory));
      });
      return mapResult;
    }

    if (hasBrand(setHas, value)) {
      var setResult = new SetCtor();
      mapSet(memory, value, setResult);
      setForEach(value, function (entryValue) {
        setAdd(setResult, cloneAny(entryValue, memory));
      });
      return setResult;
    }

    if (hasBrand(dateValue, value)) {
      var dateResult = new DateCtor(dateValue(value));
      mapSet(memory, value, dateResult);
      return dateResult;
    }

    if (hasBrand(regexpSource, value)) {
      var flags = "";
      for (var f = 0; f < regexpFlags.length; f++) {
        if (regexpFlags[f][0](value)) flags += regexpFlags[f][1];
      }
      var regexpResult = new RegExpCtor(regexpSource(value), flags);
      mapSet(memory, value, regexpResult);
      return regexpResult;
    }

    if (hasBrand(weakMapHas, value) || hasBrand(weakSetHas, value) ||
        hasBrand(weakRefDeref, value) || hasBrand(registryUnregister, value)) {
      dataCloneError("Weak collections and references cannot be cloned");
    }
    if (objectIsPrototypeOf(PromisePrototype, value)) {
      dataCloneError("Promise objects cannot be cloned");
    }
    if (isUnsupportedHostObject(value)) {
      dataCloneError("This platform object cannot be cloned");
    }

    if (errorIsError(value)) return cloneError(value, memory);

    var prototype;
    try { prototype = objectGetPrototypeOf(value); }
    catch (_) { dataCloneError("Proxy objects cannot be cloned"); }
    for (var p = 0; p < unsupportedPrototypes.length; p++) {
      if (objectIsPrototypeOf(unsupportedPrototypes[p], value)) {
        // A genuine supported branded object returned above. Reaching its
        // prototype here means a forged receiver or a detectable Proxy.
        dataCloneError("This built-in or platform object cannot be cloned");
      }
    }

    // Ordinary instances deserialize as plain objects. This intentionally
    // drops a user-defined or null prototype; only enumerable own string keys
    // cross the clone.
    var objectResult = {};
    mapSet(memory, value, objectResult);
    cloneEnumerableProperties(value, objectResult, memory);
    return objectResult;
  }

  function cloneEnumerableProperties(source, target, memory) {
    var keys = objectKeys(source);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      // Reading invokes an enumerable own getter exactly once. Defining a data
      // property avoids the legacy __proto__ setter and discards descriptors,
      // as StructuredSerialize/Deserialize requires.
      var cloned = cloneAny(source[key], memory);
      objectDefineProperty(target, key, {
        value: cloned, enumerable: true, writable: true, configurable: true
      });
    }
  }

  function cloneAny(value, memory) {
    var type = typeof value;
    if (type === "function") dataCloneError("Functions cannot be cloned");
    if (type === "symbol") dataCloneError("Symbols cannot be cloned");
    if (value === null || type !== "object") return value;
    return cloneObject(value, memory);
  }

  function structuredClone(value) {
    var options = arguments.length > 1 ? arguments[1] : undefined;
    if (options !== undefined && options !== null) {
      var transfer = options.transfer;
      if (transfer !== undefined) {
        var transferList = arrayFrom(transfer);
        if (transferList.length !== 0) {
          dataCloneError("transfer is not supported");
        }
      }
    }
    return cloneAny(value, new MapCtor());
  }

  global.structuredClone = structuredClone;
})(globalThis);
