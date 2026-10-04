//! The engine-side structured clone binding under the same freeze app code sees.
#![cfg(feature = "hermes")]

use ibex2::engine::hermes::{DynamicCode, Hermes};

fn check(body: &str) {
    let mut runtime = Hermes::new(DynamicCode::Closed).expect("runtime");
    assert!(runtime.install_stdlib());
    runtime.install_bindings().expect("bindings");
    runtime.harden().expect("harden");
    runtime
        .eval(&format!(
            r#"(function () {{
                function assert(value, message) {{
                    if (!value) throw new Error(message || "assertion failed");
                }}
                function dataCloneError(fn) {{
                    try {{ fn(); }} catch (error) {{
                        assert(error instanceof DOMException, "not a DOMException");
                        assert(error.name === "DataCloneError", "wrong error name: " + error.name);
                        return;
                    }}
                    throw new Error("expected DataCloneError");
                }}
                {body}
            }})()"#
        ))
        .unwrap_or_else(|error| panic!("{body}\n{error}"));
}

#[test]
fn primitives_wrappers_and_plain_objects_round_trip() {
    check(
        r#"
        const primitives = [undefined, null, true, false, 0, -0, 1.5, NaN,
          Infinity, -Infinity, "text", 123456789012345678901234567890n];
        for (const value of primitives) {
          const clone = structuredClone(value);
          assert(Object.is(clone, value), "primitive changed");
        }
        const wrappers = [new Boolean(true), new Number(-0), new String("hi"), Object(12n)];
        for (const value of wrappers) {
          const clone = structuredClone(value);
          assert(clone !== value, "wrapper identity kept");
          assert(clone.valueOf() === value.valueOf(), "wrapper value changed");
          assert(Object.getPrototypeOf(clone) === Object.getPrototypeOf(value), "wrapper brand changed");
        }
        let gets = 0;
        const source = { first: 1, get second() { gets++; return { nested: 2 }; } };
        Object.defineProperty(source, "hidden", { value: 3 });
        source[Symbol("ignored")] = 4;
        const clone = structuredClone(source);
        assert(clone !== source && clone.first === 1 && clone.second.nested === 2);
        assert(gets === 1, "getter count");
        assert(Object.keys(clone).join(",") === "first,second", "key order or selection");
        assert(Object.getPrototypeOf(clone) === Object.prototype, "plain prototype");
        const nullProto = Object.create(null); nullProto.x = 1;
        assert(Object.getPrototypeOf(structuredClone(nullProto)) === Object.prototype);
        "#,
    );
}

#[test]
fn arrays_keep_holes_length_properties_cycles_and_sharing() {
    check(
        r#"
        const array = new Array(5);
        array[1] = { x: 1 };
        array.extra = array[1];
        array.self = array;
        const clone = structuredClone(array);
        assert(clone !== array && clone.length === 5);
        assert(!(0 in clone) && (1 in clone) && !(2 in clone) && !(4 in clone), "holes changed");
        assert(clone[1] !== array[1] && clone.extra === clone[1], "sharing changed");
        assert(clone.self === clone, "cycle changed");
        const shared = { value: 1 };
        const graph = { a: shared, b: shared }; graph.graph = graph;
        const graphClone = structuredClone(graph);
        assert(graphClone.a === graphClone.b && graphClone.a !== shared);
        assert(graphClone.graph === graphClone);
        "#,
    );
}

#[test]
fn dates_regexps_maps_and_sets_keep_their_data_and_graph() {
    check(
        r#"
        const date = new Date(-123456789);
        const invalidDate = new Date(NaN);
        const regexp = /a+b/gi; regexp.lastIndex = 7;
        const key = { key: true };
        const map = new Map();
        const set = new Set();
        map.set(key, set); map.set("self", map); set.add(key); set.add(map);
        const source = { date, invalidDate, regexp, map, set };
        const clone = structuredClone(source);
        assert(clone.date !== date && clone.date.valueOf() === date.valueOf());
        assert(Number.isNaN(clone.invalidDate.valueOf()));
        assert(clone.regexp !== regexp && clone.regexp.source === regexp.source);
        assert(clone.regexp.flags === regexp.flags && clone.regexp.lastIndex === 0);
        const clonedKey = Array.from(clone.map.keys())[0];
        assert(clonedKey !== key && clonedKey.key === true);
        assert(clone.map.get(clonedKey) === clone.set);
        assert(clone.map.get("self") === clone.map);
        assert(clone.set.has(clonedKey) && clone.set.has(clone.map));
        "#,
    );
}

#[test]
fn buffers_views_and_every_available_typed_array_keep_bytes_and_aliasing() {
    check(
        r#"
        const names = ["Int8Array", "Uint8Array", "Uint8ClampedArray", "Int16Array",
          "Uint16Array", "Int32Array", "Uint32Array", "Float32Array", "Float64Array",
          "BigInt64Array", "BigUint64Array", "Float16Array"];
        for (const name of names) {
          const Type = globalThis[name];
          if (typeof Type !== "function") continue;
          const source = new Type(4);
          const bytes = new Uint8Array(source.buffer);
          for (let i = 0; i < bytes.length; i++) bytes[i] = i + 1;
          const clone = structuredClone(source);
          assert(Object.getPrototypeOf(clone) === Type.prototype, name + " brand");
          assert(clone !== source && clone.buffer !== source.buffer, name + " identity");
          assert(new Uint8Array(clone.buffer).every((x, i) => x === i + 1), name + " bytes");
        }
        const buffer = new ArrayBuffer(24);
        const bytes = new Uint8Array(buffer); bytes.set([1, 2, 3, 4], 4);
        const left = new Uint8Array(buffer, 4, 8);
        const right = new Uint16Array(buffer, 4, 4);
        const data = new DataView(buffer, 2, 12);
        const clone = structuredClone({ buffer, left, right, data });
        assert(clone.buffer !== buffer && clone.left.buffer === clone.buffer);
        assert(clone.right.buffer === clone.buffer && clone.data.buffer === clone.buffer);
        assert(clone.left.byteOffset === 4 && clone.left.length === 8);
        assert(clone.right.byteOffset === 4 && clone.right.length === 4);
        assert(clone.data.byteOffset === 2 && clone.data.byteLength === 12);
        assert(clone.left[0] === 1 && clone.left[1] === 2);
        "#,
    );
}

#[test]
fn errors_normalize_names_and_keep_message_and_stack() {
    check(
        r#"
        for (const name of ["Error", "EvalError", "RangeError", "ReferenceError",
                            "SyntaxError", "TypeError", "URIError"]) {
          const source = new globalThis[name]("message-" + name);
          source.stack = "stack-" + name;
          const clone = structuredClone(source);
          assert(clone !== source && clone instanceof globalThis[name], name + " brand");
          assert(clone.name === name && clone.message === source.message, name + " fields");
          assert(clone.stack === source.stack, name + " stack");
        }
        const odd = new Error("odd"); odd.name = "CustomError";
        const normalized = structuredClone(odd);
        assert(normalized.name === "Error" && normalized instanceof Error);
        "#,
    );
}

#[test]
fn unsupported_values_and_platform_objects_throw_data_clone_error() {
    check(
        r#"
        const rejected = [function () {}, Symbol("x"), Object(Symbol("x")),
          new WeakMap(), new WeakSet(), Promise.resolve(1), new Headers(),
          new URL("https://example.com/"), new URLSearchParams("x=1"),
          new AbortController(), AbortSignal.abort(), crypto,
          new DOMException("x", "AbortError")];
        if (typeof WeakRef === "function") rejected.push(new WeakRef({}));
        if (typeof FinalizationRegistry === "function") rejected.push(new FinalizationRegistry(function () {}));
        for (const value of rejected) dataCloneError(() => structuredClone(value));
        class UserClass { constructor() { this.x = 1; } }
        const userClone = structuredClone(new UserClass());
        assert(userClone.x === 1 && Object.getPrototypeOf(userClone) === Object.prototype);
        const responsePrototype = {};
        Object.defineProperty(responsePrototype, Symbol.toStringTag, { value: "Response" });
        dataCloneError(() => structuredClone(Object.create(responsePrototype)));
        dataCloneError(() => structuredClone(new Proxy(new Map(), {})));
        "#,
    );
}

#[test]
fn transfer_is_empty_or_refused_and_intrinsics_are_captured() {
    check(
        r#"
        assert(structuredClone({ x: 1 }).x === 1);
        assert(structuredClone({ x: 1 }, {}).x === 1);
        assert(structuredClone({ x: 1 }, { transfer: [] }).x === 1);
        assert(structuredClone({ x: 1 }, { transfer: new Set() }).x === 1);
        dataCloneError(() => structuredClone(new ArrayBuffer(1), { transfer: [new ArrayBuffer(1)] }));
        assert(Object.isFrozen(Map.prototype), "test must run after hardening");
        const original = Map.prototype.forEach;
        try { Map.prototype.forEach = function () { throw new Error("hostile override"); }; } catch (_) {}
        const source = new Map([[{ x: 1 }, { y: 2 }]]);
        const clone = structuredClone(source);
        assert(clone.size === 1 && Array.from(clone.values())[0].y === 2);
        assert(Map.prototype.forEach === original, "hardening changed");
        "#,
    );
}
