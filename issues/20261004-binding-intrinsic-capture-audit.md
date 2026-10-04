# Capture mutable intrinsics on Ibex 2 binding state paths

**Status:** Open
**Severity:** P1
**Systems:** Ibex 2, Bindings, Security
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-10-04
**Related:** LLP 0057.000 L3/L6, LLP 0059.000 §3.10/§3.14, LLP 0068 §3

## Threat model

A caller-owned runtime has installed Ibex 2 bindings but has **not** evaluated
`bindings::HARDEN_SOURCE`. Application code can therefore replace mutable
intrinsics after installation and between binding calls. A binding must not
look up those live methods on a brand check, private-state access, trust path,
private-byte path, or native-handle table. Capture the required intrinsic
during trusted bootstrap and invoke it through a captured `Reflect.apply` or
an uncurried wrapper.

This audit is against `a6090915`. It covers every JavaScript file under
`crates/ibex2/src/bindings/`; the findings below are the production binding
scripts that still make at least one dynamic intrinsic call on an in-scope
path. The audit records follow-up work only. Lane L3 fixed the event trust and
shared platform-brand registry findings separately and deliberately did not
widen into these files.

## Finding inventory

| Script | Dynamic calls on an in-scope path | State exposed to interposition |
|---|---|---|
| `abort.js` | Live `WeakMap.get`/`set`, `Object.create`/`setPrototypeOf`, `Function.call`, and `Array` `push`/`slice`/`forEach`/`splice`/`filter`/`some`/`indexOf` throughout lines 5–175. | Signal/controller brands, abort reasons, listener and abort-algorithm lists, dependent-source graph. |
| `blob.js` | `iterator.next()` at line 194 is a live method lookup while Blob parts become private bytes. The rest of the Blob/File/FormData WeakMap, byte-buffer, typed-array, and array mutation paths are captured and routed through captured `Reflect.apply`. | Blob byte construction. Triage must preserve required WebIDL iteration observability while separating the captured built-in Array iterator case from a caller-supplied iterator. |
| `crypto.js` | Live `WeakSet.has`/`add` and `WeakMap.has`/`get`/`set` at lines 32–41, 215–231, and 499–531; captured ArrayBuffer/view getters are later invoked through live `Function.prototype.call` at lines 119–138 and 509–517; key-usage arrays use live `slice`/`push`. | `Crypto`/`SubtleCrypto` receiver brands, `CryptoKey` native handles and metadata, and BufferSource backing store/offset/length. |
| `domexception.js` | Live private-slot `WeakMap.get`/`set` at lines 6, 35–50, and 70–97. | DOMException and QuotaExceededError brands and serialized private fields consumed by structured clone. |
| `fetch.js` | Live response/request/body/reader `WeakMap.get`/`set` and `Object.create` at lines 34–167 and 362–406; live pending-reader array methods at lines 96–134. | Response native handles, request snapshots, stream/reader ownership, pending settlements, cleanup and cancellation state. The typed-array copy used by `Response.blob()` is already captured. |
| `headers.js` | The shared brand registry at lines 18–31 is fixed, but runtime construction still uses live `Object.defineProperty` for `_handle` at line 93 and live `Object.create`/`defineProperties` for iterator state at lines 154–173. | Rust header-list handles and iterator cursor/owner state. |
| `intl_datetime.js` | Live `WeakMap.set`/`get` at lines 154–160 and live `Function.prototype.call` in the Date forwarding methods at lines 288–294. | Native formatter owner and cached bound formatter. |
| `intl_number_format.js` | Live bound-format `WeakMap.get`/`set` at lines 209–217 and live `Function.prototype.apply` for native initialization at line 199. | Native NumberFormat receiver/owner association and cached bound formatter. |
| `sqlite.js` | Live database/statement `WeakMap.get`/`has`/`set`, `Object.create`, array mutation, and `Function.prototype.apply` across lines 6–159. | Database and statement native handles, ownership, closed state, serialized parameter/result buffers, and the per-database promise tail. |
| `timers.js` | Live callback-table `Map.set`/`get`/`delete`, `Array.prototype.slice.call`, `Function.prototype.apply`, and array concatenation at lines 18–72. | Rust timer handle → JavaScript callback/argument/repetition records. |
| `url.js` | Live URL/view/URLSearchParams `WeakMap.get`/`set` at lines 54–172 and live Array iterator creation over private normalized pairs at lines 251–270. | URL component records, cached search-param views, backing query state, and branded iterator state. |

The highest-risk follow-ups are `crypto.js`, `sqlite.js`, `timers.js`, and
`fetch.js` because their private records contain or control native handles.
The remaining entries are still security-boundary work: recovering a WeakMap
receiver or substituting a live method turns an intended private brand/state
check into application-controlled behavior.

## Audited non-findings and exclusions

- `events.js` now captures uncurried WeakMap, array, and function operations
  plus descriptor creation (`9e2fc1be`). No event/target private-state or trust
  operation remains on a live intrinsic.
- `headers.js` now captures the shared platform-brand registry's WeakMap reader
  and writer (`a6090915`); it remains in the finding table for its separate
  header-handle and iterator construction paths.
- `structured_clone.js` captures and uncurries its traversal, brand-check,
  allocation, and collection operations. Calls into a caller-supplied transfer
  iterator remain intentionally observable WebIDL conversion, not access to an
  Ibex private registry.
- `intl_case.js` captures `Reflect.apply`, descriptor creation, locale methods,
  and string conversion before application code.
- `blob.js` captures its private WeakMaps, byte accessors, mutation methods,
  constructors, and `Reflect.apply`; only the live iterator `next` lookup noted
  above remains.
- `esm.js`, `harden.js`, and `testharness.js` are not installed by
  `bindings::scripts(groups)`: respectively they are runtime-only loader
  bootstrap, the explicitly absent hardening step in this threat model, and a
  test-only harness. They were inspected but are outside this caller-owned
  binding-call audit.
- `headers_ops.rs` and `storage.d.ts` are not JavaScript binding scripts.

## Done when

- Each finding is classified as either a required observable call on
  caller-supplied code or an intrinsic that must be captured and uncurried.
- Every capture-required path stops exposing its registry, private state,
  bytes, or native handle to a post-install intrinsic hook.
- The borrowed-runtime fixture poisons the identified methods after install
  and proves both semantic behavior and non-observation of private receivers.
- The events, structured-clone, Blob/FormData, crypto/subtle, fetch, storage,
  timer, URL, and Intl suites remain green without broadening `HARDEN_SOURCE`
  into a prerequisite for caller-owned runtimes.
