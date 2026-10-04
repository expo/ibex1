# LLP 0068: The standard library for a Rust consumer

**Type:** Spec
**Status:** Draft
**Systems:** Rust Stdlib, Host ABI, CapSec, Build
**Author:** Charlie Cheever / Claude (Fable 5)
**Date:** 2026-08-29
**Revised:** 2026-10-04 (§3: BLOB is in `Groups::DEFAULT` and `Groups::ALL` under the final 150 KB / 150 µs default-on budget)
**Revised:** 2026-10-04 (§3: BLOB install group and engine-free Rust FormData/multipart body); 2026-10-04 (§3: wake callbacks are serialized edge-triggered notifications; concurrent admissions coalesce, re-entrant close returns, and cross-thread close waits for the sole invocation); 2026-10-04 (OQ2: the off-Apple HTTP transport loads the native trust store lazily and at most once per process; §3: a default `Context` defers its platform transport so adoption does not build and discard it); 2026-10-04 (§3: bytecode preflight requires the pin's complete 128-byte `BytecodeFileHeader` before reading prefix fields or mutating the runtime); 2026-10-04 (§3: a late completion and queue closure serialize with FIFO insertion, so the result is dropped with its resources); 2026-10-04 (§3: Hermes adoption snapshots configuration applied through the source `Context` after construction); 2026-10-04 (§3: the last owner lease, not the last worker reference, begins shutdown and retires the wake callback); 2026-10-04 (§3: the install input is a typed, validated endowment handle; bytecode preflight checks the complete header and declared length; a failed one-shot install spends the adapter, and failure after publication requires discarding the runtime; the Hermes bootstrap order is stated as implemented); 2026-10-04 (§3: named install groups and their explicit dependency graph); 2026-09-11 (OQ2: Snapback2 0.0.24 separately qualifies and publishes the selected Linux engine-facing Intl tier; broader Intl conformance remains open); 2026-09-11 (OQ2: Linux's selected engine-facing Intl stubs are replaced by the native standard-library tier; this does not expand the no-engine Rust surface or qualify publication); 2026-09-11 (OQ2: the same transport qualified through the Linux Hermes runtime; Linux Intl and publication remain unqualified); 2026-09-07 (app-scoped filesystem and separate SQLite provider); 2026-09-06 (§2: author-required streaming and cancellation); 2026-09-03 (LLP 0057.000 plans how `Bindings` grows — one field per family, feature-gated where a family pulls a dependency or a framework, present and refusing when the feature is off — and answers OQ3 in its lane L3 with a `Receiver`; neither is built yet) 2026-08-30 (§1: `Bindings` grew `secrets` (LLP 0069) and `kv` (LLP 0070), and `Host` carries their stores beside the transport — caught by the LLP 0070 review as drift on this page; §3: the whole-surface sentence now says where the fourth and fifth bindings' tests live, caught by its round 2)
**Revised:** 2026-10-04 (§3: the PURE group includes engine-owned `structuredClone` with no host operation); 2026-10-04 (§3: wake callbacks are serialized edge-triggered notifications; concurrent admissions coalesce, re-entrant close returns, and cross-thread close waits for the sole invocation); 2026-10-04 (OQ2: the off-Apple HTTP transport loads the native trust store lazily and at most once per process; §3: a default `Context` defers its platform transport so adoption does not build and discard it); 2026-10-04 (§3: bytecode preflight requires the pin's complete 128-byte `BytecodeFileHeader` before reading prefix fields or mutating the runtime); 2026-10-04 (§3: a late completion and queue closure serialize with FIFO insertion, so the result is dropped with its resources); 2026-10-04 (§3: Hermes adoption snapshots configuration applied through the source `Context` after construction); 2026-10-04 (§3: the last owner lease, not the last worker reference, begins shutdown and retires the wake callback); 2026-10-04 (§3: the install input is a typed, validated endowment handle; bytecode preflight checks the complete header and declared length; a failed one-shot install spends the adapter, and failure after publication requires discarding the runtime; the Hermes bootstrap order is stated as implemented); 2026-10-04 (§3: named install groups and their explicit dependency graph); 2026-09-11 (OQ2: Snapback2 0.0.24 separately qualifies and publishes the selected Linux engine-facing Intl tier; broader Intl conformance remains open); 2026-09-11 (OQ2: Linux's selected engine-facing Intl stubs are replaced by the native standard-library tier; this does not expand the no-engine Rust surface or qualify publication); 2026-09-11 (OQ2: the same transport qualified through the Linux Hermes runtime; Linux Intl and publication remain unqualified); 2026-09-07 (app-scoped filesystem and separate SQLite provider); 2026-09-06 (§2: author-required streaming and cancellation); 2026-09-03 (LLP 0057.000 plans how `Bindings` grows — one field per family, feature-gated where a family pulls a dependency or a framework, present and refusing when the feature is off — and answers OQ3 in its lane L3 with a `Receiver`; neither is built yet) 2026-08-30 (§1: `Bindings` grew `secrets` (LLP 0069) and `kv` (LLP 0070), and `Host` carries their stores beside the transport — caught by the LLP 0070 review as drift on this page; §3: the whole-surface sentence now says where the fourth and fifth bindings' tests live, caught by its round 2)
**Related:** LLP 0057 (§3.1 — the split, and the reason for a Rust standard library that survived: the non-JS consumer), LLP 0067 (the capability model this states in Rust), LLP 0059.000 (§4 — the families; §3.8 — the env snapshot), `rules/NOT-DOING.md` (the bar: a no-JS consumer gets the same standard library with no engine in the process)

## Summary

Charlie Cheever decided on 2026-08-29 that the no-JS consumer of Ibex 2's
standard library is Exact 2's plan runner, which is Rust, and that this must
be supported. This document is the surface: `ibex2::host`. It is not a second
implementation — every function is the one the JavaScript bindings call,
behind the same `boundary::admit`, taking the same `GrantSet` a manifest
section parses to — and it links no engine. What it states in Rust is
LLP 0067's model: a consumer is endowed with bindings that carry their grant.

## 1. The shape

```rust
let host = Host::new();                       // the platform transport, once per process
let app = host.endow(GrantSet::parse(
    "net.fetch https://api.example.com\nfs.read /data\nenv.read HOME\n")?);
let response = app.fetch.get("https://api.example.com/things")?;   // Rust's redirects, headers, errors
let bytes    = app.fs.read_file("/data/things.json")?;            // checked as spelt and as realized
let home     = app.env.get("HOME");                               // None if not granted: absent, not refused
```

`Host` is the runtime without an engine: the platform transport, the secret
store, the kv store, and nothing else. `endow` is instantiation:
`Bindings { fetch, fs, env, secrets, kv, sqlite }` (secrets and kv are LLP 0069 and LLP 0070; SQLite is LLP 0059.000 §3.15) is the module parameter list as a struct, each binding holding an
`Arc` of the grant set for its whole life. A binding handed from one consumer to another carries the
first's authority, as LLP 0067 §3 says a JavaScript binding does. A consumer
granted nothing holds bindings that refuse — not absent bindings — so the
failure is a denial rather than a panic.

`Fs` offers the eleven operations the JavaScript `fs` has, with the same rules:
absolute paths, normalized lexically and checked as spelt and as the
filesystem will really resolve them; read on the source and write on the
destination for `rename` and `copy_file`, plus source write for `rename`. `Env` is the snapshot LLP 0059.000
§3.8 specifies. The pure tier — `stdlib::url`, `base64`, `text`, `headers` —
is plain Rust and needs no host at all.

App storage is configured by the embedder, not inferred from its environment:

```rust
let directories = AppDirectories::new(data_dir, cache_dir, temp_dir)?;
let host = Host::new()
    .with_app_directories(directories)
    .with_sqlite_provider(Arc::new(ibex2_sqlite::SqliteProvider));
let app = host.endow(GrantSet::parse(
    "fs.read app:/data\nfs.write app:/data\nsqlite.open app:/data/app.db\n")?);
app.fs.atomic_write_file("app:/data/settings.json", br#"{"theme":"dark"}"#)?;
let database = app.sqlite.open("app:/data/app.db")?;
database.execute("CREATE TABLE IF NOT EXISTS notes (body TEXT)", &[])?;
database.close()?;
```

Directories must already exist. The SQLite provider is a separate linked
artifact, not a core feature switch. A host that needs only files installs no
provider. JS embedders set the same directories/provider on `Hermes` before
running modules. The SQLite library uses native VFS/journaling and requires
host-owned stable database parents while open; app file operations use pinned
directory handles (LLP 0059.000 §3.11, §3.15).

## 2. Synchronous, and why

The primitives block. An executor is the consumer's: a runner with its own
loop — Exact 2's has a seekable clock and a data seam — puts them on its own
workers, or wraps them in whatever future type it already uses. Ibex 2 does
not pick an async runtime for a consumer, and does not ship timers here,
because the consumer's clock is its own. The JavaScript path's task queue
(`task.rs`) is the engine's executor, not a general one.

`Fetch::stream(request, &signal)` returns headers and an owned, demand-driven
`StreamingResponse`. Read its body into caller-provided byte slices, collect it,
or drop it to close an unread request. `stdlib::abort::AbortController::abort`
interrupts the native request through its signal, including blocked header and
body reads. Buffered `send`/`get` collect this same transport path; origin grants
are checked on every redirect. Cancellation introduces no Rust timer or runtime.

## 3. No engine in the process

The `hermes` feature is the engine. With it off — the crate's default — no
Hermes is linked, and `cargo test -p ibex2 --no-default-features` runs the
whole surface: `--test rust_consumer` covers a fetch through `NSURLSession`,
filesystem operations inside and outside a granted prefix, an env snapshot,
and the pure tier; the fourth and fifth bindings run beside it — secrets in
the crate's `--lib` suite (LLP 0069 §5), kv there and end-to-end in
`--test kv` (LLP 0070 §5). The platform
transport is compiled whether or not there is an engine; it had been gated
on the engine by accident of `build.rs`, which would have left a Rust
consumer with the development TCP transport and no TLS.

### Caller-owned JavaScript runtimes

`bindings::Groups` is the install-time surface selection. It is a dependency-
free bitset, separate from cargo features: features choose what family code is
linked, groups choose what one runtime receives. `Groups::DEFAULT` and
`Groups::ALL` reproduce Ibex's current runtime profile (including `INTL` only
on Linux). An omitted dependency is an error; installation never widens the
selection on the caller's behalf. The groups are:

| group | JavaScript globals or module bindings | host operations / native work | requires | linked by |
|---|---|---|---|---|
| `PURE` | `URL`, `URLSearchParams`, `Headers`, `TextEncoder`, `TextDecoder`, `atob`, `btoa`, `DOMException`, `QuotaExceededError`, `structuredClone` | URL/search params 29–39, headers 40–51, text 20–22; the current Hermes profile supplies conforming text/base64 globals as engine intrinsics; `structuredClone` is engine-owned and has no host operation | — | core |
| `CONSOLE` | `console` | console 1–5 | — | core |
| `TIMERS` | `setTimeout`, `setInterval`, both clears, `queueMicrotask`, `performance`; private pump callback | timers/performance 60–63 | `CONSOLE` | core |
| `ABORT` | `AbortController`, `AbortSignal` | JavaScript state; timer use is conditional when `TIMERS` is present | `PURE` | core |
| `CRYPTO` | `Crypto`, `crypto` | entropy/UUID 70–71 | `PURE` | core today; a family feature is L2 work |
| `BLOB` | `Blob`, `File`, `FormData`; fetch body/response integration when `FETCH` is also selected | multipart boundary/encode 73–74; Rust `stdlib::multipart::FormData` uses the same encoder without an engine | `PURE` | core, default-on (15,207-byte binding; 45.669–85.124 µs floor cost) |
| `FETCH` | `Request`, `Response`; endowed `fetch` is module-bound in Ibex's secure runtime | fetch 101, response read 102, control 72, response handles | `PURE`, `ABORT` | core today; a family feature is later work |
| `STORAGE` | endowed `fs`, `sqlite` | filesystem 110–120, SQLite 150–158 and result 80 | — | filesystem is core; SQLite provider is a separately linked artifact |
| `ENV` | endowed `process.env` snapshot | grant-selected environment snapshot | — | core |
| `SECRETS` | no JSI projection yet; named for the existing Rust binding | `secret.keep` library operations | — | core/platform backend |
| `KV` | no JSI projection yet; named for the existing Rust binding | `storage.kv` library operations | — | core/platform backend |
| `INTL` (Linux) | selected `Intl`, locale methods on Number/BigInt/String/Date | ICU-backed formatting/case operations | — | `hermes` on Linux today |

`bindings::scripts(groups)` returns the ordered `(name, source_path)` inputs
for the caller to compile with its own engine compiler. It excludes the
runtime-only `esm.js`, `harden.js`, and test harness. The order preserves the
shipping runtime's established bootstrap order while filtering out unselected
groups.

The one JSI entry point is:

```cpp
Adapter adapter(runtime, context.state_ptr());
adapter.install(groups, context.bindings_ptr(), compiled_scripts, script_count);
```

Here `compiled_scripts` is the name/byte-span array produced from that exact
`bindings::scripts(groups)` order. The adapter checks the dependency graph,
count, names, and order before evaluating anything. It installs native host
functions first, evaluates only precompiled bytes, materializes the selected
endowed bindings, and returns without a checkpoint, task delivery, wait, or
other loop action. A caller that wants a capability on its global receives it
there (`fetch`, `fs`, `sqlite`, or `process`); Ibex's secure runtime consumes
those endowed values during trusted bootstrap and removes them from the real
global before module code, preserving LLP 0067 R1/R2.

`bindings_ptr()` has a distinct opaque C++ handle type; it is not a grant or
state pointer. For a caller-owned runtime it must be the endowment from the
same `Context` whose `state_ptr()` constructed the `Adapter`. The ABI validates
the live handle and its tag before returning either state or grants, and the
adapter separately requires that state pointer identity. An old call that
passes `context.grants_ptr()` therefore does not compile, and a forced cast is
refused rather than reinterpreted.

`Context::new` carries the platform-default transport as a lazy endowment. A
borrowed runtime that uses it constructs that transport at first fetch; an
owning Hermes runtime adopts the same lazy endowment rather than constructing a
source transport only to discard it.

Installation is one-shot. Before publishing any native function or global,
the adapter requires the complete fixed `BytecodeFileHeader` — 128 bytes in the
selected pin — before reading its magic, engine version, or declared file
length, then checks the declared length against the actual buffer. A build with
Hermes's internal file-format header derives that size with `sizeof` and
asserts the pinned value; installed public-only headers use that asserted pin
value. A failed attempt spends the adapter, so a retry is refused. If an engine
rejection or other failure occurs after publication begins, the error states
that the runtime is partially mutated and must be discarded; the adapter never
presents that runtime as fresh installation state again.

The pre-existing `Adapter` constructor, `set_binding`, `async_binding`,
`storage`, `settle`, and `deliver_one` remain source-compatible for Exact2's
current storage embedder. `storage` still returns frozen `{fs, sqlite}` and
modifies no globals; `install` is the additive whole-surface door.
`Hermes::install_runtime(groups, &context)` uses the actual bootstrap order:
`prepare_runtime` first reserves runtime-only global slots, then the same
`Adapter::install` installs the selected standard-library groups, and only then
does Hermes evaluate `esm.hbc`. The module loader asks the adapter's retained
factories for per-module endowed values and removes the temporary capability
globals before project code.
Unlike a borrowed runtime, Hermes already has a runtime state and adapter from
construction. It copies a snapshot of the source `Context`'s transport,
stores, environment, optional provider, and directories into that existing
state, including directories and a provider applied through the `Context`
setters after construction; it never replaces the queue, shares task IDs with
the source `Context`, or reconstructs the adapter and its construction-time
integrity snapshot. Configuration made on Hermes before installation
(directories, provider, and loader) therefore remains attached to the runtime.
Destroying Hermes shuts down only its own state, not the source `Context`.
`loader::allowed_globals(groups)` derives R5's allow-list from that runtime's
recorded selection; it is no longer a second, fixed inventory that can drift
from installation.

Implemented 2026-09-07 (Charlie: make the bindings available in Rust and
TypeScript; Codex). `ibex2::bindings::Context` supplies a separate Rust state
and host-admitted grant set. Its directories and optional SQLite provider are
configured exactly as the Rust host's. `include/ibex2_jsi.h` and
`src/engine/ibex2_jsi.cc` are the installable JSI adapter; the embedder compiles
them against its own JSI headers, with no `hermes` feature required. The
existing Ibex2 Hermes runtime uses this same adapter.

The caller bakes `src/bindings/sqlite.js` with its engine's compiler. Its
completion value is a factory passed to `Adapter::storage`, which returns
frozen `{fs, sqlite}` capabilities and modifies no globals. The host decides
how to pass that object to app code. The adapter is constructed during trusted
initialization. After installing its own prelude, the caller evaluates the
precompiled `bindings::HARDEN_SOURCE` before app code: SQLite checks that its
intrinsics and their global bindings are locked before opening any database.
Captured validators prevent app code from substituting that check. The Rust
API needs no JS hardening. `src/bindings/storage.d.ts` declares that
TypeScript API; `bindings::TYPESCRIPT` makes the same declarations available
to a Rust-based bake. `fs.readdir` returns an array, `fs.stat` a record, and
`fs.readFile` an `ArrayBuffer`. Writes require bytes, never silently treating
an unsupported value as an empty file. SQLite integers return as `bigint`.

The adapter delivers at most one completion when asked; it runs no timers or
microtask checkpoints. `Context::set_wake` schedules the caller's executor
from a publishing worker, outside queue locks. Wake is an edge-triggered,
coalescing notification: an admission records a pending edge; if no invocation
is in flight that publisher becomes the invoker, and admissions during its call
only leave one pending edge for its loop to invoke afterward. At most one wake
callback runs per queue. A coalescing publisher never invokes, waits for, or is
counted as an active callback. The callback only schedules and returns. It
never runs JavaScript and never blocks waiting for the owner thread; `wait` is
the blocking alternative. Only the owner thread touches JSI.
The caller detaches the
adapter before destroying either its runtime or Rust context. Detach clears
JS roots; retained capability functions fail closed. A `Context` holds an owner
lease on its runtime state, and an owning Hermes runtime holds its own lease.
Worker and completion references are not owners. Dropping the last owner closes
the wake notification and drops its callback. On the invoking thread this
returns immediately; on another thread it waits until the sole invocation has
returned. It then begins shutdown and cancels outstanding work even when a
worker still holds the state. Queue closure and
FIFO insertion share one lock, so a completion offered after closure is
dropped with its owned resources instead of entering the queue. If the last
owner is released re-entrantly by the wake callback itself, the outer wake loop
retires its invocation after the callback returns. No coalesced publisher is a
second active callback, and no worker can publish a completion or invoke the
retired callback afterward. The remaining unsupported case is ordinary lock
ordering: a thread that holds a lock the callback acquires must not release the
last owner while that callback is already in flight on another thread, because
shutdown waits for the callback and the callback waits for the lock. The
borrowed-runtime fixture tests installation, explicit checkpoints,
persistence, grants and detach without the Ibex2 loader.

This is the reusable storage door. Exact2's data-source continuation integration
is separate work: installing the bindings alone does not teach its executor
how to resume an answer awaiting storage.

## 4. Exact 2

The runner creates one `Host` at boot with the platform's transport and
endows each application from its manifest — the same manifest grammar as
LLP 0065 §4.2, minus the sections that name JavaScript modules — so an
application's data seam holds a `Bindings` and nothing ambient. Whether an
application's Rust code is trusted (a crate the author wrote) or endowed
(code the author did not write, as wasm with explicit imports per LLP 0057
OQ4) is Exact 2's decision; this surface serves both, since a `Bindings` is
what a wasm host would hand its module as imports.

## 5. Open questions

**OQ1 — The crate boundary.** *Resolved the same day:* the loader — Oxc's
parser, transformer, and resolver — is behind the `loader` feature, on by
default. A Rust consumer depends on `ibex2` with `default-features = false`
and compiles none of it; the same cut is the run-only binary of LLP 0065
§3.3, 5.6 MB against 9.6 MB.

**OQ2 — Linux.** *Resolved 2026-08-30, for Exact 2's Linux host (its LLP
1016 D2):* the default transport off Apple platforms is
`transport::rustls_http` — HTTP/1.1 over rustls through `ureq`, the webpki
roots compiled in, a thirty-second timeout, no redirect following (that is
`fetch`'s, above, as on Apple). Pure Rust: a builder with no system TLS and no
-dev packages runs it as is. It is a transport and not a second `fetch`: every
status is a response, and what never connected is `TypeError: Failed to
fetch`. **Trust is the platform's**, as §3 of LLP 0057 says and as
`NSURLSession` has it on Apple: the roots are the machine's CA bundle
(`rustls-native-certs`: `/etc/ssl/certs`, `SSL_CERT_FILE`/`SSL_CERT_DIR`), so
an enterprise CA or a development proxy works there as everywhere else; only a
machine with no bundle at all gets the compiled-in webpki roots — Mozilla's
set, the one a distro installs — and `RustlsHttpTransport::roots` says which,
for the consumer's journal (Charlie, 2026-08-30). The native bundle is read on
the first TLS connection (or the first `roots` query), cached with its TLS
configuration, and shared by every transport in the process; constructing a
transport or making a plaintext request does not read it. The development TCP transport
stays for tests that want plaintext and no dependency. A
`cfg(not(target_vendor = "apple"))` dependency, so an Apple build carries none
of it. The same transport is now qualified through the engine-bearing path on
Ubuntu 24.04.4: the Ibex Hermes suite covers redirects, body bounds,
streaming cancellation, aborts, and deadlines, and a release AOT CLI fixture
performs a granted HTTPS request using native roots. The Linux installation
carries the vanilla Hermes/JSI/Boost/ICU/tinfo inputs as static archives and
requires no undeclared shared transport or TLS library; the qualified binary's
observed floor is glibc 2.39 / `GLIBCXX_3.4.30`, not musl or an older
distribution. Pinned Hermes's non-Apple Intl stubs remain unchanged, but the
engine-facing Ibex tier now replaces the selected consumer-visible operations
for Number/BigInt formatting, locale String case mapping, and Date/DateTime
formatting with Rust-owned state and ICU computation. That implementation is
not part of `Host` and does not alter the no-engine Rust surface this document
specifies. It is not a qualification of complete Intl. The unchanged consumer
witness and packaged artifact separately passed for the published Snapback2
0.0.24 Linux package; the resolution is retained in
`issues/closed/20260911-linux-hermes-intl-numberformat-stub.md`. Broader Intl
behavior remains tracked in open issue
`20260911-selected-intl-conformance-followups.md`.

**OQ3 — Async.** If every consumer ends up wrapping these in the same future
type, that type belongs here. Not before.
