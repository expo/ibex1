# LLP 0067: Capabilities in Ibex 2

**Type:** Spec
**Status:** Accepted
**Systems:** CapSec, Module Loader, Runtime, Host ABI, Build
**Author:** Charlie Cheever / Claude (Fable 5)
**Date:** 2026-08-29
**Revised:** 2026-10-04 (§5: the legacy closure test traverses the resolved all-feature normal/build dependency graph and excludes dev-only edges); 2026-10-04 (§5: the legacy closure boundary is enforced from resolved Cargo dependencies; local `crate::host` is the intended R-c implementation); 2026-10-04 (§2: `net.websocket` is a built family; the `net.fetch` subdomain grant — both upstreamed from exact2's vendored copy); 2026-09-11 (§5: selected Linux Intl publication qualified in Snapback2 0.0.24; broader conformance boundaries remain open); 2026-09-11 (§5: selected Intl option-alias and locale-case callable limits, and TimeClip semantics); 2026-09-11 (§4, §5: Linux native Intl completion over vanilla Hermes, narrow post-install intrinsic admission, and the bounded exotic-constructor limitation); 2026-09-11 (§5: Linux vanilla-Hermes artifact, qualified scope, and Intl limitation); 2026-09-07 (app paths, rename source authority, and SQLite); 2026-08-30 (§2, §8: five families — `secret.keep` (LLP 0069) and `storage.kv` (LLP 0070) were added to the corpus without patching this page, which the LLP 0070 review caught; §8 now states the author-required form of a call site both arrived under) 2026-08-29 (accepted by Charlie Cheever, the same day) 2026-08-29 (§7: the tests the review added; §2 and §3 after the Grok 4.6 / Codex review: package identity is the bound install; fs paths are checked as realized as well as as spelt)
**Related:** LLP 0057 (§3.1 the boundary split, §4, and OQ2 — the decision this states), LLP 0059.000 (§4 — the capability families), LLP 0062 (the measurements: the escape inventory and the freeze), LLP 0065 (§4 — grants and resolution), LLP 0058.000.000 (the adapter protocol the runtime follows), LLP 0060 and LLP 0058.000 (superseded by this document for the model), LLP 0058.000.001 (tombstoned — the program this replaces with tests)

## Summary

Authority is an object a module is handed. A module's `fetch` carries its
grant in its closure; the runtime checks a request against that grant at one
Rust chokepoint and never asks who is calling. Nothing capability-bearing is on
the global object, so a module that was not handed a capability has no
expression that evaluates to one. That is the whole model. This page states it
in full so it can be tested rather than proven, and says what it does not
claim.

## 1. Five properties

Cited from code as R1–R5.

- **R1 — Nothing capability-bearing is on the global object.** `globalThis`
  carries `console`, timers, `performance`, `Headers`, `atob`/`btoa`, the
  lowering helpers, and nothing that reaches.
- **R2 — Capabilities arrive as parameters of the module's own scope.** Every
  module is evaluated as
  `function (module, exports, require, fetch, fs, process, __ibex2_meta, sqlite)`, and
  the `fetch`, `fs`, and `process` it receives were built for it with its
  grant captured. A module cannot borrow another's binding by name.
- **R3 — Modules ship as bytecode.** Compiled ahead of time against the engine
  this binary links (§5); a `--precompiled` run compiles nothing, resolves
  nothing the build already resolved, and refuses what was not built. So do the runtime's own bindings, compiled by
  `build.rs` with the engine's `hermesc`: a runtime parses no JavaScript at
  start. Grants are not part of the artifact key, so changing a manifest
  never recompiles anything.
- **R4 — Intrinsics are frozen before any module code runs.** Every existing
  global binding is locked and everything reachable from it is frozen; the
  global object itself stays extensible (§4).
- **R5 — The global name list is asserted before anything runs.** R1 is a
  property of a list, and a list nothing checks drifts: `run` refuses to start
  if the global object carries a name outside `ALLOWED_GLOBALS`.

## 2. Grants

A manifest keyed by module identity (LLP 0065 §4): a section names a file, a
package, a directory, or `*`; a module gets the most specific section naming
it, nothing is combined, and an empty section means nothing. A package
section applies to the install the manifest is bound to — the directory
`<root>/node_modules/<name>` resolves to, after symlinks — never to a path
because of how it is spelt, and never to a package because of what its own
`package.json` says; every section is canonical after binding; a section
naming something that does not exist is refused before any module runs. No
manifest means no authority.

Seven families exist, each a parameterized question:

| family | grant | the question |
|---|---|---|
| `net.fetch` | origin, or `scheme://*.domain` | may this request go to this origin? |
| `net.websocket` | origin | may a socket open to this origin? (LLP 0059.000 §3.12) |
| `fs.read` / `fs.write` | path prefix | may this path be read, or written? |
| `env.read` | variable name | is this variable in the snapshot? |
| `secret.keep` | name | may this secret be read, replaced, and forgotten? (LLP 0069) |
| `storage.kv` | scope | may this scope be read, written, listed, and deleted from? (LLP 0070) |
| `sqlite.open` | database path | may this database be opened? (LLP 0059.000 §3.15) |

`process.env` is the model in one object: a snapshot of exactly the granted
variables, so an ungranted one is undefined because it is absent, not because
a check refused it. `storage.local`, when its JavaScript call site arrives, binds
over a `storage.kv` scope rather than becoming a family of its own
(LLP 0070 §4).

**The subdomain grant.** A `net.fetch` grant may name every host under one
domain: `net.fetch https://*.host.example` admits `a.host.example` and
`b.c.host.example` at that scheme and port, and never `host.example` itself.
`*` must be the whole leftmost label and appear nowhere else; the domain
needs two labels or more and cannot be an address; `net.websocket` takes no
pattern. Hosts compare as the URL parser normalized them (lowercase,
punycode), and a trailing dot does not match. It is its own grant kind, so
an exact grant never matches as a pattern. Neither kind of origin grant may
carry a user or password: `https://api.example.com@evil.com` is the origin
`evil.com`, and a line that reads as one host while admitting another is
refused. There is no public-suffix check:
`*.co.uk` parses, and the manifest's author is trusted to name a domain they
mean. Because one grant now admits sibling hosts, a followed redirect that
changes origin drops `Authorization`, `Cookie`, and `Proxy-Authorization`
(LLP 0059.000 §3.5). Charlie, 2026-09-26, for an AT Protocol account that
lives on one of many hosts: *"a wildcard grant is probably worth it actually,
and the developer should just use it carefully."* Built first in exact2's
vendored copy and upstreamed 2026-10-04.

## 3. The check

One chokepoint, in Rust, at the host-call boundary (LLP 0059.000 §1). It reads
the grant the invoked binding carries and answers the family's question. It
never inspects a stack, a frame, a domain, or a job queue; there is no
attribution and no registry to keep. An operation touching two paths
(`rename`, `copyFile`) needs read on the source and write on the destination;
`rename` additionally requires write on the source.
Paths are checked twice: as spelt, normalized lexically so `/data/../etc/passwd`
does not pass a `/data` grant, and as the filesystem will really resolve them,
so a symlink inside a granted prefix — one a module with write on that prefix
could plant — does not reach outside it. The grant's own prefix is realized
the same way, so a grant on a directory that is itself a symlink still holds. An async operation carries its grant into the
host task; a synchronous host call is permitted only for an operation that
never leaves the calling thread.

A binding handed from module A to module B and invoked by B attributes to
**A** — it is A's authority. That is a different fact from what a stack walk
reports, and a truer one.

App prefixes (`app:/data`, `app:/cache`, `app:/tmp`) form a separate namespace
from native absolute prefixes. The host supplies the three roots; descriptor-
relative Unix operations reject symlink traversal and keep their root identity.
SQLite admits its database path once, then database and statement objects carry
that authority. Its authorizer prevents SQL from opening additional files.
The module's `sqlite` parameter is frozen and no raw database handle is exposed.

## 4. Integrity

The freeze (`harden.js`) runs after the standard library and bindings are
installed and before the first module: each existing global binding is made
non-writable and non-configurable — `Array` cannot be pointed elsewhere — and
every object reachable from them is frozen, so `Array.prototype.map` cannot be
replaced and `Object.prototype` cannot be polluted. The global object stays
extensible, because a property an application adds is state, not authority.
Budget: **2 ms**, declared in `rules/RULES.md` and enforced by
`the_freeze_stays_within_its_budget`; 0.7–1.0 ms today.

The trusted Linux Intl completion replaces exactly four properties captured
by the integrity snapshot: `Number.prototype.toLocaleString`,
`BigInt.prototype.toLocaleString`, and String's two locale case methods. Once
that installation succeeds, the adapter admits the new value/getter/setter
identity for those already-captured properties only; it does not recapture an
object or admit an arbitrary property. A later replacement of even one of the
four still makes SQLite refuse the runtime, pinned by a regression test.

Dynamic code is closed at construction (`withEnableEval(false)`): `eval`,
`new Function`, and every form that compiles are refused. Hermes's cached
`Function("return this")` fast path is not closed by it and yields the global
object — accepted, because the global object is empty of authority (R1) and
reaching it buys nothing. Pinned by a test.

## 5. The engine and the artifacts

The engine is unpatched upstream Hermes at the pinned commit, and
`ibex2 build` requires a `HermesInputReceipt` beside it attesting zero
patches, verified against the engine and `hermesc` on disk at build time. The
runtime hashes nothing at start: the archive it links is digested once at link
time (`IBEX2_LINKED_ENGINE_DIGEST`), folded into every artifact key, and
recorded in the manifest, which is checked before any module loads — artifacts
built by another binary are refused under `--precompiled` and ignored
otherwise. The artifacts themselves are read from one bundle behind that
manifest, once, and served from memory. Resolution is contained: a module cannot resolve outside the
declared root, on either arm, after canonicalization (LLP 0065 §3–§5). The
closure scan (`tests/closure.rs`) keeps the legacy runtime's authority
machinery out of this crate's dependency and link closure. The local
`crate::host` library is the intentional R-c standard-library implementation,
not legacy authority and not a forbidden dependency. The test runs Cargo
metadata with all `ibex2` features, starts at the `ibex2` node in
`resolve.nodes`, traverses every reachable normal or build dependency edge
without filtering target conditions, and rejects a reachable package named
`ibex-runtime`, `ibex_runtime`, `capsec-semantics`, `ibex-sfe-format`, or
`ibex-sfe-catalog`; package IDs make renames and intermediary workspace crates
inert. It does not traverse dev-only edges because test-only dependencies are
not part of the product dependency or link closure being asserted.

The Linux engine artifact is implemented for x86-64 as a source build of that
same exact vanilla pin. Each build re-exports the pinned Git object into an
isolated source directory rather than trusting mutable cached source. The
installed static closure carries Hermes, JSI, Boost.Context, ICU, and tinfo;
the resulting executable has no shared dependency on those libraries (nor on
curl or a TLS library). Its remaining dynamic dependencies are the ordinary
GNU/Linux C and C++ runtime libraries. The qualified target is specifically
Ubuntu 24.04.4, glibc 2.39, built with GCC 13.3 and Rust 1.93.1, with observed
symbol floors `GLIBC_2.39` and `GLIBCXX_3.4.30`; this is not an older-glibc or
musl claim. The Ibex engine suite and a release-mode AOT CLI HTTPS fixture
exercise grant checks, redirects, body bounds, cancellation, aborts,
deadlines, and task/microtask ordering.

The engine itself remains unchanged, including its non-Apple Intl stubs. Ibex's
trusted Linux standard-library tier now replaces the affected selected surface
with Rust-owned formatter state and ICU computation: `Intl.NumberFormat` and
its Number/BigInt locale methods, String locale case mapping, and
`Intl.DateTimeFormat`/parts and the Date locale methods. The JavaScript tier is
object and observable-coercion plumbing; formatter owners are unreachable JSI
native state rather than exposed numeric handles. Focused tests cover locale
negotiation, option validation/defaults, grouping and rounding, currency,
percent, significant digits, special and signed values, parts, stable bound
formatters, prototype/receiver behavior, lifetime, case mapping, time zones,
calendars, and integrity after hardening. The complete Linux Hermes suite and
freeze budget pass with that tier installed.

The selected 2020 locale negotiation ASCII-lowercases syntactically valid
Unicode option types before locale-data lookup. An unsupported explicit
calendar or numbering-system option leaves a supported requested Unicode
extension selected and retained in the resolved locale. Supplying `hour12`
overrides and removes a requested
`hc` extension. Time-zone identifiers are matched ASCII-case-insensitively;
non-ASCII lookalikes are not admitted. Finite in-range DateTimeFormat inputs
are TimeClip-truncated toward zero before ICU receives them. Public
NumberFormat and DateTimeFormat methods, accessors, bound format functions,
and Date locale methods have their builtin nonconstructor shape, names, and
lengths.

This is deliberately not a complete-Intl or blanket ECMA-402 claim. It does
not add the constructors absent from both qualified engine profiles, and the
accepted `formatMatcher` choices currently share ICU's best-pattern selection.
Option processing performs the selected ASCII case normalization but not full
UTS 35 alias canonicalization: canonical calendar spellings work, while legacy
aliases such as `islamicc` and `ethiopic-amete-alem` do not yet resolve as
`islamic-civil` and `ethioaa`. The String locale lower/upper-case replacements
produce the selected native results but remain constructable ordinary
functions rather than the nonconstructable shape of built-in methods.
The ordinary constructors preserve call/new behavior, custom object
prototypes, subclasses, and the specified single observable prototype lookup.
One exotic constructor case remains outside the selected completion: on this
pinned Hermes, `Reflect.construct` with a different `newTarget` whose
`prototype` is not an object falls back to `Object.prototype`, rather than the
corresponding Intl prototype. Public JSI has no custom `[[Construct]]` hook,
while a JavaScript Proxy performs Hermes's ordinary allocation and observable
prototype read before its construct trap. Ibex does not add a second read, a
descriptor heuristic, or a Hermes patch to disguise that engine constraint.
The implementation did not qualify publication by itself: the unchanged
consumer witness and actual packaged artifact were separate release evidence.
That evidence is now complete for Snapback2 0.0.24 on the stated Ubuntu target;
the registry-only Linux consumer passed after publication. The closed issue
`issues/closed/20260911-linux-hermes-intl-numberformat-stub.md` records that
release, while open issue `20260911-selected-intl-conformance-followups.md`
retains the deliberately broader Intl boundaries above.

## 6. What it is not

Supply-chain integrity against packages that were not granted — not a sandbox.
Not defended, and not going to be: **voluntary handoff** (a module may pass a
capability it holds to any other; a test pins that this works); **resource
exhaustion** (a module may spin, allocate, or recurse); **channels** between
modules, the extensible global object among them; **anything done before the
freeze**, which only trusted boot code can do; and **whatever the platform
hands back** — a platform API's defaults assume a browser with ambient
authority, and each is checked on its own (cookies are off, LLP 0059.000
§3.5). No compartments, no per-package intrinsics, no caller attribution.

## 7. Evidence

Tests that fail: grants honoured and denied per module, per package, and per
directory, including a directory named after a granted package inside another
package (`tests/loader.rs`, `tests/resolution.rs`); R1 and R5 as an exact
comparison of the global object's added names against `ALLOWED_GLOBALS`; a
module that cannot see another module's response or any handle accessor; the
freeze's effect, its budget, and a walk of everything reachable from the
global bindings that reports anything left open (`tests/harden.rs`); the
closure scan; the receipt refusals; the manifest-engine refusal; `fs` path
normalization, the two-path operations, and a symlink inside a granted prefix
that does not reach outside it. That is the evidence, and the whole of it.

Not evidence, and not sought: proofs that no path bypasses the boundary;
receipts beyond the artifact-to-engine binding; graduation manifests, tier
definitions, policy generations, revocation ancestry, or a five-platform
ceremony. LLP 0058.000.001's program is tombstoned for this reason. Adding an
item to this section requires removing one; the moment the claim becomes
"prove it," it is Ibex 1 again, and the answer is no.

## 8. How it grows

A family is added with a measured call site and a test, never ahead of one —
where the author naming a need as something to build on counts as the call
site, stated rather than measured (LLP 0059.000 §6's *author-required*; that
is how `secret.keep` and `storage.kv` arrived, each with its consumer named
in exact2 LLP 1018).
Revocation arrives when something needs revoking. Package grants exist because
a real manifest was unwritable without them. Nothing else is planned.
