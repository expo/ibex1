# <img src="./assets/brand/ibex-mark.svg" alt="" width="27" height="36"> Ibex

**Ibex** is the JavaScript/TypeScript **runtime** used by [Exact](https://github.com/ccheever/exact)
and [Snapback](https://github.com/ccheever/valet). It embeds Hermes and exposes
a small, stable host ABI so native hosts can create runtimes, evaluate JS/HBC,
and install host calls.

Analogous in spirit to `node`, `bun`, or `deno` — a runtime, not an app
framework. The `ibex` runtime binary lives in this repo. The Exact project CLI
and app framework live in the `exact` repo.

> **Status: extracted "for now."** This repository was split out of the Exact
> monorepo as a history-preserving extraction. It will be re-homed under the
> `expo` org later.

## What's here

- The `ibex-runtime` Rust crate (Hermes bindings in `src/engine/*.cc`, the
  host ABI in `src/host`, the module loader, vendored Brotli).
- The `ibex` runtime binary (`src/bin/ibex`) for running JavaScript and
  TypeScript files.
- Catalog-pinned release builds can package a program as a standalone,
  self-contained executable; see [Standalone executables](./docs/standalone-executables.md).
- The Hermes build scripts (`scripts/build-hermes-*.sh`, `download-hermes.sh`).

## The contract

Consumers depend on a deliberately narrow surface (see [LLP 0002](./llp/0002-host-embedding-abi.spec.md)):

- The lifecycle/evaluation C ABI: production construction uses
  `ex_hermes_create_armed`; the historical `ex_hermes_create` symbol always
  refuses, and `ex_hermes_create_diagnostic` is explicitly non-production.
  Runtime driving continues through `ex_hermes_destroy`, `ex_hermes_eval`,
  `ex_hermes_free_string`, and the diagnostic-only
  `ex_hermes_set_host_call`. Armed runtimes silently reject the generic host
  bridge and expose only dedicated native APIs.
- The Rust host ABI: `ibex_runtime::host::{install_host, Host}`.

## Building

Ibex needs Hermes headers + a prebuilt `libhermesvm`. Install/build them with
`./scripts/download-hermes.sh`, which delegates to the platform source builder
and defaults to Hermes `260318099.0.0-stable`. The platform-specific entry
points are `./scripts/build-hermes-linux.sh` on Linux and
`./scripts/build-hermes.sh` on macOS/iOS. They install ignored native artifacts
into `linux/`, `ios/Frameworks/`, and `tools/hermes/`. Then:

```sh
# default profile
cargo build

# runtime binary
cargo build --bin ibex

# full runtime CLI profile
cargo build --bin ibex --features host-http-server,cli-notify

# full native crypto on Linux
cargo build --features openssl-crypto
```

Run the local binary with:

```sh
cargo run --bin ibex -- --version
```

### Running source safely

Ordinary source execution is enforce-only and fails closed unless Ibex's
standard promotion pipeline has shipped a generated CapSec v2 target
advertisement for the exact runtime tuple. `--project-root` selects the
trusted project mount; it never generates or refreshes an advertisement. Until
a production tuple is advertised, `ibex capsec audit <file>` is available as
an explicitly unarmed diagnostic workflow, not as an enforce-mode substitute.

Ibex normally stores generated bundles, bytecode, and protected CapSec
artifacts in the platform cache directory. In a filesystem sandbox where that
directory is not writable, pass a trusted, writable absolute path before the
command:

```sh
ibex --runtime-cache-dir /absolute/private/cache --project-root /absolute/project run app.mjs
```

The override does not expose a JavaScript mount or relax cache checks. Ibex
canonicalizes the directory and refuses it if it overlaps the authenticated
project or package roots.

`build.rs` auto-detects the standalone layout; `HERMES_INCLUDE_DIR` and
`HERMES_LIB_DIR` override the Hermes locations. `HERMES_VERSION` can override
the source ref passed to the build scripts; `scripts/hermes-version.sh` holds
the repo default.

The opt-in portable macOS arm64 build path consumes one already installed
checkout-local artifact and retained transport instead of the legacy path
overrides. It must be entered through the production runner; exporting the
selectors and invoking Cargo directly is deliberately refused:

```sh
./scripts/run-portable-hermes-cargo.mjs \
  --artifact-id "$ARTIFACT_ID" \
  --archive-digest "$ARCHIVE_DIGEST" \
  --expected-source-revision "$ARTIFACT_SOURCE_REVISION" \
  -- build --bin ibex
```

The runner first invokes the fixed production store verifier. Its checked
promotion admission keeps the artifact source revision A distinct from the
clean checkout revision: diagnostic A has `authorized:false` and current A;
an admitted production checkout has pairwise-distinct source A, promotion
topic P, and merge C with `authorized:true`. Any other D checkout is refused,
not downgraded to diagnostic mode. Only after fresh offline provenance and
reconstructive store verification does the runner mint a random, private,
one-use capability and launch Cargo itself. `build.rs` claims that live
capability before opening any artifact or host tool; it rechecks no-follow
ancestry, ownership, modes, ACLs, link counts, the checked Cargo target map,
rustc wrapper, and canonical LF-terminated promotion admission, then joins the
receipt back to the exact manifest, installation receipt, policy, bundle,
archive, and fresh verifier result. Stale/copied receipts and direct Cargo
invocations fail closed. The checked admission is embedded as a separate
compile-time record so A and C retain the same frozen build-consumption v1
artifact identity; legacy builds embed exactly `null\n` for that record.

Every portable `hermesc` version probe and compilation runs through its
digest-bound compatibility contract with a cleared environment, empty stdin,
exact `argv[0]`, a fresh private working directory, and one deadline covering
the entire supervised process group, pipe drain, and pinned output checks. A
tool that leaves descendants behind is refused. The output-aware rustc wrapper
derives Cargo's checked executable set and gives each normal bin, unit/integration
test, example, or bench exactly one depth-correct loader-relative rpath; it
does not install both possible depths. Absolute checkout/store rpaths remain
for legacy non-authoritative builds only.

This is still a Phase 1 build-input slice. A real private offline-verifiable
artifact corpus is required for the production runner, and the post-link and
runtime-mapping gates must land before this can enable production REPL,
conformance promotion, target attestations, or advertisements.

Linux native networking requires `pkg-config` and libcurl >= 7.86 so Fetch and
WebSocket use libcurl. For constrained local builds only,
`IBEX_ALLOW_CURL_CLI_FALLBACK=1` enables a degraded fetch-only fallback that
shells out to `curl`; WebSocket remains unavailable in that fallback profile.

### Android

Android builds consume the same Maven/PREFAB artifacts Android apps already use:
`com.facebook.hermes:hermes-android` for Hermes and
`com.facebook.react:react-android` for JSI. Install/extract them, then build
through the NDK wrapper:

```sh
./scripts/install-android-hermes.sh
ANDROID_TARGET=aarch64-linux-android ./scripts/cargo-android.sh
```

Android currently requires `--features openssl-crypto`; the wrapper includes it
by default. Native Android fetch/WebSocket use OkHttp through the Android
Java/JNI bridge in `platform/android/java/dev/ibex/runtime/IbexNetworking.java`.
The same bridge provides Android clipboard, raw DNS, location, camera
permission/device metadata, locale, screen, appearance/accessibility, app
lifecycle/configuration/deep-link events, and platform-version data to the JS
runtime.
Embedding apps must include that Java source, add OkHttp to the Android
classpath (for example `implementation("com.squareup.okhttp3:okhttp:5.4.0")`),
and call `ex_android_initialize(JavaVM*, Context)` before creating a runtime
that should observe Android platform data or use networking APIs. The wrapper
also sets `EXACT_ALLOW_FALLBACK=1` unless already set, so
AAR-based builds can use bootstrap JS source when no matching host `hermesc` is
installed. `HERMES_ANDROID_VERSION`, `REACT_ANDROID_VERSION`,
`ANDROID_HERMES_VARIANT`, and `ANDROID_API` are overrideable. The default
Android artifact pair is `hermes-android:250829098.0.14` with
`react-android:0.86.0`. Maven Central now publishes the
`260318099.0.0`/`.0.1` Hermes AARs, but `.0.1` predates the WeakRef
read-barrier fix in the source-built pin. Android therefore stays on the older,
unaffected reviewed artifact until a fixed AAR is available; the paired JSI
PREFAB must continue to include `jsi/hermes-interfaces.h`.

### Ibex 2 on Windows

Ibex 2's x64 MSVC engine uses unpatched, statically linked Hermes. In an x64
Visual Studio developer PowerShell with CMake, Ninja, Python, Node, and the
repository's Rust toolchain installed:

```powershell
.\scripts\build-hermes-windows.ps1 -Vanilla
node scripts/hermes-input-receipt.mjs tools/hermes-vanilla/windows-x64
cargo build -p ibex2 --features hermes
.\target\debug\ibex2.exe run path\to\main.js --root path\to\project
```

Use `ibex2 build` followed by `ibex2 run --precompiled` for ahead-of-time
bytecode. The executable needs the Windows system libraries and Microsoft C++
runtime, but no Hermes DLL. The Rust-only surface still builds without the
`hermes` feature. Windows `app:/` storage, native filesystem grants, SQLite
paths, and the Linux Intl projection are not yet qualified; see
[LLP 0068](./llp/0068-the-standard-library-for-a-rust-consumer.spec.md#windows-host-and-engine).

## Crypto profiles

- **`openssl-crypto`** — full native crypto on Linux via OpenSSL, including
  hashing/HMAC, AES, PBKDF2/scrypt/HKDF, asymmetric sign/verify/key generation,
  and key import/export. Optional on macOS.
- **Android** — currently uses the `openssl-crypto` profile with vendored
  OpenSSL.
- **default (no OpenSSL)** — uses platform crypto on Apple/Windows. On Linux it
  now builds without OpenSSL and provides the reduced portable surface used by
  core runtime flows: MD5/SHA-1/SHA-2 hashing, HMAC, PBKDF2, scrypt, and HKDF.
  Linux AES and asymmetric crypto still require `openssl-crypto`.

## License

MIT — see [LICENSE](./LICENSE). Vendored and linked third-party software is
inventoried in [THIRD-PARTY-NOTICES.md](./THIRD-PARTY-NOTICES.md), including
the MIT-licensed Hermes engine this runtime embeds and patches.
