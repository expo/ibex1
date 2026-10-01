# LLP 0001: Target Platforms and the CI Build Matrix

**Type:** RFC
**Status:** Draft
**Systems:** Build, Engine, Crypto, CI
**Author:** Charlie Cheever / Claude (Tuft)
**Date:** 2026-06-13
**Revised:** 2026-10-01 (tvOS gains a `build.rs` arm and Apple-mobile cfg gates: `ibex-runtime --lib` compiles for `aarch64-apple-tvos` and `aarch64-apple-tvos-sim`, the Hermes xcframework carries tvOS slices, and child_process spawning fails closed on tvOS; no CI row and no runtime evidence yet)
**Revised:** 2026-07-17 (ENG-24933 adds a pinned patched no-debugger Windows Hermes source build/release bundle pipeline; Windows remains compatibility-only with pathname-reopen identity explicitly insufficient for mapped-image attestation)
**Revised:** 2026-07-17 (ENG-24933 adds Windows x64 as an explicit unadvertised CapSec candidate and runs the complete exact-target report against the pinned patched no-debugger DLL; Windows remains compatibility-only while that report is incomplete)
**Revised:** 2026-07-18 (LLP 0031 narrows Ibex 0.2 native source/module
execution to evidence-gated macOS arm64 and Linux x64; this RFC's broader
matrix remains the product ambition and build-visibility plan, not a 0.2
execution advertisement)
**Revised:** 2026-07-18 (exact-target recipe generation now intersects source-discovered native registrations with the Windows translation units selected by `build.rs`)
**Revised:** 2026-07-18 (the Windows replacement crypto translation unit
preserves the cross-target hash-normalizer test ABI and reports that profile as
unsupported, so the complete Cargo matrix can link before deciding applicability)
**Revised:** 2026-07-17 (ENG-24933 adds a pinned patched no-debugger Windows Hermes source build/release bundle pipeline and independent loaded-DLL volume/file identity; Windows remains compatibility-only pending remote artifact and conformance evidence)
**Revised:** 2026-07-15 (ENG-25066 advertises the native module runner on exact macOS arm64 and Linux x64 targets while retaining Windows as an explicit compatibility-only row until a matching patched Hermes artifact exists); 2026-07-15 (ENG-25061: matching-artifact native module-runner corpus on macOS arm64 and Linux x64); 2026-07-12 (ENG-24263/ENG-24264: full exact-engine CapSec matrix/evidence is a gating macOS job; Windows runs behavioral locked-DLL staging coverage; Android queue behavior runs on a host JVM)
**Related:** LLP 0000; LLP 0002

## Summary

The intended product target set is **macOS, iOS, tvOS, Android, Linux, and
Windows** `[inferred: this is the platform ambition carried by the retrofit
draft and extraction history, not something the current checkout can prove by
itself]`. The current `build.rs` has first-class target branches for macOS,
iOS, Android, Linux, and Windows `[observed]` (`build.rs:804-1224`).

This RFC records the target set, the build axes that matter beyond OS name
(architecture and crypto profile), and the CI matrix needed to make platform
support observable. Where a row is not wired in code yet, this document marks it
as proposed/known-red rather than claiming it builds.

For Ibex 0.2, LLP 0031 governs executable source/module support: only
`aarch64-apple-darwin` and `x86_64-unknown-linux-gnu` may be promoted after
their exact native-runner and CapSec evidence gates pass. Other rows in this
RFC remain visible build or future-product targets and do not inherit runtime
TypeScript, source audit, or compatibility-evaluator support.

## 1. Target platforms

### What's a distinct build target vs. a form factor

Not everything that "runs ibex" is a separate build:

- **Apple family**: macOS, iOS, and tvOS are wired in `build.rs` `[observed]`.
  tvOS shares the iOS posture: CommonCrypto with `EXACT_PLATFORM_IOS`,
  `EXACT_NO_OPENSSL`, and `EXACT_NO_BROTLI`; no vendored OpenSSL; Hermes linked
  by the host Xcode project; and the iOS descriptor-to-mapped-code proof for
  loaded-engine attestation (`src/engine/mod.rs`,
  `src/engine/hermes_runtime.cc`). tvOS forbids `fork`/`execve`, so
  child_process spawning reports `ENOSYS` there
  (`src/engine/hermes_runtime_process.cc`). Rust 1.97 ships prebuilt std for
  `aarch64-apple-tvos` and `aarch64-apple-tvos-sim` but not `x86_64-apple-tvos`,
  so the Rust simulator archive is arm64 only `[observed]`. iPadOS is covered by iOS `[inferred]`;
  watchOS and visionOS are deferred until there is a concrete need `[inferred]`.
- **Android**: **Android** is a distinct target (NDK cross-compile,
  Hermes/JSI from Android Maven/PREFAB artifacts) `[observed]`
  (`build.rs:26-47, 172-227, 933-949, 1106-1172`;
  `scripts/install-android-hermes.sh`). **Android TV is not a separate build**
  — it is Android with the same OS/ABI rows `[inferred]`. Same for Wear OS /
  Chromebooks.
- **Linux** and **Windows** are distinct targets and are explicitly handled by
  `build.rs` `[observed]` (`build.rs:824-831, 954-1073`).

So the canonical target set is six OSes — macOS, iOS, tvOS, Android, Linux,
Windows — and "also runs on Android TV / iPadOS" is a coverage note, not a
matrix row.

### Current `build.rs` support (honest status)

| OS | build.rs arm | Crypto backend | Status |
|---|---|---|---|
| macOS | yes | CommonCrypto/Security; optional OpenSSL feature for some non-iOS paths | wired in `build.rs` |
| iOS | yes | CommonCrypto/Security with `EXACT_PLATFORM_IOS`, `EXACT_NO_OPENSSL`, `EXACT_NO_BROTLI` | wired in `build.rs` |
| Linux | yes | default defines `EXACT_NO_OPENSSL`; `openssl-crypto` enables OpenSSL linking; native networking requires libcurl >= 7.86 | wired in `build.rs` |
| Windows | yes | `hermes_runtime_crypto_windows.cc`, `EXACT_NO_OPENSSL`, WinHTTP/Bcrypt/Ncrypt/Crypt32 | wired in `build.rs` |
| **Android** | yes | `openssl-crypto` with vendored OpenSSL; Hermes/JSI from Android PREFAB; Java/JNI bridge for OkHttp fetch/WebSocket and Android platform/camera metadata | wired for cross-compile |
| tvOS | yes | same as iOS (`EXACT_PLATFORM_IOS`, `EXACT_NO_OPENSSL`, `EXACT_NO_BROTLI`); child_process unavailable | compiles (`--lib`); no CI row, no runtime evidence |

The table is grounded in the target selection and compile/link branches in
`build.rs` `[observed]` (`build.rs:804-1224`). tvOS has a target arm and
`scripts/build-hermes.sh` emits tvOS device/simulator slices, but nothing has
run the engine on tvOS yet. The matrix should keep tvOS as a
**known-red** row until a CI cross-compile row lands `[inferred: this keeps the product target set visible while
implementation catches up]`. Android is no longer known-red for compile or for
the default native fetch/WebSocket surface because it compiles
`native_android_networking.cc` and delegates HTTP/WebSocket work to the Android
OkHttp bridge; the same Android Java/JNI bridge now initializes clipboard,
raw DNS, location, locale, screen, appearance/accessibility,
camera permission/device metadata, app-state/deep-link/configuration events,
and platform-version globals for the JS runtime `[observed]` (`build.rs`;
`src/engine/native_android_networking.cc`;
`src/engine/hermes_runtime_android.cc`;
`platform/android/java/dev/ibex/runtime/IbexNetworking.java`).

The Windows build substitutes its filesystem, crypto, DNS, process, network,
OS-info, debugger, and process-setup translation units for the corresponding
default backend files `[observed]` (`build.rs`). Source discovery intentionally
retains registrations from every implementation, but exact-target recipe
generation must intersect those registrations with this build selection. A
global found only in an excluded default translation unit is not callable
Windows evidence; the current intersection keeps 37 recipes spanning 33 such
globals residual under `native-public-operation-not-installed-on-target`.
Globals with an actual Windows installation branch remain eligible.
Replacement translation units must also preserve cross-target integration-test
C ABI shape when the test contract reports unsupported applicability at
runtime; otherwise Windows cannot link the complete matrix far enough to make
that honest decision.

## 2. The axes that matter beyond OS

A platform name alone under-specifies the build. Three more axes carry real bug
risk:

### 2.1 Crypto profile (the axis that caused the original break)

Ibex's crypto is platform-dependent and is the single most fragile build axis:

- **Apple:** the non-Windows crypto file includes CommonCrypto/Security
  `[observed]` (`src/engine/hermes_runtime_crypto.cc:23-44`). iOS always defines
  `EXACT_PLATFORM_IOS` and `EXACT_NO_OPENSSL` `[observed]` (`build.rs:817-823`).
  macOS can opt into OpenSSL headers/linking with `openssl-crypto` `[observed]`
  (`build.rs:799-807`).
- **Windows:** `build.rs` compiles `hermes_runtime_crypto_windows.cc`, defines
  `EXACT_NO_OPENSSL`, and links Windows crypto/network libraries `[observed]`
  (`build.rs:729-765, 954-989`). That Windows crypto shim registers hash,
  hashRaw, and HMAC host functions, not the non-Windows asymmetric throwing
  stubs `[observed]` (`src/engine/hermes_runtime_crypto_windows.cc:141-221`).
- **Linux:** `build.rs` defines `EXACT_NO_OPENSSL` unless the
  `openssl-crypto` feature is enabled and links OpenSSL only in that feature
  profile `[observed]` (`build.rs:824-831, 1066-1073`). The reduced default
  profile no longer includes or calls OpenSSL: it provides portable
  MD5/SHA-1/SHA-2 hashing, HMAC, PBKDF2, scrypt, and HKDF, plus clear throwing
  stubs for asymmetric/key-generation functions `[observed]`
  (`src/engine/hermes_runtime_crypto.cc`). The `openssl-crypto` profile is the
  full Linux native crypto profile, adding OpenSSL-backed AES, asymmetric
  crypto, ECDH/X25519/Ed25519 helpers, RSA-OAEP, and key import/export
  `[observed]` (`src/engine/hermes_runtime_crypto.cc`).
- **Android:** Android now requires the `openssl-crypto` profile and uses
  vendored OpenSSL until an Android-native crypto backend exists `[observed]`
  (`build.rs:933-949`; `README.md:48-68`). This matches the proposed v1 matrix's
  OpenSSL Android profile while keeping the no-OpenSSL Android shape out of the
  supported set `[inferred]`.

The matrix MUST therefore build **Linux in both profiles** (openssl-crypto and
the reduced no-OpenSSL default), because the no-OpenSSL reduced build is
the profile most likely to reveal feature-gating drift. Exercising only the
openssl profile would miss that class of regression `[inferred]`.

### 2.2 Linux networking profile

Linux Fetch and WebSocket use libcurl as the supported native backend. The CI
matrix MUST install `pkg-config` and libcurl >= 7.86 for Linux rows so
`EXACT_HAS_CURL` is enabled `[observed]` (`build.rs:1175-1236`). The
`IBEX_ALLOW_CURL_CLI_FALLBACK=1` profile is a degraded local-build escape hatch,
not a CI or release profile, because it shells fetch through `curl` and leaves
native WebSocket unavailable `[observed]` (`src/engine/native_fetch_linux.cc`;
`src/engine/native_websocket_linux.cc`).

### 2.3 Architecture

- macOS, Windows, Linux: **arm64 + x86_64** (Linux also `aarch64` on native
  runners where available).
- iOS/tvOS: arm64 device + arm64/x86_64 simulator.
- Android: `arm64-v8a`, `armeabi-v7a`, `x86_64`.

Architecture catches fewer bugs than the crypto axis, but codegen/ABI and
pointer-width assumptions do surface here.

## 3. Proposed v1 matrix

Build (and, where the runner can execute the target, test) the following. Each
cell builds `--features openssl-crypto` where that's the platform's real profile
and the platform's native profile otherwise:

| OS | Arch | Crypto profile | Runner | Notes |
|---|---|---|---|---|
| Linux | x86_64 | openssl-crypto | ubuntu | primary; install libcurl >= 7.86 |
| Linux | x86_64 | default (no-OpenSSL) | ubuntu | reduced crypto profile; install libcurl >= 7.86 |
| Linux | aarch64 | openssl-crypto | ubuntu-arm (or cross) | install libcurl >= 7.86 |
| macOS | arm64 | CommonCrypto (default) | macos | tier-1 |
| macOS | x86_64 | CommonCrypto | macos | |
| iOS | arm64 (sim) | CommonCrypto | macos | cross-compile + simulator boot |
| tvOS | arm64 (sim) | CommonCrypto | macos | **known-red** until build.rs support lands |
| Windows | x86_64 | crypto_windows / NO_OPENSSL | windows | |
| Android | arm64-v8a | openssl-crypto | ubuntu + NDK | cross-compile required; cache Hermes/React PREFAB artifacts |

Known-red rows should stay visible but non-gating until their `build.rs` support
lands `[inferred]`. As tvOS support lands, flip it to required. Android should
be gating for cross-compile once CI has cached Hermes/React Android artifacts
and an NDK toolchain.

## 4. What CI must handle per cell

- **Hermes artifacts.** Each platform needs Hermes headers and libraries at the
  paths `build.rs` expects, or via `HERMES_INCLUDE_DIR` / `HERMES_LIB_DIR`
  overrides `[observed]` (`build.rs:172-227, 289-304`). Linux/Windows
  fail early when their default Hermes dirs are absent `[observed]`
  (`build.rs:183-210`).
- **Hermes compiler (`hermesc`).** Bootstrap HBC generation checks for a
  compatible `hermesc`; missing/mismatched `hermesc` panics unless
  `EXACT_ALLOW_FALLBACK` is set `[observed]` (`build.rs:33-55, 487-527`).
- **Hermetic default.** Cells build the default vendored-generated path; at
  least one cell should also run `IBEX_REGENERATE_RUNTIME=1` with the JS
  toolchain to keep the regeneration path honest `[inferred]`. The standalone
  path copies committed generated artifacts and panics if they are missing
  `[observed]` (`build.rs:321-351`).
- **Caching.** Cargo + Hermes-artifact caching per (OS, arch) to keep wall-clock
  sane.

The checked CI now has three concrete layers. Hermetic Ubuntu preflight runs
the semantic core, generated/drift gates, the platform-neutral Windows staging
tests, and the production Android WebSocket flow-controller tests on a host
JVM. A Windows runner repeats the staging suite and adds the real exclusive
locked-DLL case. The CapSec workflow installs exact patched artifacts on arm64
macOS and x64 Windows and executes every command in `CONFORMANCE_COMMANDS`
against each physical loaded engine, including the complete default/all-feature
Rust matrix, JS/runtime corpora, Android Java behavior, and artifact-bound
report generation. Because both candidates still have unresolved fixture
recipes, each job requires an incomplete report and no committed target
attestation; it uploads distinct execution/report/refusal evidence and fails if
its target either promotes or is advertised. This is a complete CapSec
prerequisite/evidence gate, not a claim that the remaining Android
cross-compile/emulator, iOS/tvOS, or Linux runtime matrix rows have landed
`[observed]` (`.github/workflows/ci.yml`;
`.github/workflows/compartment-conformance.yml`).

The module-runner workflow separately installs one patched Hermes artifact
bundle per advertised job so its JSI headers, link library, and CLI share an
identity. It runs the native ESM/CommonJS record and pure graph corpora on
macOS arm64 and Linux x64, and runs the canonical plus frozen Test262 producer
corpus through the bundled Hermes CLI on macOS. Windows remains visible: it
builds both feature profiles and runs the platform-neutral graph corpus. The
old NuGet installer is replaced by a download-first, source-build fallback for
the same pinned commit and patch digest as Apple/Linux; the artifact workflow
builds a no-debugger Release `hermesvm.dll`, checks the patched attribution
export, records its binary digest/profile, and publishes the exact x64 bundle.
The runtime separately snapshots the loader module set, requires exactly one
loaded module with the authored `hermesvm.dll` basename, and pins that module
by its mapped base address before deriving its loader-reported pathname. This
avoids both an executable-side MSVC import thunk and ambiguous basename lookup.
Rust reopens that pathname and compares its current Windows volume serial/file
index with the pinned file handle used for hashing. That detects ordinary
named-file substitution but does not authenticate the image section that
supplied already mapped code: a replacement after load can make both reopened
handles name the same different file. This closes ordinary pathname-only and
mismatched-file substitution but not mapped-image provenance, so the
conformance ledger retains that explicit Windows blocker. Windows x64 is
nevertheless an explicit CapSec candidate, and the complete-matrix workflow
consumes the pinned bundle to produce target-, source-, catalog-, and
loaded-DLL-bound evidence. The target
remains compatibility-only while the report is incomplete and mapped-image
provenance is unresolved; no advertisement follows from the implementation,
candidate declaration, or report execution alone `[observed]`
(`scripts/build-hermes-windows.ps1`;
`scripts/install-windows-hermes.ps1`; `.github/workflows/hermes-artifacts.yml`;
`.github/workflows/module-loader-baselines.yml`;
`.github/workflows/compartment-conformance.yml`).

## 5. Sequencing

1. Land the matrix for the five targets that build today (macOS, iOS, Android,
   Linux, Windows) + the Linux dual-profile row — immediate regression
   protection.
2. Add tvOS (Apple-family `build.rs` arm; small) and flip from known-red. The
   `build.rs` arm and cfg gates have landed; the CI cross-compile row has not.
3. Add Android (`build.rs` target arm + Hermes/JSI Android artifacts + NDK
   toolchain in CI) — initial compile support and native networking have landed;
   CI/emulator smoke remains.
4. Add arm64 rows as native runners allow.

## Open questions

- Where do per-platform Hermes artifacts come from in CI — built from source per
  run (slow), cached, or published as release assets and fetched?
- Should tvOS/iOS go beyond "compiles" to a simulator smoke test, and Android to
  an emulator smoke test, or is cross-compile-only sufficient for v1?
- Do we add arm64 Windows, or defer until there's demand?
