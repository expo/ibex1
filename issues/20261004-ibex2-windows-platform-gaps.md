# Complete Ibex 2 Windows platform families

**Status:** Open
**Systems:** Rust Stdlib, Host ABI, Build
**Severity:** P2
**Author:** Codex
**Date:** 2026-10-04

LLP 0068's Windows engine slice runs source and precompiled programs through
the pinned static vanilla Hermes VM. It does not establish whole-platform parity.

- `app:/data`, `app:/cache`, and `app:/tmp` now use retained Windows handles,
  relative NT operations and reparse rejection. The native SQLite provider
  works under its existing trusted-embedder, stable-ancestry contract. SQLite
  still uses native filenames; stronger hostile-host namespace ownership would
  require a separate provider/VFS design, not a claim made by this port.
- Native Windows absolute paths are not supported by `fs::normalize` or
  `PathPrefix`. Specify drive, UNC, verbatim-path, separator, case, and stream
  semantics before admitting them. SQLite currently admits only `app:/` grants.
- Windows does not install the Linux ICU-backed Intl projection. It has
  Hermes's Windows Unicode support; broader Intl conformance is unqualified.
- Four loader symlink fixtures need Windows Developer Mode or the symlink
  privilege. They compile on Windows and are explicitly ignored by default.
  Run and restore these cases when their platform prerequisites are satisfied.
  The storage-success embedding and structured-clone fixtures are now enabled
  and pass on Windows.
- The initial engine target is x64 MSVC. ARM64 is explicitly rejected.

Engine validation, build commands, and dependency requirements are recorded
in [LLP 0068](../llp/0068-the-standard-library-for-a-rust-consumer.spec.md#windows-host-and-engine)
and the README. The Microsoft C++ runtime and Windows system ICU remain runtime
requirements; no Hermes DLL is needed.
