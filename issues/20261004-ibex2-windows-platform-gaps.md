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
- Native `fs.read`/`fs.write` now admit qualified local-drive and canonical
  verbatim-disk paths through retained NT handles. Grant components compare
  exactly; lookup respects the filesystem's case policy. Quoted JSON targets
  cover spaces without changing unquoted grammar. UNC, mapped remote drives,
  device namespaces, streams and all reparse nodes remain refused. SQLite
  currently admits only `app:/` grants. Exact's shared `exact-grants` parser
  needs a separate reviewed consumer change before these grant extensions can
  reach that consumer; do not replace its patched vendored grant module.
- Windows does not install the Linux ICU-backed Intl projection. It has
  Hermes's Windows Unicode support; broader Intl conformance is unqualified.
- Three loader symlink fixtures need Windows Developer Mode or the symlink
  privilege. They compile on Windows and are explicitly ignored by default.
  Run and restore these cases when their platform prerequisites are satisfied.
  The storage-success embedding and structured-clone fixtures are now enabled
  and pass on Windows.
- Caps now executes correctly on Windows after its file-URL guard fix. It
  reports an existing 137 oversized files against a 133-file baseline; none of
  the Windows grant/backend files exceeds that cap.
- The initial engine target is x64 MSVC. ARM64 is explicitly rejected.

Engine validation, build commands, and dependency requirements are recorded
in [LLP 0068](../llp/0068-the-standard-library-for-a-rust-consumer.spec.md#windows-host-and-engine)
and the README. The Microsoft C++ runtime and Windows system ICU remain runtime
requirements; no Hermes DLL is needed.
