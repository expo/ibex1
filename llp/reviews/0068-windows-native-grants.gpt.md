# Review of LLP 0068 Windows native filesystem grants

**Family:** Codex (same family as author; independent parent agent)
**Provider/runtime:** OpenAI Codex desktop multi-agent collaboration
**Date:** 2026-10-04
**Redacted:** No
**Method:** Parent read the proposed amendment and approved before implementation.
This records an independent agent review, not a cross-family model review.

The strict component-case restriction is acceptable as an explicit first slice.
Verify actual NtCreateFile exact-name behavior on ordinary NTFS and distinct-case
entries where available; do not infer it only from omitting OBJ_CASE_INSENSITIVE.

Per-operation root pinning is appropriate for path grants. Cross-call host
replacement may be observed, but each operation must keep admitted parent
handles. Preserve disjoint namespaces, lexical admission before I/O, no ungranted
ancestor creation, no reparse following, and both operands pinned before mutation.

Prefer confirming locality from the retained drive handle so mapped-drive
classification cannot diverge from the opened root; state any trusted-namespace
assumption. Preserve platform refusals and source/target regularity checks.

Run the proposed adversarial tests, no-engine/Hermes suites and runtime fixtures.
Push only after qualification and final review. Vendor integration remains a
separate commit. The implementer accepted these conditions.

The actual NT probe showed that removing OBJ_CASE_INSENSITIVE still folds case
on ordinary NTFS, but distinguishes names in a case-sensitive directory. The
parent approved correcting the text to separate exact lexical authority from
filesystem lookup policy, and required regressions for both behaviors. The
held-handle FileFsDeviceInformation query succeeded and is the locality check.

The parent separately approved the quoted-filesystem-target amendment before
grammar implementation. Conditions: only fs.read/fs.write decode one complete
JSON string, never parse decoded content as lines, reject the entire set on bad
input, and preserve unquoted grammar. Round-trip claims must exclude legacy
programmatic POSIX/app controls; quoted controls are explicitly refused.
Exact's shared exact-grants consumer propagation remains a separate review.

## Implementation review

The parent independently read native path admission/execution, directory NT
opens and retained-drive locality checks, regularity/identity/atomic paths,
app refactoring and quoted-target parsing. No blocking issue was found. Its
scope question about native `sqlite.open` syntax led to an explicit regression:
the shared prefix constructor accepts the spelling, but Windows
`resolve_sqlite` still refuses it before provider access or file creation.

A second independent same-family agent (`/root/skirmish_gameplay`) performed a
bounded read-only source review of the LLP, implementation and adversarial
tests. It found no blocker in admission, held roots/ancestors/operands,
local-device qualification, regularity/identity-before-truncate, exact lexical
case namespaces or one-pass JSON parsing. It confirmed that hard-link sharing
and per-operation path identity limitations are accurately documented. It
required retaining symlink-privilege/8.3 availability limits and rerunning the
current parser/Rust-consumer fixtures. It did not independently rerun the
implementer's full suites; this record does not claim otherwise.
