#!/usr/bin/env node
// @ref LLP 0058.000.001#5-build-artifact-and-dependency-isolation — HermesInputReceipt (G0)
/**
 * Produce a HermesInputReceipt for an installed Hermes engine.
 *
 * A distinct producer, deliberately: LLP 0058.000.001 §5 requires the four
 * receipt schemas to have distinct producers and no self-hash, and keeping this
 * out of build-hermes.sh also means the reviewed engine's cache identity does
 * not move every time the receipt format does.
 *
 * The claim the receipt makes is narrow and checkable: THIS engine was built
 * from THIS upstream commit with an EMPTY Ibex patch set. "Vanilla" stops being
 * a build flag someone remembered to pass and becomes a property of an artifact.
 *
 *   node scripts/hermes-input-receipt.mjs <engine-dir> [--out <path>] [--commit <sha>]
 *
 * Exits non-zero if the engine carries patched symbols, which is the one thing
 * a receipt claiming an empty patch set must never be written over.
 */

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCHEMA = 'ibex/hermes-upstream-pinned-receipt/1';

/** The digest of an empty patch set — what "vanilla" has to hash to. */
const CANONICAL_EMPTY_PATCH_SET = createHash('sha256').update('').digest('hex');

/** Symbols the carried patch series exports. Their absence is the evidence. */
const PATCHED_SYMBOLS = [
  'ex_hermes_vm_current_package_id',
  'ex_hermes_vm_collect_package_ids',
  'ex_hermes_vm_disable_eval',
  'ex_hermes_vm_set_pending_package_id',
];

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function die(message) {
  console.error(`hermes-input-receipt: ${message}`);
  process.exit(1);
}

function flagValue(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) {
    return undefined;
  }
  const value = argv[index + 1];
  if (!value || value.startsWith('--')) {
    die(`${name} requires a value`);
  }
  return value;
}

const args = process.argv.slice(2);
if (args.length < 1 || args[0].startsWith('--')) {
  die('usage: hermes-input-receipt.mjs <engine-dir> [--out <path>] [--commit <sha>]');
}
const engineDir = resolve(args[0]);
const outPath = flagValue(args, '--out') ?? join(engineDir, 'hermes-input-receipt.json');
const commitOverride = flagValue(args, '--commit');

const engineCandidates = [
  join(engineDir, 'hermesvm.framework/Versions/1/hermesvm'),
  join(engineDir, 'linux-static/libhermesvm_a.a'),
  join(engineDir, 'windows-static/hermesvm_a.lib'),
];
const engineBinary = engineCandidates.find(existsSync);
if (!engineBinary) {
  die(`no engine binary at ${engineCandidates.join(' or ')}`);
}

// The negative guarantee, checked rather than asserted: an engine carrying the
// patch stack's exports is not an empty-patch-set engine, whatever produced it.
let exported = '';
try {
  const nmArgs = process.platform === 'darwin'
    ? ['-gU', engineBinary]
    : ['-g', '--defined-only', engineBinary];
  exported = process.platform === 'win32'
    ? execFileSync('dumpbin', ['/symbols', engineBinary], {
        encoding: 'utf8',
        maxBuffer: 128 * 1024 * 1024,
      })
    : execFileSync('nm', nmArgs, { encoding: 'utf8' });
} catch (error) {
  die(`cannot read symbols from ${engineBinary}: ${error.message}`);
}
// Archive member headings are not symbols, and release libhermesvm_a.a also
// defines RuntimeTaskRunner constructors whose parameter type mentions
// AsyncDebuggerAPI. Parse only nm symbol rows and distinguish those references
// from methods actually defined on AsyncDebuggerAPI.
const exportedSymbols = exported
  .split('\n')
  .map((line) => process.platform === 'win32'
    ? (/\bUNDEF\b/.test(line) ? undefined : line.match(/\bExternal\s+\|\s+(\S+)/)?.[1])
    : line.trim().match(/^(?:[0-9a-fA-F]+\s+)?[A-Za-z]\s+(\S+)$/)?.[1])
  .filter(Boolean);
const found = PATCHED_SYMBOLS.filter((patched) =>
  exportedSymbols.some((symbol) => symbol === patched || symbol === `_${patched}`)
);
if (found.length > 0) {
  die(
    `refusing to write an empty-patch-set receipt for a PATCHED engine; it exports ${found.join(', ')}`
  );
}

// The receipt must not claim an empty patch set while a patch series sits in
// the tree as a build input. Recorded, so a reader can tell "no patches exist"
// from "patches exist and were not applied" — only the second needs the check
// above to mean anything.
const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const patchDir = join(repoRoot, 'patches/hermes');
const patchesPresent = existsSync(patchDir)
  ? readdirSync(patchDir).filter((name) => name.endsWith('.patch')).sort()
  : [];

const hostPlatform = process.platform === 'darwin' ? 'macos'
  : process.platform === 'win32' ? 'windows' : process.platform;
const configuredHermesc = process.env.IBEX2_HERMESC;
const hermescCandidate = configuredHermesc
  ? resolve(configuredHermesc)
  : join(repoRoot, 'tools/hermes-vanilla', `hermesc-${hostPlatform}-${process.arch}${process.platform === 'win32' ? '.exe' : ''}`);
if (configuredHermesc && !existsSync(hermescCandidate)) {
  die(`IBEX2_HERMESC does not exist: ${hermescCandidate}`);
}
// `compiler: null` is deliberate for engine-only/run-only installations. A
// build that does have hermesc records and verifies its digest, while a run
// consumes already-receipted bytecode without discovering a compiler.
const hermesc = existsSync(hermescCandidate) ? hermescCandidate : undefined;

let sourceCommit = commitOverride;
let sourceRef = '';
let sourceVersion = '';
try {
  if (process.platform === 'win32') {
    // The native PowerShell builder does not require a Bash installation.
    const pins = readFileSync(join(repoRoot, 'scripts/hermes-version.sh'), 'utf8');
    const literal = (name) => process.env[name]
      || pins.match(new RegExp(`${name}="\\$\\{${name}:-([^}]+)\\}"`))?.[1];
    sourceCommit ||= literal('IBEX_HERMES_VANILLA_SOURCE_COMMIT');
    sourceVersion = literal('IBEX_HERMES_VERSION');
    sourceRef = process.env.IBEX_HERMES_SOURCE_REF || `${sourceVersion}-stable`;
    if (!sourceVersion) throw new Error('source version pin is absent');
  } else {
    const pin = execFileSync(
      'bash',
      [
        '-c',
        'source "$1" && printf "%s\\t%s\\t%s" "$IBEX_HERMES_VANILLA_SOURCE_COMMIT" "$IBEX_HERMES_SOURCE_REF" "$IBEX_HERMES_VERSION"',
        'hermes-input-receipt',
        join(repoRoot, 'scripts/hermes-version.sh').replaceAll('\\', '/'),
      ],
      { encoding: 'utf8' }
    ).trim();
    const [commit, ref, version] = pin.split('\t');
    sourceCommit = sourceCommit || commit;
    sourceRef = ref;
    sourceVersion = version;
  }
} catch (error) {
  die(`cannot read vanilla Hermes pin: ${error.message}`);
}
if (!/^[0-9a-f]{40}$/.test(sourceCommit)) {
  die(`vanilla Hermes pin is not a 40-hex commit: ${sourceCommit}`);
}

const receipt = {
  schema: SCHEMA,
  producedOn: new Date().toISOString().slice(0, 10),
  upstream: {
    artifact: 'facebook/hermes',
    sourceCommit,
    sourceRef,
    sourceVersion,
  },
  engine: {
    binary: basename(engineBinary),
    binaryDigest: `sha256-${sha256File(engineBinary)}`,
    // Debugger-enabled builds are ~35% slower to boot (LLP 0063 §6), so which
    // variant an artifact is must be part of its identity, not folklore.
    variant: exportedSymbols.some((symbol) =>
      /16AsyncDebuggerAPI(?:[0-9]|C[123]|D[012])/.test(symbol) || /\?[^@]+@AsyncDebuggerAPI@/.test(symbol)
    )
      ? 'debugger'
      : 'release',
    target: process.platform === 'darwin' ? 'apple' : process.platform,
  },
  patchSet: {
    // The claim. An empty set hashes to the digest of no input at all.
    digest: `sha256-${CANONICAL_EMPTY_PATCH_SET}`,
    applied: [],
    presentInTree: patchesPresent,
    verifiedAbsentSymbols: PATCHED_SYMBOLS,
  },
  compiler: hermesc
    ? { binary: basename(hermesc), digest: `sha256-${sha256File(hermesc)}` }
    : null,
};

writeFileSync(outPath, `${JSON.stringify(receipt, null, 2)}\n`);
console.log(`wrote ${outPath}`);
console.log(`  upstream      ${receipt.upstream.sourceCommit}`);
console.log(`  variant       ${receipt.engine.variant}`);
console.log(`  patch set     empty (${patchesPresent.length} patches present in tree, 0 applied)`);
console.log(`  hermesc       ${receipt.compiler ? receipt.compiler.binary : '(absent)'}`);
