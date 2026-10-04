#!/usr/bin/env node
/**
 * metrics — the speed numbers that matter for Ibex 2, in one run under 30 s
 * on a warm build. Diagnostic, never blocking (rules/RULES.md §Loop shape).
 *
 *   node scripts/metrics.mjs             table
 *   node scripts/metrics.mjs --json      one JSON object
 *   node scripts/metrics.mjs --record    also append the JSON line to metrics/ibex2-speed.jsonl
 *
 * The in-process numbers come from crates/ibex2/examples/speed.rs; this adds
 * what only a process can show — cold start, RSS — and what "tighter" means
 * in bytes and lines. Budgets are read from rules/RULES.md so they cannot
 * drift from the prose.
 */
import { spawnSync } from 'node:child_process';
import {
  appendFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { cpus, hostname, loadavg, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const t0 = Date.now();
const ROOT = resolve(new URL('..', import.meta.url).pathname);
const json = process.argv.includes('--json');
const record = process.argv.includes('--record');
const rules = readFileSync(resolve(ROOT, 'rules/RULES.md'), 'utf8');
const budget = (label) =>
  rules.match(new RegExp(`\\|\\s*\\**${label}[^|]*\\|\\s*\\**([^|\\n*]+)`, 'i'))?.[1].trim() ?? '?';
const budgetMs = (label) => Number.parseFloat(budget(label));
const run = (cmd, args, opts = {}) => spawnSync(cmd, args, { cwd: ROOT, encoding: 'utf8', ...opts });
const fail = (what, r) => { console.error(`${what} failed:\n${r.stderr ?? ''}`); process.exit(1); };

const out = {
  date: `${new Date().toISOString().slice(0, 19)}Z`,
  commit: run('git', ['rev-parse', '--short', 'HEAD']).stdout.trim(),
  host: hostname(),
  // The 1-minute load average when the run started, so a reader can discount
  // a number taken on a busy machine — a run under a load of 150 doubled
  // every row and would have been read as a regression.
  load1: +loadavg()[0].toFixed(1),
  cores: cpus().length,
};
const loaded = out.load1 > out.cores / 2;
const step = (name, f) => { const t = Date.now(); const v = f(); out[`_${name}_s`] = +((Date.now() - t) / 1000).toFixed(2); return v; };
const BIN = resolve(ROOT, 'target/release/ibex2');
const SPEED = resolve(ROOT, 'target/release/examples/speed');

// 1. The build. A no-op on a warm cache; its time is reported, not counted as speed.
step('build', () => {
  const r = run('cargo', ['build', '-q', '--release', '-p', 'ibex2', '--features', 'hermes', '--bin', 'ibex2', '--example', 'speed']);
  if (r.status !== 0) fail('cargo build', r);
});

// 2. In process: the floor by phase, graphs from source and bytecode, the boundary.
step('inprocess', () => {
  const r = run(SPEED);
  if (r.status !== 0) fail('examples/speed', r);
  Object.assign(out, JSON.parse(r.stdout.trim().split('\n').pop()));
});

// 3. A process: cold start of a precompiled one-module program, and its RSS.
//    Spawn overhead is included — it is what a user of the binary pays too.
step('process', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ibex2-metrics-'));
  try {
    const entry = join(dir, 'hello.js');
    writeFileSync(entry, "console.log('hello');\n");
    const build = run(BIN, ['build', entry]);
    if (build.status !== 0) { out.process_note = `build: ${build.stderr.trim().split('\n').pop()}`; return; }
    const args = ['run', entry, '--precompiled'];
    run(BIN, args); // warm the page cache
    const samples = [];
    for (let i = 0; i < 7; i++) {
      const t = process.hrtime.bigint();
      const r = run(BIN, args);
      if (r.status !== 0) { out.process_note = `run: ${r.stderr.trim().split('\n').pop()}`; return; }
      samples.push(Number(process.hrtime.bigint() - t) / 1e6);
    }
    samples.sort((a, b) => a - b);
    out.process_start_ms = +samples[3].toFixed(2);
    out.process_start_min_ms = +samples[0].toFixed(2);
    if (process.platform === 'darwin') {
      const r = run('/usr/bin/time', ['-l', BIN, ...args]);
      const m = r.stderr.match(/(\d+)\s+maximum resident set size/);
      if (m) out.process_rss_kib = Math.round(Number(m[1]) / 1024);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// 4. Size: what "tighter" means in bytes and lines. The run-only binary —
//    no loader, no Oxc — is built into its own target dir so the two feature
//    sets do not evict each other; warm, that is a relink.
step('size', () => {
  out.binary_bytes = statSync(BIN).size;
  const runOnly = run('cargo', ['build', '-q', '--release', '--no-default-features', '--features', 'hermes', '-p', 'ibex2', '--bin', 'ibex2', '--target-dir', 'target/run-only']);
  if (runOnly.status === 0) out.binary_run_only_bytes = statSync(resolve(ROOT, 'target/run-only/release/ibex2')).size;
  const bindingsDir = resolve(ROOT, 'crates/ibex2/src/bindings');
  out.bindings_js_bytes = readdirSync(bindingsDir)
    .filter((f) => f.endsWith('.js') && f !== 'testharness.js')
    .reduce((n, f) => n + statSync(join(bindingsDir, f)).size, 0);
  const lines = (dir) => {
    let n = 0;
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) n += lines(p);
      else if (/\.(rs|cc|mm|h)$/.test(e.name)) n += readFileSync(p, 'utf8').split('\n').length;
    }
    return n;
  };
  out.runtime_lines = lines(resolve(ROOT, 'crates/ibex2/src'));
});

// The budget row: the floor plus a 500-module bytecode graph, against RULES.md.
if (Number.isFinite(out.floor_ms) && Number.isFinite(out.graph_500_bytecode_ms)) {
  out.boot_500_ms = +(out.floor_ms + out.graph_500_bytecode_ms).toFixed(2);
}
out.total_s = +((Date.now() - t0) / 1000).toFixed(1);

if (record) {
  mkdirSync(resolve(ROOT, 'metrics'), { recursive: true });
  appendFileSync(resolve(ROOT, 'metrics/ibex2-speed.jsonl'), `${JSON.stringify(out)}\n`);
}
if (json) { console.log(JSON.stringify(out)); process.exit(0); }

const ms = (v) => (Number.isFinite(v) ? `${v.toFixed(v < 10 ? 2 : 1)} ms` : 'n/a');
const us = (v) => (Number.isFinite(v) ? `${v.toFixed(v < 10 ? 2 : 0)} µs` : 'n/a');
const ns = (v) => (Number.isFinite(v) ? `${v.toFixed(0)} ns` : 'n/a');
const kib = (v) => (Number.isFinite(v) ? `${v.toFixed(0)} KiB` : 'n/a');
const entryBudget = budgetMs('Process start');
const rows = [
  ['floor: runtime ready for app code', ms(out.floor_ms),
    `cold ${ms(out.floor_cold_ms)} · create ${ms(out.floor_create_ms)} · bindings ${ms(out.floor_bindings_ms)} · freeze ${ms(out.floor_freeze_ms)} (budget ${budget('Intrinsic freeze')}: ${out.floor_freeze_ms <= budgetMs('Intrinsic freeze') ? 'ok' : 'OVER'})`],
  ['100 modules from bytecode', ms(out.graph_100_bytecode_ms), `the same graph from source: ${ms(out.graph_100_source_ms)}`],
  ['500 modules from bytecode', ms(out.graph_500_bytecode_ms),
    `min ${ms(out.graph_500_bytecode_min_ms)} = ${us(out.graph_500_bytecode_per_module_us)} per module — track the min`],
  ['floor + 500 modules', ms(out.boot_500_ms),
    `budget ${budget('Process start')} to app entry: ${out.boot_500_ms <= entryBudget ? 'ok' : 'OVER'}`],
  ['500 modules, AOT build', ms(out.graph_500_build_ms), 'hermesc, one module at a time — the dev-loop cost'],
  ['process: cold start, precompiled', ms(out.process_start_ms),
    out.process_note ?? `min ${ms(out.process_start_min_ms)} · one module, spawn included · RSS ${kib(out.process_rss_kib)}`],
  ['sync host call', ns(out.sync_host_call_ns), 'performance.now() through its binding'],
  ['async host task round trip', us(out.async_fs_roundtrip_us), 'fs.readFile of one byte, back through the loop'],
  ['BLOB install group', us(out.blob_floor_us),
    `floor delta · ${kib(out.blob_bytecode_bytes / 1024)} bytecode (budgets 50 µs / 150 KiB: ${out.blob_floor_us <= 50 && out.blob_bytecode_bytes <= 150 * 1024 ? 'ok' : 'OVER'})`],
  ['binary', kib(out.binary_bytes / 1024), `run-only ${kib(out.binary_run_only_bytes / 1024)} · runtime ${out.runtime_lines} lines · JS bindings ${kib(out.bindings_js_bytes / 1024)}`],
];
console.log(`ibex2 metrics — ${out.date}, ${out.commit}, warm build, medians (min where noise matters), load ${out.load1} on ${out.cores} cores${loaded ? ' — LOADED: do not read these as a trend' : ''}`);
for (const [k, v, note] of rows) console.log(`  ${k.padEnd(34)} ${v.padStart(11)}   ${note}`);
console.log(
  `  ${'total'.padEnd(34)} ${`${out.total_s} s`.padStart(11)}   build ${out._build_s} s · in-process ${out._inprocess_s} s · process ${out._process_s} s` +
  (out.total_s > 30 ? '   OVER the 30 s this script promises' : ''),
);
