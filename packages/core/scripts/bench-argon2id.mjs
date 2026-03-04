#!/usr/bin/env node
/**
 * Bean j285 — Phase 2.15 Argon2id baseline benchmark.
 *
 * Measures the wall-clock time for Argon2id key derivation under the
 * baseline parameters defined in docs/security/security-invariants.md:
 *
 *   m = 65536 (64 MiB)
 *   t = 3     (3 iterations)
 *   p = 1     (single lane)
 *   hashLength = 32 bytes
 *
 * Performance budget: single Argon2id derivation ≤ 1000 ms
 * (see docs/performance-budgets.md)
 *
 * Usage:
 *   node scripts/bench-argon2id.mjs
 *   node scripts/bench-argon2id.mjs --runs 10
 *
 * Run from the @e2e-anywhere/core package root, or via:
 *   pnpm --filter @e2e-anywhere/core exec node scripts/bench-argon2id.mjs
 */

import { argon2id } from 'hash-wasm';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const BASELINE = {
  iterations: 3, // t
  parallelism: 1, // p
  memorySize: 65536, // m = 64 MiB (in KiB)
  hashLength: 32, // 256-bit derived key
};

// Total number of benchmark runs (first result is discarded as warm-up)
const args = process.argv.slice(2);
const runsIdx = args.indexOf('--runs');
const RUNS = runsIdx !== -1 ? parseInt(args[runsIdx + 1] ?? '5', 10) : 5;
const WARMUP = 1;

// Performance budget from docs/performance-budgets.md
const BUDGET_MS = 1000;

// ---------------------------------------------------------------------------
// Benchmark helpers
// ---------------------------------------------------------------------------

function percentile(sorted, p) {
  const idx = Math.ceil((sorted.length * p) / 100) - 1;
  return sorted[Math.max(0, idx)];
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

console.log('Argon2id baseline benchmark');
console.log(
  `Parameters: m=${BASELINE.memorySize} KiB, t=${BASELINE.iterations}, p=${BASELINE.parallelism}, hashLength=${BASELINE.hashLength} bytes`,
);
console.log(`Runs: ${RUNS + WARMUP} (${WARMUP} warm-up + ${RUNS} measured)`);
console.log(`Performance budget: ${BUDGET_MS} ms\n`);

const timings = [];

for (let i = 0; i < RUNS + WARMUP; i++) {
  // Different password/salt per run to defeat any caching
  const password = new Uint8Array(32).map((_, j) => (i * 7 + j) & 0xff);
  const salt = new Uint8Array(16).map((_, j) => (i * 13 + j + 99) & 0xff);

  const start = performance.now();
  await argon2id({
    password,
    salt,
    ...BASELINE,
    outputType: 'binary',
  });
  const elapsed = performance.now() - start;

  if (i < WARMUP) {
    console.log(`  warm-up: ${elapsed.toFixed(1)} ms`);
  } else {
    timings.push(elapsed);
    console.log(`  run ${i - WARMUP + 1}: ${elapsed.toFixed(1)} ms`);
  }
}

const sorted = [...timings].sort((a, b) => a - b);
const mean = timings.reduce((s, x) => s + x, 0) / timings.length;
const min = sorted[0];
const max = sorted[sorted.length - 1];
const p50 = percentile(sorted, 50);
const p95 = percentile(sorted, 95);

console.log('\n--- Results ---');
console.log(`Mean:   ${mean.toFixed(1)} ms`);
console.log(`Min:    ${min.toFixed(1)} ms`);
console.log(`Max:    ${max.toFixed(1)} ms`);
console.log(`p50:    ${p50.toFixed(1)} ms`);
console.log(`p95:    ${p95.toFixed(1)} ms`);
console.log(`Budget: ${BUDGET_MS} ms`);
console.log(`Status: ${max <= BUDGET_MS ? '✓ PASS' : '✗ FAIL (exceeds budget)'}`);

if (max > BUDGET_MS) {
  console.error(`\nFAIL: Maximum timing ${max.toFixed(1)} ms exceeds budget of ${BUDGET_MS} ms.`);
  console.error('Consider reducing m, t, or p parameters with security review sign-off.');
  process.exit(1);
}
