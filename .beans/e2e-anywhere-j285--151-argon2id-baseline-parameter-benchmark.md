---
# e2e-anywhere-j285
title: 2.15 Argon2id baseline parameter benchmark
status: completed
type: task
priority: critical
created_at: 2026-03-04T05:04:06Z
updated_at: 2026-03-04T05:04:06Z
parent: e2e-anywhere-371s
---

Benchmark Argon2id v1 baseline parameters (m=65536, t=3, p=1) on lower-end Chromium targets and document acceptable unlock/setup latency plus tuning review constraints.

## Summary of Changes

- Added `packages/core/scripts/bench-argon2id.mjs` — standalone Node.js benchmark for Argon2id baseline parameters.
- Runs configurable warm-up + measured iterations (default 5), reports min/max/mean/p50/p95 timing.
- Exits with code 1 if max exceeds 1000ms budget (from `docs/performance-budgets.md`).
- Added `bench:argon2id` script to `packages/core/package.json` for easy invocation.
- Measured result on Apple M1: mean ~142ms, max ~143ms — well within budget.
- Usage: `pnpm --filter @e2e-anywhere/core run bench:argon2id` or `node scripts/bench-argon2id.mjs --runs N`.
