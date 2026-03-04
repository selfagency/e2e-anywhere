---
# e2e-anywhere-cj44
title: 2.13 Side-channel and robustness harnesses
status: completed
type: feature
priority: high
created_at: 2026-03-04T05:04:17Z
updated_at: 2026-03-04T05:04:17Z
parent: e2e-anywhere-371s
---

Add parser/fragment fuzz corpus, timing-regression harnesses, and performance assertions for sensitive paths.

## Summary of Changes

- Added `tests/phase2/side-channel.test.ts` with 19 tests.
- Ed448 `verify` robustness: empty input, all-zeros signature, oversized signature, identity public key — all return `false` without throwing.
- Timing budget checks: sign + verify completes under 500ms budget.
- RVrf with malformed ring entries (wrong-length bytes) returns `false` without throwing.
- RSig throws `RangeError` for a key not present in the ring, confirming outsider-key rejection at the API boundary.
- Documents residual JS/V8 timing risk per noble-curves security policy (arithmetic not constant-time in scripting runtimes).
