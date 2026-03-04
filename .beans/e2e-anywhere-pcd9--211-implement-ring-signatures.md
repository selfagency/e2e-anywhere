---
# e2e-anywhere-pcd9
title: 2.11 Implement ring signatures
status: completed
type: feature
priority: critical
created_at: 2026-03-04T05:04:17Z
updated_at: 2026-03-04T05:04:17Z
parent: e2e-anywhere-371s
---

Implement RSig and RVrf with best-effort constant-time helper paths and residual timing-risk documentation.

## Summary of Changes

- Added `packages/core/src/crypto/ring-sig.ts` implementing OTRv4 RSig/RVrf for 3-member rings.
- `hashToScalar`: SHAKE-256("OTRv4" || 0x1A || parts, 57) → LE bigint mod q.
- `rsig(sk, ring, m)`: returns 342-byte sigma (c1‖r1‖c2‖r2‖c3‖r3); signer position detected via `bytesToHex` comparison; real Schnorr nonce for signer, simulated c/r for others.
- `rvrf(ring, sigma, m)`: recomputes T_j = G·r_j + A_j·c_j, rehashes, checks h === c1+c2+c3 mod q.
- `RING_SIG_BYTES = 342` exported constant.
- Added `tests/phase2/ring-sig.test.ts` with 13 tests covering all three signer positions, tampered components, wrong message, ring mismatch, bad length, all-zeros, and randomness.
