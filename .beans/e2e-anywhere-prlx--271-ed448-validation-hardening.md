---
# e2e-anywhere-prlx
title: 2.14 Ed448 validation hardening
status: completed
type: task
priority: high
created_at: 2026-03-04T05:04:22Z
updated_at: 2026-03-04T15:57:25Z
parent: e2e-anywhere-371s
---

Reject identity and small-order points in decode/validation acceptance paths aligned to OTRv4 contributory behavior.

## Summary of Changes

- Added `validatePoint(bytes: Uint8Array): boolean` export to `packages/core/src/crypto/ed448.ts`.
- Rejects inputs that are not exactly 57 bytes.
- Rejects points where `point.isSmallOrder()` is true (identity + cofactor-order points).
- Rejects points where `!point.isTorsionFree()` (confirms prime-order subgroup membership).
- Returns `false` on any exception (malformed/non-canonical encodings).
- Added 6 tests to `tests/phase2/ed448.test.ts`: valid keypair passes; all-zeros fails; wrong length fails; all-0xFF fails; multiple fresh keypairs all pass.
- Protects against: identity point injection, small-subgroup attacks, non-canonical encodings.
