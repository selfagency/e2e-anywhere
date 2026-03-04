---
# e2e-anywhere-78em
title: 2.12.2 Explicit DH group-membership validator
status: completed
type: task
priority: high
created_at: 2026-03-04T05:04:22Z
updated_at: 2026-03-04T05:04:22Z
parent: e2e-anywhere-86v1
---

Expose validateDHGroupMembership(publicKey: bigint) and add edge-case tests for 0,1,p-1,p and valid random members.

## Summary of Changes

- Exported `DH_P` constant from `packages/core/src/crypto/dh3072.ts` so tests can reference boundary values.
- Added `validateDHGroupMembership(pubKey: bigint): boolean` to `dh3072.ts` — boolean-returning complement to the throwing `validatePublicKey`; returns true iff pubKey ∈ [2, p-2].
- Added 7 edge-case tests to `tests/phase2/dh3072.test.ts` in a nested `validateDHGroupMembership` suite: rejects 0, 1, p-1, p; accepts fresh keypair, 2 (lower boundary), and p-2 (upper boundary).
- Total dh3072 test count: 14.
