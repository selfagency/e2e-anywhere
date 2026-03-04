---
# e2e-anywhere-86v1
title: 2.12 Primitive unit/property tests
status: completed
type: feature
priority: high
created_at: 2026-03-04T05:04:17Z
updated_at: 2026-03-04T05:04:17Z
parent: e2e-anywhere-371s
---

Add vectors and property tests for all primitives, including encode/decode round-trips and membership checks.

## Summary of Changes

- Added `tests/phase2/property-tests.test.ts` with 22 property-based tests spanning all 5 crypto modules.
- Ed448: sign/verify round-trip, signature length, wrong-message rejection, wrong-key rejection, determinism.
- DH3072: shared-secret equality (Alice/Bob), serialize/deserialize round-trip, `validatePublicKey` rejects weak keys.
- KDF: deterministic output, correct output length, distinct outputs for different inputs.
- ChaCha20: encrypt/decrypt round-trip, output length, tampered ciphertext, wrong key, wrong nonce.
- Ring signatures: all three signer positions produce valid/verifiable signatures, randomness, forgery rejection, wrong-message rejection.
