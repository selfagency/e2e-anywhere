---
# e2e-anywhere-371s
title: Phase 2 — Cryptographic Primitives
status: completed
type: epic
priority: critical
created_at: 2026-03-04T05:03:28Z
updated_at: 2026-03-04T05:04:22Z
---

Track implementation and verification of OTRv4 cryptographic primitives, vectors, robustness checks, and Argon2id feasibility outcomes.

## Summary of Changes

All Phase 2 child beans completed. 104 tests passing.

- **oysc** (2.6): Adopted `@noble/curves@2.0.1`, `@noble/hashes@2.0.1`, `@noble/ciphers@2.1.1`, `hash-wasm@4.12.0` dependencies.
- **vssq** (2.7): Ed448 `sign`, `verify`, `generateKeypair` wrappers.
- **kw2g** (2.8): DH-3072 (RFC 3526 MODP Group 15) `generateKeypair`, `computeSharedSecret`, `validatePublicKey`, `serializePublicKey`, `deserializePublicKey`.
- **78em** (2.8.1): `validateDHGroupMembership(bigint): boolean` + edge-case tests (0, 1, 2, p-2, p-1, p).
- **a6lf** (2.9): KDF (HKDF-SHA512 / HMAC-SHA512) `deriveKey`, `hmac`.
- **rv8v** (2.10): ChaCha20-Poly1305 `encrypt`, `decrypt` wrappers.
- **pcd9** (2.11): OTRv4 RSig/RVrf ring signatures for 3-member rings (342-byte wire format).
- **86v1** (2.12): Property-based tests for all 5 crypto primitives (22 tests).
- **4sdp** (2.12.1): Argon2id library selection record in `docs/security/security-invariants.md`.
- **cj44** (2.13): Side-channel and robustness harnesses (19 tests).
- **prlx** (2.14): `validatePoint()` — rejects identity, small-order, and non-canonical Ed448 points.
- **j285** (2.15): Argon2id baseline benchmark (`packages/core/scripts/bench-argon2id.mjs`); ~143ms on M1, well within 1000ms budget.
