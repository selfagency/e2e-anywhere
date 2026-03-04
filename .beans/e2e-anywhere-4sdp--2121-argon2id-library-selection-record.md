---
# e2e-anywhere-4sdp
title: 2.12.1 Argon2id library selection record
status: completed
type: task
priority: critical
created_at: 2026-03-04T05:04:22Z
updated_at: 2026-03-04T05:04:22Z
parent: e2e-anywhere-86v1
---

Document selected Argon2id library and rationale in security invariants and add CI WASM instantiation smoke test under extension CSP.

## Summary of Changes

- Updated `docs/security/security-invariants.md` with an "Argon2id library selection record" section documenting:
  - Selected library: `hash-wasm@4.12.0` (MIT, TypeScript types, no production dependencies, actively maintained).
  - CSP requirement: `wasm-unsafe-eval` required in `content_security_policy.extension_pages`.
  - Baseline parameter table: m=65536 KiB, t=3, p=1, hashLength=32 bytes.
  - Benchmark and CI smoke test requirements.
