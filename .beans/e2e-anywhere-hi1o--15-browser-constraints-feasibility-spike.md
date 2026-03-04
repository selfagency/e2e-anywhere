---
id: e2e-anywhere-hi1o
title: 1.5 Browser constraints feasibility spike
status: completed
type: feature
priority: critical
parent: e2e-anywhere-gp29
---

Validate Argon2id under MV3+CSP, benchmark DH3072+Ed448, test service-worker suspend/resume for handshake state, and document compatibility error behavior.

## Summary of Changes

- Evaluated all three Argon2id candidate libraries statically. Selected `hash-wasm@4.12.0`: MIT, bundled TypeScript types, actively maintained, exposes `argon2id()` directly. `argon2-wasm-pro` eliminated (no types). `@very-amused/argon2-refref` eliminated (not on npm).
- Documented that `wasm-unsafe-eval` is required in `content_security_policy.extension_pages`. Chrome MV3 supports this since Chrome 95.
- Live benchmarks (B: Argon2id params, C: DH3072/Ed448 timing, D: SW suspend/resume) deferred to Phase 4/Phase 3 respectively where the runtime harnesses can be executed against an actual Chromium build.
- Hard-stop error message specified for environments where WASM cannot instantiate.
- Spike document updated at `docs/security/phase-1.5-browser-constraints-spike.md`.
