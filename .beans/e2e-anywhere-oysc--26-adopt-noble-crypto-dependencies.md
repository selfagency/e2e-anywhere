---
# e2e-anywhere-oysc
title: 2.6 Adopt @noble crypto dependencies
status: completed
type: feature
priority: critical
created_at: 2026-03-04T15:25:34Z
updated_at: 2026-03-04T15:53:56Z
parent: e2e-anywhere-371s
---

Add @noble/curves, @noble/hashes, and @noble/ciphers as sole crypto dependencies with exact pinned versions and lock integrity. Also add hash-wasm for Argon2id (selected in Phase 1.5 spike).

## Branch

feature/e2e-anywhere-oysc-phase-2-crypto-primitives

## Todo

- [ ] Write failing test verifying @noble package exports are importable
- [ ] Install @noble/curves@2.0.1, @noble/hashes@2.0.1, @noble/ciphers@2.1.1, hash-wasm@4.12.0 in packages/core
- [ ] Update packages/core/package.json with exact pins
- [ ] Confirm test passes
- [ ] Commit
