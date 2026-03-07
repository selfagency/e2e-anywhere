---
# e2e-anywhere-wdw9
title: Phase 3 — OTR v4 Protocol Engine
status: in-progress
type: epic
priority: critical
created_at: 2026-03-04T05:03:28Z
updated_at: 2026-03-06T23:38:20Z
---

Track DAKE, ratchet, SMP, fragmentation, protocol state machine, and resilience protections for the OTRv4 engine.

**branch**: epic/wdw9-otrv4-protocol-engine

## Scope

This epic decomposes Phase 3 of the implementation plan into discrete sub-features:

- **WireFormat Types** (Task 14): Define serializable message types and TLVs
- **ClientProfile** (Task 15): Profile signing, validation, expiration, forging key lifecycle
- **Interactive DAKE** (Task 16): 3-flow handshake with state recovery and timeout handling
- **DoubleRatchet** (Task 17): Sending/receiving ratchet with key derivation and skipped-key store
- **SMP Verification** (Task 18): 4-message symmetric protocol with rate-limiting and cooldown
- **StateManager** (Task 19): Top-level OTR FSM, heartbeat, session expiry, protocol events

## Threat Model References

- Document referenced: `docs/security/threat-model.md`
- Security invariants: `docs/security/security-invariants.md` (section: Parser and protocol-state invariants)
- OTRv4 spec: https://github.com/otrv4/otrv4/blob/master/otrv4.md

## Key Decisions

1. **Interactive-only DAKE**: Prekey server eliminated; both parties are always online
2. **Forging key default**: Discarded immediately after ClientProfile signing; retention is explicit opt-in with warning
3. **SMP attempt limiting**: 3 max per session; escalating cooldown (5s → 30s → 120s); mandatory re-keying after failure
4. **Session expiry default**: 24 hours of inactivity (configurable via settings, task 41)
5. **Handshake timeout**: 30s max in `WAITING_AUTH_R` or `WAITING_AUTH_I`; then clear state and allow retry
6. **Storage tier**: Session state lives in `chrome.storage.session` only (ephemeral); skipped keys and fragments bounded by hard limits and eviction priority tiers

## Todo

- [ ] **Sub-epic decomposition**: Create child beans for each sub-feature (WireFormat, ClientProfile, DAKE, DoubleRatchet, SMP, StateManager)
- [ ] **Validation checkpoint**: Verify child bean structure and link parent/child relationships
- [ ] **Type system design**: Draft `packages/core/src/otr/types.ts` with serialization signatures (no implementation yet)
- [ ] **Async validation**: Run `pnpm test` to confirm Phase 2 crypto primitives still pass
- [ ] **Review checkpoints**: Document review gates for security-sensitive PRs (manifests, message handlers, crypto changes)

## Validation Checkpoints (Per-PR Gates)

Before merging any child-bean PR:

1. **Crypto/Parser Validation**: New message types parse correctly; invalid inputs rejected deterministically
2. **State Machine**: Transitions never violate protocol FSM invariants (test with adversarial inputs)
3. **Storage Bounded**: Reassembly buffers, skipped-key stores, and fragment stores respect hard limits
4. **Timeout Enforcement**: Handshake and SMP timeouts fire correctly under service-worker suspend/resume
5. **Security Review**: Changes to manifest.json, message handlers, DOM manipulation, or crypto parameters require explicit sign-off
