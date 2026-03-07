---
# e2e-anywhere-epoo
title: 3.16 Interactive DAKE handshake
status: completed
type: feature
priority: critical
created_at: 2026-03-04T05:04:33Z
updated_at: 2026-03-07T05:02:55Z
parent: e2e-anywhere-wdw9
---

---

## branch: feature/e2e-anywhere-epoo-316-interactive-dake-handshake

## Todo

- [ ] Define DAKE state types and `WAITING_*` constants in `interactive-dake.ts`
- [ ] Implement `initiateDAKE` (send Identity message)
- [ ] Implement `handleIdentity` (derive `K`, `phi`, send Auth-R)
- [ ] Implement `handleAuthR` (verify RingSig, compute `K`, send Auth-I)
- [ ] Implement `handleAuthI` (verify RingSig, finalize initialization)
- [ ] Add MV3 session storage persistence for DAKE resume/restart
- [ ] Implement timeout recovery logic (30s clear)
- [ ] Write Vitest integration test for DAKEZ flow with two virtual parties
