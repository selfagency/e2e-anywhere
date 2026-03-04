# Threat Model

## Scope and goals

This document defines the threat model for `e2e-anywhere` Phase 0.

Primary goals:

- Preserve confidentiality and integrity of OTR-protected content in transit.
- Prevent accidental persistence or disclosure of decrypted plaintext.
- Preserve user deniability properties defined by OTRv4 interactive mode.
- Provide user-visible tamper-evidence and integrity anomaly notifications.

## Assets

- Long-term identity secrets and derived key material.
- Ephemeral session state and ratchet keys.
- Decrypted message plaintext (transient display only).
- Fingerprints, SSID, SMP state, and trust decisions.
- Extension code and release artifacts.

## Trust boundaries

- Browser extension context (service worker, content scripts, extension UI) is trusted code.
- Platform page JavaScript and DOM are untrusted.
- Network and platform servers are untrusted transports.
- Local operating system and endpoint integrity are partially trusted but can be compromised.
- Package/dependency and extension delivery supply chain are trust-sensitive boundaries.

## Adversaries

- Network observer or active MITM.
- Malicious platform DOM and page JavaScript.
- Malicious browser extension with overlapping privileges.
- Local attacker with memory or process inspection capability.
- Supply-chain attacker (dependency compromise or distribution-channel compromise).

## Assumptions

- Browser cryptographic primitives execute correctly when available.
- Users verify identities (fingerprint or SMP) when authenticity is required.
- OTRv4 security properties apply only to OTRv4 sessions and compatible flows.
- Service-worker lifecycle is ephemeral and state can be interrupted at any time.

## In-scope threats

- Message tampering, replay, malformed-frame parsing attempts.
- DOM-level manipulation of rendered encrypted/decrypted artifacts.
- Side-channel observability by page JavaScript:
  - OTR frame timing.
  - DOM mutation patterns.
- Contact graph inference by local attacker with memory access:
  - Session-map contents may reveal conversation participants.
- Dependency and release supply-chain compromise.
- Manifest/permission drift and storage-envelope corruption.

## Out-of-scope for prevention (still documented)

- Full endpoint compromise by local malware is out-of-scope for prevention.
  - Rationale: malware with host-level privileges can inspect memory/UI and bypass client controls.
  - Mitigation stance: best-effort tamper-evidence, integrity mismatch warnings, and recovery guidance.

## Side-channel considerations

Residual side channels are expected and documented:

- DOM mutation/timing observability from untrusted page scripts.
- Runtime timing noise and non-deterministic GC behavior in JavaScript runtimes.
- Potential UI fingerprinting from extension-injected artifacts.

Mitigation posture:

- Reduce signal where feasible (bounded parsing/reassembly behavior, optional timing jitter where acceptable).
- Avoid introducing high-amplitude deterministic patterns.
- Document residual risk explicitly for users and reviewers.

Additional implementation constraints:

- Content-script DOM observation must be scoped to known message containers and debounced to reduce mutation-amplification side effects on large/infinite-scroll views.
- Non-urgent UI mutations (e.g., badge decoration) should use idle-time scheduling to reduce deterministic mutation bursts.

## Supply-chain and distribution risks

- A compromised upstream package can pass audit at publication time and still be malicious.
- A compromised Chrome Web Store publisher/update path can deliver malicious auto-updates.

Mitigation posture:

- Exact dependency pinning and lockfile integrity checks.
- CI audit gates and reproducible release process.
- Post-v1 evaluation of hardened release channel options.

## WASM and execution-boundary risks

- Argon2id may require `wasm-unsafe-eval` under MV3 CSP; this expands the effective trust boundary to extension JavaScript entry points that can load WASM.
- Mitigation: constrain WASM usage to dedicated short-lived Worker contexts where feasible, and terminate Workers immediately after derivation to reduce long-lived exposure.
- Residual risk remains: any compromised extension code path capable of loading WASM can execute attacker-controlled WASM payloads.

## Integrity/tamper-evidence stance

When integrity anomalies are detected (storage envelope mismatch, version-tag mismatch, manifest/permission drift, import corruption), the extension must:

- Fail closed for affected operation.
- Inform the user with clear recovery actions.
- Avoid silent fallback to weaker behavior.

## Non-goals

- Perfect protection against privileged local attackers.
- Complete elimination of all timing or side-channel leakage in browser JavaScript execution environments.
