# Security Invariants

These invariants are non-negotiable and release-blocking.

## Data handling invariants

1. No plaintext or key material logging.
   - Never log decrypted content, passphrases, seeds, private keys, or derived key bytes.
2. No unsafe DOM sinks for decrypted content.
   - Do not use `innerHTML`/equivalent sinks for decrypted user content.
3. No persistence of decrypted plaintext.
   - Decrypted content must exist only transiently in runtime memory and immediate display layer.
   - The extension never persists decrypted plaintext to any storage layer.

## Cryptographic invariants

1. Argon2id is mandatory for passphrase-based key encryption.
   - Baseline parameters (v1): `m=65536` (64 MiB), `t=3`, `p=1`.
   - Parameter changes require benchmark evidence and security review sign-off.
   - No fallback to scrypt, PBKDF2, or weaker alternatives.
   - If conforming Argon2id is unavailable, fail closed with user-visible hard error.
2. Forging key retention defaults to discard.
   - Retention is explicit opt-in with clear risk warning.
3. Key operations must follow protocol-specified validation requirements.
   - Ed448 validation must reject identity and small-order points.
   - Reject malformed points/keys/messages before state transition.

## Parser and protocol-state invariants

1. Strict wire-format validation before state mutation.
   - Parse first, validate fully, transition state only on success.
2. Fragment reassembly and skipped-key storage are bounded.
   - Enforce hard limits on count, bytes, and lifetime.
   - Under storage pressure (>=80% of `chrome.storage.session` quota), evict by priority tiers: fragment buffers first, then oldest skipped keys, while preserving active session/handshake state.
3. DAKE progression must be bounded in time.
   - Handshake states `WAITING_AUTH_R`/`WAITING_AUTH_I` timeout after 30s and are cleared for safe retry.
4. Session state serialization must be version-tagged.
   - On version mismatch, apply migration or discard-and-re-handshake according to storage type.

## Memory/time safety invariants

1. No unbounded growth in reassembly buffers, skipped-key stores, or session maps.
2. Time/space limits must be enforceable and test-covered for adversarial inputs.
3. Best-effort in-memory zeroization is required for sensitive byte arrays where possible.
4. Mnemonic display teardown must clear component state and remove rendered phrase content before component disposal.

## Storage invariants

1. `chrome.storage.sync` is not used for key/session material.
2. Ephemeral session state belongs in `chrome.storage.session` only.
3. Encrypted seed/key envelope belongs in `chrome.storage.local` only.

## Telemetry/privacy invariants

1. No telemetry SDKs, automatic diagnostics upload, or background beaconing.
2. Bug-report diagnostics are user-initiated with explicit consent and preview/redaction.

## Session policy defaults

1. Default session expiry: 24 hours of inactivity.
2. SMP cooldown constants (implementation constants):

- 1st failure: 5s
- 2nd failure: 30s
- 3rd failure: 120s + mandatory re-key

## CI enforcement checklist

- Threat model exists: `docs/security/threat-model.md`
- Security invariants exists: `docs/security/security-invariants.md`
- Privacy classification exists: `docs/privacy/data-classification.md`
- Privacy policy draft exists: `docs/privacy/privacy-policy-draft.md`
- Lint, format check, typecheck, tests, build pass
- Dependency audit runs and gates high/critical vulnerabilities

## Notes for future updates

- The specific Argon2id implementation choice and CSP/wasm viability are finalized in Phase 1.5 and documented here as an addendum.
- Where feasible, Argon2id execution is isolated in a short-lived Worker that is terminated immediately after derivation completes.
