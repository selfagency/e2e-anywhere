# Data Classification

## Policy summary

`e2e-anywhere` follows a strict no-telemetry/no-metadata-collection posture beyond protocol/runtime necessity.

- No analytics SDKs.
- No automatic diagnostics upload.
- No remote logging endpoints.
- No background beacons.

## Data classes

### Class A — Secret cryptographic material (Highly Sensitive)

Examples:

- Seed material.
- Private keys and derived secret keys.
- Passphrase-derived key-encryption keys.

Storage:

- Encrypted-at-rest envelope only in `chrome.storage.local`.

Rules:

- Never logged.
- Never sent to remote endpoints.
- Export/import only via explicit user action.

### Class B — Session runtime secrets (Highly Sensitive, Ephemeral)

Examples:

- Ratchet state, skipped message keys, fragment buffers.

Storage:

- `chrome.storage.session` only.

Rules:

- Browser-session lifetime only.
- Version-tag validation required on restore.
- Eviction/TTL constraints apply.

### Class C — Decrypted message plaintext (Highly Sensitive, Transient)

Examples:

- Human-readable decrypted content.

Storage:

- No storage allowed.

Rules:

- Render transiently in UI only.
- Never persisted to `local`, `session`, `sync`, IndexedDB, or logs.

### Class D — Operational UI/settings metadata (Low/Moderate sensitivity)

Examples:

- User settings (language preference, session expiry preference).
- Non-sensitive extension version/build info.

Storage:

- `chrome.storage.local` when required for function.

Rules:

- Minimal retention.
- Must not include conversation identifiers unless strictly required.

## Explicit exclusions

- `chrome.storage.sync` is not used.
  - Rationale: sync metadata can reveal E2EE usage patterns and key-presence timing.

## Retention policy

- Class A: retained until explicit user deletion, wipe flow, or key replacement.
- Class B: retained for browser session duration only; cleared on browser restart.
- Class C: not retained.
- Class D: retained until user changes settings or invokes wipe flow.

## User controls

- Export encrypted key file (user-initiated).
- Import encrypted key file (user-initiated).
- Seed phrase display (user-initiated, high-friction confirmation).
- Wipe all keys and data (destructive flow).
- Bug report generation is opt-in and local-preview-first.

## Known metadata disclosures

- Mastodon capability query (`/api/v2/instance`) may disclose extension activity pattern to:
  - Mastodon instance operator.
  - Correlating network observer.

Mitigation:

- Query is lazy (first relevant DM navigation) and cached; not performed at startup.
- User receives informational disclosure in-product when first queried.
- Prefer local/default per-instance limits when available; query `/api/v2/instance` only when host defaults are unknown or mismatched.
- Optional randomized first-query delay may be applied to reduce straightforward timing correlation.
