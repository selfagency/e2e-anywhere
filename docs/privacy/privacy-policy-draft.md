# Privacy Policy (Draft)

## Last updated

2026-03-03

## Overview

`e2e-anywhere` is designed for end-to-end protected messaging workflows with a strict privacy posture:

- No telemetry.
- No analytics.
- No automatic diagnostics upload.
- No metadata collection beyond strict protocol/runtime necessity.

## What is encrypted

- Seed/key material is encrypted at rest before local persistence.
- Session message payloads are protected by OTRv4 protocol flows.
- Decrypted plaintext is never persisted; it is transiently processed for display only.

## What we do not collect

- No usage analytics.
- No contact graph analytics.
- No conversation content upload.
- No automatic error reporting.

## Storage locations

- `chrome.storage.local`: encrypted seed/key envelope and non-sensitive local settings.
- `chrome.storage.session`: ephemeral session runtime state.
- `chrome.storage.sync`: not used.

## Retention

- Ephemeral session state is cleared when the browser session ends/restarts.
- Encrypted key material remains until user deletion or key rotation/import replacement.
- Decrypted plaintext is not retained.

## Key transfer and recovery

- Users can transfer/recover identity using a user-controlled seed phrase flow.
- Seed phrase exposure is treated as full-key exposure risk and should be handled offline and securely.

## User controls

Users can:

- Start/end encrypted sessions.
- Verify identity (e.g., SMP/fingerprint workflows).
- Export/import encrypted key backup files.
- Change passphrase.
- Wipe all keys and local extension data.
- Generate bug reports only through explicit user action.

## Bug-report privacy policy

- Reporting is user-initiated only.
- Stack traces/diagnostics are opt-in per report.
- Report payload is previewable and redactable locally before sharing.
- No automatic background submission.
- Verification-failure messaging distinguishes likely user mismatch (e.g., wrong SMP answer) from cryptographic/protocol failures that may indicate tampering.

## Security anomaly handling

When integrity anomalies are detected, the extension warns the user and fails closed for affected operations. Guidance for recovery is presented in-product.

## Limitations

- Full endpoint compromise (e.g., local malware with host-level access) is out-of-scope for prevention.
- Best-effort tamper-evidence and warning mechanisms are used to reduce silent failure risk.
- Some platform capability discovery (e.g., Mastodon instance limit lookup) can reveal extension-activity patterns to the platform operator or network observer; this lookup is lazy, minimized, and cached.

## Future updates

This draft will be revised before first public release and versioned with release notes.
