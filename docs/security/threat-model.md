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
- Zero-permission sibling extension exploiting exposed message interfaces.

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

## Browser extension attack surface

This section documents the extension-specific threat surface derived from the three-context architecture (background script, content script, popup) and known exploitation patterns documented by the GitHub Security Lab and OWASP.

### Context privilege hierarchy

All three extension contexts are trusted code, but they have distinct privilege levels and attack exposure:

| Context                     | Extension API access                | DOM access                                     | Attacker exposure                                                              |
| --------------------------- | ----------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------ |
| Background (service worker) | Full — all permitted Extension APIs | None                                           | Via messages from content scripts, `onMessageExternal`, or `onConnectExternal` |
| Content script              | None (must message background)      | Full — runs in page context but isolated world | Directly exposed to attacker-controlled page DOM and JS                        |
| Popup                       | Full — all permitted Extension APIs | Own DOM only                                   | Via user interaction; if page can overlay/iframe the popup (clickjacking)      |

**Critical:** XSS in the background script context grants Universal XSS (UXSS) — the ability to execute arbitrary JavaScript in any tab the extension has permission for. This is categorically more severe than XSS in a content script (which is scoped to one site).

### Message passing attack vectors

The most common privilege escalation path in extensions is unsanitized or unauthenticated message handling:

- **`runtime.onMessage`**: Receives messages from extension's own content scripts. Content scripts run in the page context and may be influenced by attacker-controlled DOM. Treat all message payloads as untrusted.
- **`runtime.onMessageExternal` / `runtime.onConnectExternal`**: Receives messages from other extensions or, if `external_connectable` is misconfigured, from arbitrary websites. A zero-permission malicious sibling extension can send arbitrary messages to this handler.
- **`postMessage` from page**: Content scripts may relay `window.postMessage` events from the page to the background; failure to validate origin allows attacker-controlled pages to drive privileged operations.

Attack chain: malicious page → content script relay (no origin check) → background handler (no sender check) → UXSS or data exfiltration via Extension API.

### `external_connectable` misconfiguration

If the manifest includes an `external_connectable` entry with a wildcard host or overly broad extension ID list, arbitrary websites or extensions can initiate privileged connections. This must be absent unless explicitly required, and if present, locked to specific known origins.

### `web_accessible_resources` attack vectors

Resources listed in `web_accessible_resources` are loadable by any web page. This introduces two attack vectors:

1. **Iframe attack**: A malicious page loads an extension HTML page in a hidden iframe. If that page acts on URL parameters (e.g., `?action=export-keys`), the attacker can drive privileged operations.
2. **Clickjacking**: A malicious page overlays the extension iframe transparently, tricking the user into confirming privileged actions (approving key exports, signing transactions, etc.).

Mitigation: `web_accessible_resources` entries must use `use_dynamic_url: true` (randomizes UUID per session), be scoped to the minimum required host match patterns, and extension pages that perform sensitive actions must not accept URL parameters to initiate those actions.

### `activeTab` permission

The `activeTab` permission allows injection of JavaScript into any tab the user is currently interacting with. Critically, this permission does **not** appear in the Chrome install permission prompt and is therefore invisible to users. If an attacker can inject code into any path that triggers `tabs.executeScript()` or `scripting.executeScript()` with attacker-controlled `code`, this yields UXSS across all sites.

### URL parameter injection in extension pages

Extension HTML pages that read `location.search` or `location.hash` and pass values to privileged operations are vulnerable if those pages are web-accessible. Treat URL parameters as untrusted and never use them to gate security-sensitive decisions.

### MV2 vs MV3 security regression risks

This extension targets Manifest V3. The following MV2 attack vectors must not be reintroduced:

- `unsafe-eval` in CSP — removed in MV3; must not be added back.
- `tabs.executeScript({code: string})` — removed in MV3; replaced by `scripting.executeScript()` which accepts local files only.
- `eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)` — functionally equivalent to `unsafe-eval`; forbidden in all contexts regardless of manifest version.
- Broad `permissions` (v2) vs explicit `host_permissions` (v3): v3 requires `host_permissions` to send cookies with requests; do not broaden permission scope to accommodate legacy patterns.

### Extension-to-extension attack

A malicious extension with zero permissions installed by the user can send arbitrary messages to `onMessageExternal` handlers. The threat is:

1. Compromised or malicious extension installed alongside e2e-anywhere.
2. Extension sends crafted message to e2e-anywhere's external message handler.
3. If handler lacks sender ID validation, it processes the message as trusted.

Mitigation: `onMessageExternal` handlers must validate `sender.id` against an explicit allowlist. If no legitimate cross-extension communication is required, `onMessageExternal` and `onConnectExternal` must not be registered at all.

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
