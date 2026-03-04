# Implementation Plan — Repository & Toolchain Bootstrap

## Phase 0 — Threat Model, Privacy Model, and Release Gates

0.1 Write `docs/security/threat-model.md` with assets, adversaries, trust boundaries, assumptions, and explicit in/out-of-scope items. Include: malicious platform DOM, malicious extension, local malware, network observer, side-channel observability by page JavaScript (OTR frame timing, DOM mutation patterns), contact graph inference by a local attacker with memory access (session map contents reveal conversation participants — document as in-scope concern, out-of-scope for prevention), and side-channel attack considerations.

0.2 Write `docs/privacy/data-classification.md` and `docs/privacy/privacy-policy-draft.md` covering: encrypted content boundaries, strict no-telemetry/no-metadata-collection policy, retention periods, key-transfer behavior via seed phrase, user controls, and explicit statement that `chrome.storage.sync` is not used.

0.3 Define non-negotiable crypto and parsing invariants (`docs/security/security-invariants.md`): no plaintext/key logging, no unsafe DOM sinks (`innerHTML`) for decrypted content, **the extension never persists decrypted plaintext to any storage layer** (decrypted content exists only transiently in memory and the DOM display layer), strict wire-format validation before state transitions, bounded memory/time for reassembly and skipped-key stores, Argon2id with no weaker fallback, and forging key discarded by default.

0.4 Define endpoint-compromise stance: local malware remains out-of-scope for prevention, but implement best-effort tamper-evidence signals and user notifications for integrity anomalies.

0.5 Define a privacy-preserving bug-report policy: user-initiated only, explicit opt-in for stack traces/diagnostics, local preview + redaction before submission, and no automatic error upload.

0.6 Add release blockers in CI: threat model present, privacy doc present, security invariant checklist present, tests passing.

0.7 Create GitHub Actions CI workflow (`.github/workflows/ci.yml`): lint (Oxlint), format check (Oxfmt), typecheck (tsc --noEmit), test (Vitest), build (Vite), security invariant presence check (verify `docs/security/threat-model.md`, `docs/security/security-invariants.md`, `docs/privacy/data-classification.md`, `docs/privacy/privacy-policy-draft.md` exist), and dependency audit (`pnpm audit`). This workflow is the enforcement mechanism for task 0.6 release blockers.

0.8 Define a localization strategy (`docs/localization.md`): extract all UI strings into i18next JSON files; support English (default) and at least one additional language (Spanish for v1); document the process for adding new languages.

0.9 Define performance budgets (`docs/performance-budgets.md`): extension startup time ≤ 500ms; handshake completion ≤ 1s; memory usage ≤ 50MB; `chrome.storage.session` usage ≤ 8MB (to allow headroom below the 10 MB quota limit).

---

## Phase 1 — Repository & Toolchain Bootstrap

1\. Initialize monorepo at /Users/daniel/Developer/e2e-anywhere with pnpm workspaces: `packages/core` (protocol engine, platform-agnostic), `packages/extension` (browser extension), `packages/test-fixtures`.

2\. Configure TypeScript (strict, no `any`), Oxlint, Oxfmt, Vitest, and the Chrome extension type stubs (`@types/chrome`).

3\. Create `packages/extension/manifest.json` as MV3 with **least privilege**: `content_scripts` + `host_permissions` scoped to Bluesky and Mastodon only for v1, service worker background, `storage` permission, and include `activeTab` only if proven necessary (default: omit).

4\. Set up a Vite-based build (`vite-plugin-web-extension`) that outputs separate bundles for the service worker, each content script, and the popup.

5\. Add a Phase 1.5 feasibility spike for browser constraints: verify Argon2id implementation viability under MV3 + CSP (candidate libraries: `argon2-wasm-pro`, `hash-wasm`, `@very-amused/argon2-refref` — note that `@noble/hashes` does NOT include Argon2; scrypt is not an acceptable substitute); benchmark DH3072 + Ed448 operations on supported Chrome targets; validate service-worker suspend/resume behavior for handshake state; and document the browser compatibility error message to display if no conforming Argon2id implementation is available (`chrome.storage.session` size budget: establish empirically — quota is 10 MB as of Chrome 112+, but must accommodate the full session map of multiple concurrent conversations, skipped message key stores, and fragment buffers; verify the effective limit under MV3 and document any discrepancies).

5.1 Standardize Argon2id baseline parameters for v1: `m=65536` (64 MiB), `t=3`, `p=1`. Benchmark these exact parameters during Phase 1.5 on lower-end Chromium targets and confirm acceptable unlock/setup latency. Any tuning must go through documented security review and cannot downgrade to a weaker KDF family.

1.6 Set up dependency management: pin exact versions of all dependencies in `package.json`; configure Dependabot or Renovate for automated dependency updates with manual review gates; add a `pnpm audit` step to CI to block on high/critical severity vulnerabilities.

1.7 Set up localization: add `i18next` (and a Web Component-compatible integration layer) to `package.json`; create a `locales/` directory in `packages/extension` with English strings (`en.json`).

1.8 Set up performance monitoring: add `web-vitals` to measure extension startup time and handshake latency; log performance metrics to `chrome.storage.local` for user-initiated export only (no automatic upload, consistent with no-telemetry policy).

---

## Phase 2 — Cryptographic Primitives (`packages/core/src/crypto/`)

Reference spec (direct): [OTRv4 Protocol Specification](https://github.com/otrv4/otrv4/blob/master/otrv4.md)

> **Decision — `@noble` over libsodium/WASM:** The `@noble` library family was chosen for smaller bundle size, TypeScript-native implementation, audited codebase, and no WASM startup costs. Note: `@noble/hashes` does not include Argon2 — Argon2id is handled separately (see task 12.1).

6\. Add `@noble/curves`, `@noble/hashes`, `@noble/ciphers` as the sole crypto dependencies. Pin exact versions and lock the hash.

7\. Implement ed448.ts: typed wrappers around `@noble/curves/ed448` for scalar generation (`generateECDH()`), point operations, point validation (curve membership check — note that `@noble/curves` handles cofactor internally; the wrapper must validate via test vectors rather than reimplementing cofactor clearing), and encoding/decoding per RFC 8032 §5.2.1 (point encoding/decoding) as referenced by the OTRv4 spec (57-byte encoding; do not describe as generically 'little-endian' — the format is RFC 8032-specified).

7.1 Ed448 validation hardening: explicitly reject identity and small-order points during decode/validation acceptance paths (aligned with OTRv4 contributory-behavior requirements), in addition to existing test-vector validation.

8\. Implement dh3072.ts: 3072-bit DH group operations using native `BigInt`, with the exact prime `dh_p` from RFC 3526 as specified in the OTRv4 spec. Include `generateDH()` and group membership validation.

9\. Implement kdf.ts: `KDF(usageID, ...values, size)`, `HWC(...)`, and `HCMAC(...)` all as `SHAKE-256("OTRv4" || usageID || values, size)` with all `usage_*` constants from the spec.

10\. Implement chacha20.ts: thin wrapper around `@noble/ciphers/chacha` with nonce always set to 0 per spec.

11\. Implement ring-sig.ts: `RSig(A1, a1, {A1, A2, A3}, m)` and `RVrf(...)` using constant-time style primitives (`constant_time_eq`, `constant_time_select`) where possible. Document explicitly that JavaScript provides no hardware-level timing guarantees: V8's optimizing compiler may introduce branches, GC pauses create timing noise, and `performance.now()` resolution varies by browser. The constant-time primitives here are best-effort and reduce but do not eliminate timing risk. Verify timing behavior with statistical tests and document residual risk in the threat model.

12\. Write unit tests for every primitive: test vectors from the OTRv4 spec where available, plus property tests (encode→decode round-trips, group membership).

12.1 Document the chosen Argon2id library: after the Phase 1.5 feasibility spike, record the selected library (`argon2-wasm-pro`, `hash-wasm`, or `@very-amused/argon2-refref`) and the rationale in `docs/security/security-invariants.md`. Add a CI step to verify WASM instantiation succeeds under the extension CSP (using a purpose-built smoke-test, not merely `wasm-pack`).

12.2 Implement explicit group membership validation for DH3072: expose a `validateDHGroupMembership(publicKey: bigint): boolean` function in `dh3072.ts` and test with edge cases (values of 1, `dh_p − 1`, `dh_p`, `0`, and randomly generated valid members).

13\. Add side-channel and robustness checks: parser and fragment-fuzzer corpus, timing-regression harness for sensitive compare/select paths, and performance budget assertions for handshake and ratchet operations.

---

## Phase 3 — OTR v4 Protocol Engine (`packages/core/src/otr/`)

Reference spec (direct): [OTRv4 Protocol Specification](https://github.com/otrv4/otrv4/blob/master/otrv4.md)

> **Decision — Interactive-only DAKE:** OTRv4 interactive-only mode is used, eliminating the prekey server requirement entirely and maximizing deniability for both parties.

14\. Define all wire-format types in types.ts: `ClientProfile`, `IdentityMessage`, `AuthRMessage`, `AuthIMessage`, `DataMessage`, `TLVRecord`, `RingSig`, with full serialize/deserialize using the OTRv4 binary layout (exact byte widths, endianness per spec).

15\. Implement client-profile.ts: create, sign (`sym_h` → EdDSA as RFC 8032 §5.2.3 — note: §5.2.6 is Ed448ph/prehashed, which is NOT what OTRv4 uses), and validate a `ClientProfile`. Expiration set to 1 week; renewal logic included. Forging key generation included; **default behavior is to discard the forging key secret immediately after ClientProfile signing** — retaining it is an explicit expert opt-in with a clear onboarding warning explaining that retaining the forging key eliminates deniability if it is later compromised.

16\. Implement interactive-dake.ts: the full DAKEZ 3-flow handshake (Identity → Auth-R → Auth-I), state variables (`WAITING_AUTH_R`, `WAITING_AUTH_I`, `ENCRYPTED_MESSAGES`), Mixed shared secret `K`, SSID computation, double ratchet initialization, phi construction (instance tags + first ephemeral keys as mandated by spec). Include explicit error recovery: if the service worker is terminated mid-DAKE (MV3 ephemeral lifecycle), restore state from `chrome.storage.session` and resume or restart the handshake on the next message event.

16.1 DAKE timeout recovery: if handshake state remains in `WAITING_AUTH_R` or `WAITING_AUTH_I` for more than 30 seconds (peer disconnect/network stall), clear pending DAKE state from `chrome.storage.session`, emit retry guidance in UI, and allow clean re-initiation.

17\. Implement double-ratchet.ts: sending/receiving ratchet, ECDH + brace key rotation (every 3rd DH ratchet), `derive_ratchet_keys`, `derive_enc_mac_keys`, skipped message key store (`skipped_MKenc`, bounded by `max_skip`), MAC key revelation, session expiration timer.

18\. Implement smp.ts: full 4-message SMP over Ed448 for identity verification (zero-knowledge proofs, state machine `SMPSTATE_EXPECT1`→`4`). Secret includes fingerprint + SSID as specified. **SMP attempt rate-limiting: maximum 3 attempts per session, with escalating cooldown (5s, 30s, 120s); mandatory session re-keying after SMP failure; UI must warn the user on each failed attempt and explain the cooldown.** This prevents automated brute-force of weak shared secrets by an adversary controlling the transport.

19\. Implement state-machine.ts: top-level OTR state machine handling all 13 protocol events. Heartbeat messages (empty plaintext, `IGNORE_UNREADABLE`) sent after configurable idle timeout.

19.1 Define session expiry defaults: default session expiry is **24 hours of inactivity**; make this configurable from the settings UI (task 41). Document the default in `docs/security/security-invariants.md`.

19.2 Define SMP cooldown durations explicitly: 1st failure → 5 s cooldown; 2nd failure → 30 s cooldown; 3rd failure → 120 s cooldown + mandatory session re-keying. These values are implementation constants, not configurable by the user.

19.3 Hardcode the Bluesky post length limit: use **300 characters** (AT Protocol spec) for outgoing fragment sizing in the Bluesky adapter. Document this value and its source in `docs/platforms/bluesky.md` so it can be re-validated against spec changes on each platform dependency update.

20\. Implement fragmentation.ts: transmit and receive fragment reassembly with per-identifier buffers and a reassembly timeout. Character limit for outgoing fragments is determined per-platform: Mastodon adapters must query `max_status_length` from `/api/v2/instance` (lazily on first DM navigation, cached — see task 30) and use that value (not a hardcoded 500-character default, since Mastodon instance limits vary from 500 to 65,535+); Bluesky adapters use the AT Protocol post length limit from the platform spec.

21\. Test the DAKE end-to-end with two in-process virtual parties. Test double ratchet with out-of-order messages, skipped messages, session expiry. Test SMP success and failure. Test service-worker crash recovery during DAKE (simulate termination between state transitions and verify resumption from serialized state).

22\. Add replay/DoS protections: maximum fragments per message, maximum buffered bytes per conversation, duplicate fragment detection, and LRU eviction on pressure. Skipped message key store: **max 200 entries per conversation** (not 1,000 — an adversary controlling message delivery order can exhaust memory by sending messages with high ratchet indices, consuming stored keys up to the limit); delete skipped keys after 30 days or 200 entries, whichever comes first.

---

## Phase 4 — Key Management (`packages/core/src/keys/`)

> **Decision — No `chrome.storage.sync`:** Even with encrypted content, sync metadata (key existence, modification timestamps) leaks to Google and can establish that a user employs E2EE. Key transfer is handled by seed phrase (paper key) instead. `chrome.storage.sync` is not used anywhere in this extension.

23\. Implement identity-key.ts: derive the Ed448 long-term key pair (`sym_h` → `sk_h`, `H`), forging key pair, and instance tag (random 4 bytes ≥ `0x00000100`) deterministically from a 256-bit random seed via HKDF-SHA512. The seed is the canonical secret — all key material is re-derived from it. Never expose `sk_h` outside this module. (256 bits chosen to match BIP39 24-word mnemonic encoding, which requires exactly 256 bits of entropy.)

24\. Implement key-store.ts: serialize the 256-bit seed to a byte array, encrypt with AES-256-GCM using a key derived via **Argon2id** from a user passphrase (candidate libraries: `argon2-wasm-pro`, `hash-wasm`, or `@very-amused/argon2-refref` — determined by Phase 1.5 spike). Store ciphertext in `chrome.storage.local`. If no conforming Argon2id WASM implementation is available under the active CSP configuration, the extension must refuse to generate or store keys and display a hard error: 'This browser configuration does not support the required cryptographic operations. WebAssembly may be blocked by a security extension or policy. The extension cannot function safely in this configuration.' Do not fall back to scrypt, PBKDF2, or any weaker KDF.

25\. Implement export-import.ts: download an encrypted key file (Argon2id ciphertext of the 256-bit seed). On import, decrypt and re-derive key material; verify the resulting public key fingerprint before storing.

26\. Implement device-pairing.ts: key transfer uses a **24-word mnemonic seed phrase** (Keybase-style paper key) encoding the 256-bit seed via the BIP39 wordlist (use `@scure/bip39` — audited, same author as `@noble/*` family). Displaying the mnemonic is available from Settings and during onboarding for multi-device users. **Critical: mnemonic data must be handled as `Uint8Array` (encoded bytes) throughout the codebase — never converted to a JavaScript `string` except at the final display layer, because JS strings are immutable and cannot be zeroed from memory. The display component (Web Component) must be destroyed (removed from DOM) immediately after user acknowledgment. If a dedicated Worker is used for seed derivation, `terminate()` it immediately after completion to shrink the heap surface.** Optionally display the mnemonic as a QR code for same-room transfer: QR encodes only the plaintext mnemonic words (no network, no server, no STUN/TURN); the receiving device's extension accepts the words as text input — camera access is not required, the QR is a convenience shortcut for users who can photograph the screen. **QR display safety: auto-dismiss the QR after a configurable timeout (default: 60 seconds); display a visible warning about screen capture risks (screen recording software, OS screenshot APIs, accessibility tools may capture the QR content); suppress the QR display entirely if screen-capture detection APIs indicate active recording (best-effort, not guaranteed).** On the receiving device, the user enters the mnemonic words, the extension re-derives all key material, and re-encrypts the seed under the new device's Argon2id passphrase before storing. The mnemonic is also the primary recovery mechanism if the passphrase is lost or the device is replaced. Security guidance: treat the seed phrase as equivalent to the private key itself — never share digitally, never store unencrypted.

26.1 Zero seed phrase memory after use: after the mnemonic `Uint8Array` has been displayed and acknowledged, call `seed.fill(0)` before releasing the reference. If a dedicated Worker was used for seed derivation, call `worker.terminate()` immediately after the derived material is transferred — do not await any further tasks. These steps are mandatory, not optional cleanup.

26.3 Seed phrase display teardown hardening: the mnemonic display Web Component must clear internal state before unmount, remove rendered mnemonic nodes, and then remove host element from DOM. Use closed Shadow DOM where feasible and avoid cloning mnemonic-bearing DOM trees.

26.2 Add forging key retention warning: implement a confirmation dialog that must be explicitly accepted before the forging key retention setting can be enabled. The dialog must explain in plain language that retaining the forging key means a future compromise of that key eliminates OTRv4 deniability for all messages signed during that session. The setting defaults to disabled (discard); the dialog cannot be bypassed programmatically.

27\. Enforce zero metadata collection: do not persist analytics, diagnostics, usage counters, contact graphs, or conversation identifiers beyond strict protocol/runtime necessity; define explicit deletion flows for local ciphertext artifacts.

---

## Phase 5 — Platform DOM Adapters (`packages/extension/src/platforms/`)

> **Decision — v1 platform scope:** v1 targets **Chrome** (and Chromium-based browsers: Edge, Brave) with **Bluesky + Mastodon** support only. Reddit and Google Chat are deferred to post-v1 (task 32). Platform adapter implementations are pinned to reviewed upstream documentation and code paths, and must be re-validated on each platform dependency update.

28\. Define adapter-interface.ts: `PlatformAdapter` interface with `getConversationId()`, `getCurrentUserId()`, `getMaxMessageLength(): Promise<number>`, `interceptOutgoingMessage(callback)`, `displayDecryptedMessage(el, plaintext)`, `injectOtrFrame(otrText)`, `hideOtrFrame(el)`.

29\. Implement bluesky.ts with codebase-validated assumptions: target `https://bsky.app/messages` and `https://bsky.app/messages/:conversation`; prefer stable anchors from upstream web code (`messagesScreen`, `convoScreen`) where exposed in DOM/test attributes with resilient fallbacks; align outgoing-send detection with current web input behavior (textarea + Enter submit, including IME edge handling); model conversation identity from the route conversation parameter (`convoId`) with fallback logic for route-schema drift; and use the AT Protocol post length limit from the platform spec for fragmentation.

30\. Implement mastodon.ts with canonical route handling: target `/conversations` and `/timelines/direct` (treat `/web/direct` as legacy redirected path); account for Mastodon 'direct/private mention' semantics (not E2EE by default) while layering OTR transport; derive conversation identity primarily from `/api/v1/conversations` semantics with status-route fallback (`/@acct/:statusId`); query `max_status_length` from `/api/v2/instance` **lazily on first DM navigation** (not at extension startup — querying at startup discloses extension presence to the Mastodon server operator and any network observer; cache the result to reduce request frequency) and pass to fragmentation layer (do not hardcode 500 — Mastodon instance limits vary widely). **Document this first-party metadata disclosure in `docs/privacy/data-classification.md`: a network observer or the Mastodon instance operator can infer that this extension is active from the `/api/v2/instance` query pattern.**

30.1 Metadata-minimizing Mastodon limit lookup: maintain local defaults for known/common instance limits, and only query `/api/v2/instance` when needed for unknown or conflicting hosts. Add optional randomized delay jitter before first query to reduce timing correlation; document residual risk.

31\. Implement adapter-registry.ts: maps `location.hostname` + URL pattern to adapter. Content script picks the right adapter at runtime.

32\. Define v2 backlog adapters (non-blocking for v1): Reddit, Google Chat.

33\. Add platform drift detection and compatibility probes: verify Bluesky route and send-surface anchors at startup; verify Mastodon direct timeline route availability, conversation anchors, and instance API availability; if probes fail, disable interception for that platform with a non-breaking compatibility warning (no plaintext capture).

29.1 Implement fallback logic for DOM changes: each compatibility probe (task 33) must fail gracefully — if a probe fails, the adapter for that platform is disabled entirely (no partial interception), and a non-blocking in-extension warning is shown to the user. No plaintext content is captured in the degraded state.

29.2 Document Mastodon `/api/v2/instance` metadata disclosure: add a specific entry to `docs/privacy/data-classification.md` stating that the `/api/v2/instance` query discloses extension presence to the Mastodon instance operator and any network observer who can correlate the query pattern. Display a non-blocking one-time informational notice in the extension UI when the query is first made (per conversation session, not per navigation).

---

## Phase 6 — Background Service Worker & Content Script (`packages/extension/src/`)

34\. Implement service-worker.ts: holds the OTR session map (`conversationId → SessionState`). Because MV3 service workers are ephemeral, serialize session state to `chrome.storage.session` (cleared on browser restart — intentional for security) after each state transition. Budget serialized session state carefully: `chrome.storage.session` has a 10 MB quota (Chrome 112+); with multiple concurrent conversations, skipped key stores, and fragment buffers, verify empirically how far this extends. **Include a version tag in all serialized state structures; on deserialization, validate the version tag and discard-and-re-handshake if it does not match the current extension version (prevents undefined behavior after extension updates).** Implement a size check before each write and evict oldest non-active sessions if headroom is below a defined threshold. Handle `chrome.runtime.onMessage` for all content-script↔background communication.

34.3 Quota pressure policy: at ≥80% `chrome.storage.session` usage, evict by priority tiers — Tier 3 fragment buffers first, then Tier 2 oldest skipped keys, while preserving Tier 1 active session/handshake state.

35\. Implement content-script.ts: bootstraps the platform adapter, registers outgoing intercept and incoming observer hooks, and relays OTR messages to/from the service worker via `chrome.runtime.sendMessage`. Strip `?OTR:…` frames from displayed messages, replace with decrypted plaintext and a padlock badge. **Note: the padlock badge shadow host element is a persistent DOM artifact detectable by platform JavaScript via `querySelectorAll('*')` or `MutationObserver` (unlike transient OTR frame injection, the badge persists for the session duration). Document this fingerprinting vector in the threat model as distinct from the transient DOM timing side-channel noted in task 49.**

35.1 DOM observer performance guardrails: scope observers to adapter-resolved message containers, debounce mutation burst handling, and schedule non-urgent badge/UI decoration work via `requestIdleCallback` (with timeout fallback) to avoid infinite-scroll bottlenecks.

36\. Define messages.ts: typed message bus protocol (`SEND_PLAINTEXT`, `RECEIVED_OTR_FRAME`, `SESSION_STATUS`, `INITIATE_OTR`, `END_SESSION`, `START_SMP`).

37\. Implement low-friction re-handshake UX: on conversation revisit/browser restart, silently attempt handshake re-init with visible but non-blocking status indicator and fallback prompt only on failure.

34.1 Test service worker termination during DAKE: as part of task 21, simulate service worker termination at each discrete DAKE state transition (`WAITING_AUTH_R`, `WAITING_AUTH_I`, and immediately before `ENCRYPTED_MESSAGES` is set). Verify that state is correctly serialized before termination and that the handshake resumes or restarts correctly on the next message event. This must be an automated test, not a manual smoke test.

34.2 Verify content script isolation: add an automated test that confirms the content script's isolated world cannot read variables set by page JavaScript (e.g., assign a sentinel value in page context, confirm it is undefined from the content script context). Document residual risks — DOM timing side-channels from OTR frame injection/removal remain observable by page JavaScript regardless of isolated world; reference the threat model entry from task 49.

38\. Add platform-specific re-handshake triggers: Bluesky on transition into `messages/:conversation` and conversation re-mount; Mastodon on entering `/conversations` and opening specific conversation status threads; plus debounce handling for SPA navigation/mutation bursts.

38.1 SPA route detection hook: use `chrome.webNavigation.onHistoryStateUpdated` in background/service-worker context to notify content scripts about SPA route transitions and trigger immediate adapter re-probe.

---

## Phase 7 — Extension UI (`packages/extension/src/ui/`)

39\. Build popup UI as a Web Component (`popup.ts` + `popup.html`) styled with Tailwind CSS: show active session status (unencrypted / encrypting / encrypted / verified), fingerprint of current contact, and action buttons (Start OTR, End OTR, Verify Identity via SMP, Settings). **End OTR session termination flow: on 'End OTR' click, confirm with user, send OTR disconnect TLV to peer, evict session state from `chrome.storage.session`, remove padlock badges from the conversation DOM, display 'Session ended' status, and notify the peer's UI that the session has been terminated. The conversation thread reverts to unencrypted mode with a visible indicator.**

**Accessibility requirements for all UI surfaces (tasks 39-44): all extension UI must meet WCAG 2.2 Level AA. This includes: keyboard navigation for all interactive elements (including popup, sidebar, settings, onboarding, and SMP dialogs); visible focus indicators on all focusable elements; ARIA roles, labels, and landmarks for Web Component shadow DOM content; color contrast minimum 4.5:1 for text, 3:1 for UI components; session status indicators must not rely on color alone (use text labels + icons); fingerprint display must be screen-reader accessible; SMP question/answer UI must have proper form labels and error association (`aria-describedby`); and all modal/dialog surfaces must trap focus correctly and support Escape to close.**

40\. Build sidebar-panel.ts as a Web Component injected into the page DOM via shadow root (isolated CSS + Tailwind utilities). Show real-time session events, SSID for voice verification, and SMP question/answer UI.

41\. Build settings UI as a Web Component (`settings.ts` + `settings.html`) styled with Tailwind: key backup/restore (export encrypted file, import encrypted file, show seed phrase, show seed phrase QR), passphrase change, session expiry timer, forging key preference (default: discard — the UI must clearly explain what deniability is and what is lost by retaining the forging key before the user can change this setting), **and a 'Wipe all keys and data' action with destructive confirmation dialog that clears `chrome.storage.local` (encrypted seed), `chrome.storage.session` (session state), removes all injected DOM elements, and displays confirmation. This is the explicit deletion flow required by task 27.**

42\. Build onboarding UI as a Web Component (`onboarding.ts` + `onboarding.html`) styled with Tailwind: first-run wizard for passphrase setup (with browser compatibility check — display hard error and halt if Argon2id is unavailable), identity key generation from seed, mandatory seed phrase display and acknowledgment step, optional encrypted file export, and fingerprint verification guidance.

43\. Add privacy/security disclosures in onboarding and settings: what is encrypted, strict no-telemetry/no-metadata policy, no sync backup (and why), tamper-warning behavior, and recovery/deletion procedures.

39.1 Implement SMP failure UX: add dedicated UI flows for each SMP cooldown period — display a clear error message identifying the failure, a countdown timer showing remaining cooldown, and (on the 3rd failure) a session re-keying prompt. The user must be notified explicitly on each SMP failure and the cooldown duration explained.

39.1.1 Differentiate failure messaging: provide distinct user guidance for question/answer mismatch versus cryptographic/protocol verification failure (possible tampering path), with stronger warning copy for the latter.

39.2 Add QR code safety features: auto-dismiss the QR code display after 60 seconds (countdown visible to user); show a persistent visible warning alongside the QR about screen capture risks (screen recording software, OS screenshot APIs, accessibility tools); suppress the QR display entirely if screen-capture detection APIs indicate active recording (best-effort — document in settings UI that detection is not guaranteed).

39.3 Implement bug report redaction: add automated pattern-based redaction for common sensitive patterns (URLs, bearer tokens, instance hostnames, UUIDs that could be conversation identifiers) before the report preview is shown. Allow users to manually redact additional content via an inline text editor in the preview step. The automated redaction is a safety net, not a substitute for user review.

39.4 Add update notifications: show a non-dismissable in-extension notification for critical security updates (those tagged as security patches in the release manifest). Non-critical updates may use a dismissable badge. Do not auto-install; link to the Chrome Web Store update mechanism or the direct CRX channel if configured.

44\. Add a 'Report bug' action (Settings + error surfaces) that opens a guided report modal: collect a user-written summary, offer optional checkboxes for stack trace/extension version/active platform/non-sensitive logs, show a full editable preview with redaction controls. **Default submission method is copy-to-clipboard** (avoids writing diagnostic data to browser history via URL); GitHub issue prefill URL to `selfagency/e2e-anywhere` is available as an explicit opt-in alternative with a warning that the report payload may appear in browser history (including synced profiles). Never send data automatically or include message plaintext, keys, or conversation identifiers.

---

## Phase 8 — Security Hardening

45\. Enforce strict Content Security Policy in `manifest.json`: `script-src 'self'`, no `eval`, no remote scripts. **Note: all three candidate Argon2id WASM libraries (`argon2-wasm-pro`, `hash-wasm`, `@very-amused/argon2-refref`) instantiate WASM dynamically, which requires `wasm-unsafe-eval` under MV3 CSP. This is the expected outcome of the Phase 1.5 spike.** The `wasm-unsafe-eval` directive allows any WASM module loaded by the extension to execute, so the extension's JavaScript entry points become the trust boundary — document this residual risk explicitly in the threat model. Evaluate whether any candidate library supports pre-compiled WASM loaded via `<script>` tag or static import to avoid the directive entirely; if not, accept `wasm-unsafe-eval` as the minimum viable CSP and ensure no other WASM modules are bundled.

45.7 WASM isolation strategy: where feasible, execute Argon2id in a short-lived dedicated Worker and terminate immediately after key-derivation transfer, minimizing exposure of long-lived extension contexts to wasm-enabled execution paths.

46\. Ensure all plaintext and key material is zeroed from memory after use (`Uint8Array.fill(0)` — JS GC is non-deterministic and V8 may retain copies in optimized representations; this is best-effort). Document explicitly in the threat model that short-lived key material may persist in the heap until the next GC cycle. Consider running sensitive operations in dedicated Workers that are `terminate()`d immediately afterward to shrink the heap surface.

47\. Store session state in `chrome.storage.session` (not `local` or `sync`) so it is cleared on browser restart, limiting the window where session keys are at risk.

48\. Never log decrypted plaintext or key material to the console; add an Oxlint rule prohibiting `console.log` in production builds.

49\. Content script operates in an isolated world (Chrome MV3 default) — no access to page JavaScript heap. Validate this explicitly; note that DOM mutation timing remains observable to page JavaScript (OTR frame injection and removal patterns are a timing side-channel detectable by the platform page). Document this residual risk in the threat model.

50\. Implement max-skip limits and stored-key TTL: **200 entries per conversation maximum** (see task 22 rationale); delete skipped message keys after 30 days or 200 entries, whichever comes first.

51\. Add extension-supply-chain controls: lockfile integrity checks, dependency audit in CI, and reproducible signed release artifact process. Note: Chrome Web Store trust chain means a compromised CWS account equals a compromised extension for auto-update users; document this in the threat model and consider whether a hardened release channel (e.g., direct CRX distribution with pinned key) is warranted post-v1.

52\. Add tamper-evidence and user-warning mechanisms: authenticated key-store envelope/version checks, integrity mismatch detection at startup/import, permission/manifest drift checks across versions, and clear in-product warnings with recovery guidance.

52.1 Add extension update/migration strategy: include a version tag in all persisted data structures (`chrome.storage.local` encrypted seed envelope, `chrome.storage.session` serialized state). On startup, detect version mismatch between stored data and current extension version. For `chrome.storage.session` (ephemeral state): discard stale state and re-handshake (safe, no data loss). For `chrome.storage.local` (encrypted seed): implement migration logic for format changes; if migration is not possible, prompt the user to re-import via seed phrase or encrypted file export from the previous version. Provide a rollback/re-onboarding path for incompatible upgrades.

53\. Enforce no telemetry/no metadata exfiltration technically: no analytics SDKs, no remote logging endpoints, no background beacons, and CI guardrails to block introduction of telemetry code paths.

45.1 Validate WASM module integrity: use Subresource Integrity (SRI) hashes for the Argon2id WASM binary bundled with the extension. Document the residual risk that `wasm-unsafe-eval` permits execution of any WASM module loaded by the extension, making the JavaScript entry points the trust boundary.

45.2 Mitigate DOM timing side-channels: explore randomizing OTR frame injection timing (e.g., using `requestIdleCallback` with a random delay jitter). Document the residual risk in the threat model — randomization reduces but does not eliminate the timing signal.

45.3 Mitigate padlock badge fingerprinting: use `aria-hidden="true"` to hide the padlock badge shadow host from accessibility trees when not actively displaying verified status. This reduces (but does not eliminate) fingerprinting by accessibility tooling; document the residual risk in the threat model alongside the existing task 35 entry.

45.4 Implement dependency supply chain controls: pin all dependencies with exact versions and lock-file hashes; set up automated dependency audits in CI (already required by task 1.6); explicitly document the supply chain risk in the threat model — a compromised upstream package that passes audit at publish time remains a threat.

45.5 Implement session state migration: all serialized state structures in `chrome.storage.session` and `chrome.storage.local` must include a version tag. On deserialization, validate the tag; if it does not match the current extension version, apply the appropriate migration or discard and re-handshake. Document the risk of state corruption due to version mismatch in the threat model.

45.6 Document Chrome Web Store risks: add a section to the threat model documenting the risk of a compromised Chrome Web Store account enabling a malicious auto-update for all users. Evaluate whether a hardened release channel (direct CRX distribution with a pinned signing key, out-of-band integrity check) is warranted for post-v1. This evaluation must be resolved before the first public release.

54\. Implement safe error-capture boundaries for bug reports: stack traces are captured only after explicit per-report consent, sanitized for secrets/tokens/URLs where possible, and discarded from memory after report completion/cancel.

---

## Verification

- Unit tests for all crypto primitives and OTR state machines (`vitest` in `packages/core`).
- Integration test: two simulated peers, complete DAKE + exchange 10 messages with out-of-order delivery, then SMP verification.
- Service-worker crash recovery test: simulate MV3 worker termination at each DAKE state transition and verify correct resumption.
- Fragmentation test: serialize a 4 KB OTR frame and round-trip it through the fragment reassembler at multiple character limits (500, 1000, 5000, 65535).
- Manual smoke test: load unpacked extension in Chrome, open Bluesky + Mastodon DMs between two test accounts, verify `?OTR:` frame exchange, decrypted plaintext display, fingerprint badge, and low-friction re-handshake after browser restart.
- Platform regression tests (doc/codebase aligned): validate Bluesky `messages` and `messages/:conversation` navigation, Enter/click send paths, and convo-id extraction from route params; validate Mastodon `/conversations` and `/timelines/direct`, instance character limit query, and fallback behavior from legacy `/web/*` redirects; simulate selector drift and verify safe-disable + user warning behavior.
- Seed phrase round-trip test: generate seed on Device A, enter mnemonic on Device B, verify matching public key fingerprint.
- Encrypted file export/import round-trip test: export from Device A, import to Device B, verify same public key fingerprint.
- Argon2id unavailability test: simulate WASM blocked by CSP; verify extension displays hard error and refuses to generate or store keys (does not fall back to weaker KDF).
- `chrome.storage.session` quota test: simulate a session map near the 10 MB limit; verify eviction logic triggers correctly and active sessions are preserved.
- Security verification: parser fuzz tests, timing-regression checks for ring signature paths, and red-team style tests for malformed OTR frames.
- Privacy verification: explicit test matrix for data-at-rest locations (no sync storage), deletion workflow correctness, and proofs that no telemetry/metadata export paths exist.
- Tamper verification: tests for corrupted key-store envelope, import integrity failures, and startup integrity mismatch notifications.
- Bug-report verification: ensure report flow is strictly user-initiated, consent gates control stack-trace inclusion, preview/redaction is enforced, default submission is copy-to-clipboard (not URL prefill), and generated issue payload excludes forbidden sensitive fields.
- Data deletion verification: 'Wipe all keys and data' action clears `chrome.storage.local` and `chrome.storage.session`, removes injected DOM elements, and the extension returns to onboarding state.
- Session termination verification: 'End OTR' sends disconnect TLV, evicts session state, removes padlock badges, and both peers see 'Session ended' status.
- Accessibility verification: keyboard-only navigation through all popup/sidebar/settings/onboarding flows, screen reader audit of session status/fingerprint display/SMP dialogs, focus trap correctness in modals, color contrast check on all UI surfaces.
- Extension update verification: simulate version mismatch for `chrome.storage.session` (verify discard + re-handshake) and `chrome.storage.local` (verify migration or re-import prompt).
- Documentation verification (release gate): `threat-model.md`, privacy policy draft, and security invariants checklist present and approved.
- Performance testing: measure extension startup time, handshake latency, and peak memory usage under load; verify compliance with the budgets defined in task 0.9 (≤ 500ms startup, ≤ 1s handshake, ≤ 50MB memory, ≤ 8MB `chrome.storage.session`).
- Accessibility audits: integrate `axe-core` into the Vitest pipeline for automated WCAG 2.2 AA checks on all extension UI surfaces; conduct manual audits with VoiceOver and NVDA.
- Cross-browser testing: test the extension in Microsoft Edge and Brave (both Chromium-based MV3 hosts); document any browser-specific quirks, permission differences, or CSP interpretation differences.
- Developer documentation: create `CONTRIBUTING.md` with setup instructions, coding conventions, and contribution guidelines; add sequence diagrams for the DAKE handshake and double ratchet; generate API documentation for `packages/core` using TypeDoc.
- Release process: define semantic versioning strategy; automate changelog generation (e.g., using `changesets`); document the Chrome Web Store submission process and any hardened release channel procedures.

---

## Phase 10 — Localization and Internationalization

10.1 Extract UI strings: extract all user-visible strings from `popup.ts`, `sidebar-panel.ts`, `settings.ts`, and `onboarding.ts` into i18next JSON files under `packages/extension/locales/`. No UI string may be hardcoded in component logic.

10.2 Implement language switching: add a language selector to the settings UI (task 41); load the appropriate locale file based on user preference stored in `chrome.storage.local`; default to `en` on first install.

10.3 Test localization: verify that all UI surfaces reflect dynamic language switching without reload; test layout integrity with longer strings (e.g., German); test bidirectional text rendering with at least one RTL language (Arabic) to identify layout breakage early.

---

## Phase 11 — Performance Optimization

11.1 Optimize extension startup: lazy-load non-critical modules (platform adapters, QR code renderer, settings UI) so they are not included in the service worker or content script initial bundle. Measure the critical path (content script bootstrap → adapter probe → ready state) against the 500ms budget from task 0.9.

11.2 Optimize handshake latency: profile DH3072 scalar multiplication and Ed448 operations on representative Chrome targets; explore parallelizing independent operations (e.g., generating the ephemeral DH keypair while the identity message serializes). Document achieved latency against the 1s budget.

11.3 Optimize memory usage: profile heap usage during peak load (≥ 3 concurrent OTR sessions, each with a non-empty skipped key store); implement cleanup for sessions idle beyond the expiry threshold (task 19.1); verify compliance with the 50MB budget from task 0.9.
