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
5. **Partial mitigation — ring-sig.ts scalar zeroization.** The 57-byte LE encoding of the nonce scalar `t_i` (the value whose disclosure would allow recovery of the signer's private scalar `a_i` via `r_i = t_i − c_i·a_i`) is explicitly `.fill(0)`-ed after its last use in `rsig()`. The private scalar `a_i` is returned by `@noble/curves` as a `bigint` and cannot be intercepted in byte form. All `bigint` primitives (including arithmetic intermediates) persist in the GC-managed heap until collected — this is an inherent JavaScript runtime limitation that cannot be addressed without replacing noble's scalar API. The byte-level zeroization of `t_i` reflects the maximum achievable hygiene within the current stack.

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

## Browser extension security invariants

These invariants protect against the extension-specific attack surface documented in `docs/security/threat-model.md § Browser extension attack surface`.

### Manifest invariants

1. **Minimum permissions.** Only permissions that are demonstrably required by implemented features may appear in `manifest.json`. Over-permissioned manifests are a release blocker. `host_permissions` must use the narrowest possible match pattern; `<all_urls>` and `*://*/*` are forbidden unless no narrower scope is sufficient.
2. **`external_connectable` is absent unless explicitly required.** If present, it must specify an explicit, narrow list of extension IDs or origin patterns. A wildcard host in `external_connectable` is a release blocker.
3. **`web_accessible_resources` is scoped to the minimum set.** Every entry must:
   - Use `use_dynamic_url: true` to prevent UUID-based resource enumeration.
   - Restrict `matches` to the specific platform host patterns that require the resource.
   - Never list HTML pages that accept URL parameters to perform sensitive actions.
4. **No `unsafe-eval` in CSP.** The `content_security_policy.extension_pages` value must not contain `unsafe-eval` or `unsafe-inline` for scripts. `wasm-unsafe-eval` is the only permitted exception (required for Argon2id WASM; see Argon2id library selection record).
5. **`activeTab` permission requires explicit justification.** If present, document in the manifest PR why `activeTab` is necessary and that it cannot be scoped to specific hosts. Note that this permission does not appear in the Chrome install prompt — do not assume users are aware of it.

### Message passing invariants

1. **All message payloads are untrusted.** Regardless of context (content script, popup, external), every `runtime.onMessage` and `runtime.onMessageExternal` handler must validate the structure and content of the message before acting on it.
2. **Sender origin must be validated.** Handlers that receive messages from content scripts must check `sender.tab` and `sender.url` where the operation is privilege-sensitive. `onMessageExternal` handlers must validate `sender.id` against an explicit allowlist of known extension IDs.
3. **`onMessageExternal` and `onConnectExternal` must not be registered unless cross-extension communication is an explicit requirement.** If registered, the handler must reject all senders not in the allowlist and return an error without performing any action.
4. **No `postMessage` relay without origin check.** Content scripts that listen to `window.postMessage` events from the page must check `event.origin` before relaying the payload to the background script.

### Code execution invariants

1. **`eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)` are forbidden in all contexts.** These are functionally equivalent to `unsafe-eval` and must not appear anywhere in extension source code, including dependencies loaded at compile time. Use a linter rule (`no-eval` / `no-implied-eval`) to enforce this.
2. **`tabs.executeScript()` (MV2 API) must not be used.** Use `scripting.executeScript()` with `files` (local file paths), never with `code` strings.
3. **No dynamic code loading from remote URLs.** All scripts executed by the extension must originate from the extension package. Remote script loading is forbidden regardless of CSP configuration.

### DOM / content script invariants

1. **Content scripts must treat all DOM content as untrusted.** Data extracted from the page DOM and passed to the background script via `sendMessage` must be treated as attacker-controlled. The background script must re-validate and sanitize it before use.
2. **Content scripts must not use `innerHTML` or equivalent sinks for any data derived from page content.** Use `textContent` or purpose-built DOM construction APIs. This applies both to injected UI chrome and to any in-page rendering of decrypted content.

### Extension audit checklist additions

The following items must be verified during every security-relevant PR review:

- [ ] No new permissions added without explicit justification comment in the PR.
- [ ] `external_connectable` not present or scoped tightly.
- [ ] `web_accessible_resources` entries use `use_dynamic_url: true`.
- [ ] No `eval`, `Function`, `setTimeout(string)`, `setInterval(string)` introduced.
- [ ] All new `onMessage` handlers validate sender and payload structure.
- [ ] No extension HTML page reads URL parameters to initiate sensitive operations.
- [ ] Static analysis (`eslint-plugin-no-unsanitized` or equivalent) passes.

- Threat model exists: `docs/security/threat-model.md`
- Security invariants exists: `docs/security/security-invariants.md`
- Privacy classification exists: `docs/privacy/data-classification.md`
- Privacy policy draft exists: `docs/privacy/privacy-policy-draft.md`
- Lint, format check, typecheck, tests, build pass
- Dependency audit runs and gates high/critical vulnerabilities

## Notes for future updates

- Where feasible, Argon2id execution is isolated in a short-lived Worker that is terminated immediately after derivation completes.

## Argon2id library selection record (Phase 2, bean 4sdp)

**Selected library:** `hash-wasm@4.12.0`

**Rationale:**

- MIT license — compatible with the project's licensing requirements
- Ships TypeScript type declarations — no separate `@types/` package required
- WASM-based Argon2id implementation — portable, no native add-on compilation
- Actively maintained with a recent release history
- No transitive production dependencies (only test/dev deps)

**CSP requirements:** The extension manifest must include `wasm-unsafe-eval` in `content_security_policy.extension_pages`.
This is the minimum additional CSP surface required for WASM execution.
No `unsafe-eval` or `unsafe-inline` for scripts is required or permitted.

**Baseline KDF parameters (v1):**

| Parameter | Value | Notes                    |
| --------- | ----- | ------------------------ |
| `m`       | 65536 | 64 MiB memory cost       |
| `t`       | 3     | 3 iterations             |
| `p`       | 1     | 1 lane (single-threaded) |
| `hashLen` | 32    | 256-bit derived key      |

**Benchmark requirement:** Any change to these parameters requires timing evidence from `scripts/bench-argon2id.mjs` on a reference device (M1 MacBook), showing that the new parameters remain within the 1s budget defined in `docs/performance-budgets.md`.

**CI smoke test:** A lightweight WASM init test (`hash-wasm` initializes without error) must pass in CI to detect environment-specific WASM load failures before deployment.
