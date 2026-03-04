# Copilot Agent Instructions — E2E-Anywhere Extension Development

## Mission Statement

You are developing a security-critical browser extension that implements OTRv4 end-to-end encryption for social media messaging. This is **not** a typical web app — every line of code affects user privacy, cryptographic security, and safety against sophisticated adversaries. Treat security and privacy as **primary constraints**, not secondary concerns.

## Security-First Development Protocol

### Non-Negotiable Security Requirements

- **Never** log, store, or transmit decrypted plaintext or key material
- **Never** use `innerHTML` or similar unsafe DOM sinks for decrypted content
- **Always** validate all inputs before processing (crypto, DOM, network)
- **Always** implement least-privilege access — request minimal permissions
- **Always** use internal IDE commands and MCP tools before CLI alternatives
- **Never** bypass approval workflows for high-risk operations (database writes, deployments)

### Privacy Constraints

- **Zero telemetry policy**: No analytics, no remote logging, no background beacons
- **No `chrome.storage.sync` usage**: Key transfer via seed phrase only
- **Memory hygiene**: Zero sensitive data after use with `Uint8Array.fill(0)`
- **Metadata minimization**: No persistent conversation identifiers beyond protocol necessity

## Development Toolchain Hierarchy

1. **Internal IDE commands** (primary): Use built-in git, testing, and debugging tools
2. **MCP tools**: Leverage Exa, Context7, DeepWiki for documentation research
3. **Git/GitHub integration**: Use for commits, PRs, and issue management
4. **CLI commands**: Last resort only when no secure IDE alternative exists

### Available Tools

- **Version Control**: Git integration for commits, branches, PR creation
- **Documentation**: Exa (technical search), Context7 (code references), DeepWiki (detailed specs)
- **Testing**: Chrome DevTools, Playwright for automated testing
- **Debugging**: Integrated browser debugging, performance profiling

## Cryptographic Implementation Rules

- **Use only `@noble/*` libraries** (audited, TypeScript-native, no WASM startup costs)
- **Argon2id is mandatory** for key derivation — no fallback to weaker KDFs
- **Ed448 and DH3072** implementations must include explicit group membership validation
- **Constant-time operations** where possible (document JavaScript timing limitations)
- **Ring signatures** require statistical timing tests and documented residual risks

## Code Quality Requirements

- **TypeScript strict mode**: No `any` types, comprehensive type safety
- **Oxlint compliance**: Pass all linting rules without exceptions
- **Test coverage**: Unit tests for all crypto primitives, integration tests for protocols
- **Performance budgets**: Extension startup ≤500ms, handshake ≤1s, memory ≤50MB

## Security Review Triggers

Any changes to these areas require explicit security review:

- Cryptographic primitives or parameters
- Key storage or derivation methods
- DOM manipulation for decrypted content
- Network requests or API calls
- Permission requirements
- Data retention or deletion flows
- `manifest.json` (any change)
- Message handler registration (`onMessage`, `onMessageExternal`, `onConnectExternal`)
- `web_accessible_resources` entries
- `external_connectable` configuration
- Any use of `scripting.executeScript()` or `tabs.executeScript()`

## Browser Extension Security Rules

These rules are derived from OWASP Browser Extension Vulnerabilities and the GitHub Security Lab "Attacking Browser Extensions" research. Violations are release blockers.

### Permissions

- **Never request permissions speculatively.** Every permission in `manifest.json` must be required by an already-implemented feature. Request permissions dynamically at runtime when possible.
- **`<all_urls>` and `*://*/*` are forbidden** in `host_permissions` unless no narrower scope is possible. Justify in a comment.
- **`activeTab` requires documented justification.** It does not appear in the Chrome install prompt — document its use explicitly.

### Manifest configuration

- **Never add `external_connectable`.** If cross-extension messaging is ever required, add it with the strictest possible scope and document the decision in the threat model.
- **All `web_accessible_resources` entries must use `use_dynamic_url: true`.** This prevents UUID-based fingerprinting and resource enumeration by malicious pages.
- **Extension HTML pages that are web-accessible must not accept URL parameters to perform actions** (key export, signing, permitting anything).
- **CSP must not contain `unsafe-eval` or `unsafe-inline` for scripts.** `wasm-unsafe-eval` is the sole permitted exception.

### Message passing

- **All message payloads are untrusted**, regardless of source. Validate the full structure and content of every incoming message before acting on it — including messages from the extension's own content scripts.
- **Validate sender identity.** In `onMessage` handlers, check `sender.tab` and `sender.url` for privilege-sensitive operations. In `onMessageExternal` handlers, validate `sender.id` against an explicit allowlist.
- **`onMessageExternal` and `onConnectExternal` must not be registered unless required.** If registered, the handler must immediately reject unlisted senders.
- **Content scripts must check `event.origin` before relaying `window.postMessage` payloads** to the background script.

### Code execution

- **`eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)` are forbidden** in all extension contexts. Use the `no-eval` / `no-implied-eval` ESLint rules.
- **`scripting.executeScript()` must only use `files`, never `code` strings.** `tabs.executeScript()` (MV2 API) must not appear anywhere.
- **No remote script loading.** Every script executed by the extension must originate from the extension package.

### Content script rules

- **Treat all page DOM data as attacker-controlled.** Data extracted from `document` and sent to the background must be re-validated before use in any privileged operation.
- **No `innerHTML` for any page-derived content** — use `textContent` or DOM construction APIs. This is a separate invariant from the decrypted-content rule; it applies to all page data.

### UXSS awareness

XSS in the background script context is Universal XSS (UXSS): the attacker gains the ability to run code in any tab the extension has permission for. The path is:

> attacker-controlled page → content script (unsanitized relay) → background handler (unsanitized input) → UXSS

Every code review on the message-passing path must specifically ask: "if the content script sends attacker-controlled input here, can the background execute it as code?"

## Threat Model Awareness

Key threats you must consider:

- Malicious platform DOM (injection attacks)
- Local malware with memory access
- Network observers
- Side-channel attacks (timing, DOM mutation patterns)
- Supply chain attacks (compromised dependencies)
- Browser extension store compromise
- Universal XSS (UXSS) via background script compromise (categorically more severe than content-script XSS)
- Privilege escalation via unsanitized or unauthenticated message passing
- `external_connectable` misconfiguration exposing privileged handlers to arbitrary websites or extensions
- `web_accessible_resources` iframe loading and clickjacking attacks on extension UI
- Zero-permission malicious sibling extension driving `onMessageExternal` handlers
- URL parameter injection in web-accessible extension pages

## Platform-Specific Security Notes

- **Bluesky**: Use AT Protocol post length limits (300 chars), validate route parameters
- **Mastodon**: Query `/api/v2/instance` lazily (documents extension presence), handle variable character limits
- **Content Scripts**: Operate in isolated world but DOM timing remains observable

## Emergency Protocols

If you discover security vulnerabilities:

1. **Do not** document them in public comments or commit messages
2. Create private security issue with detailed reproduction steps
3. Follow responsible disclosure practices
4. Implement fixes with comprehensive testing
5. Update threat model documentation accordingly

## Documentation Requirements

- Update threat model for any new attack vectors discovered
- Document all privacy-impacting decisions in `docs/privacy/`
- Maintain security invariants in `docs/security/security-invariants.md`
- Include timing analysis documentation for crypto operations

Remember: This extension protects activists, journalists, and vulnerable populations. Security flaws can have real-world consequences including imprisonment or worse. Treat every commit as potentially life-saving code.
