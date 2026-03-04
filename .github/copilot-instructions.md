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

## Threat Model Awareness

Key threats you must consider:

- Malicious platform DOM (injection attacks)
- Local malware with memory access
- Network observers
- Side-channel attacks (timing, DOM mutation patterns)
- Supply chain attacks (compromised dependencies)
- Browser extension store compromise

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
