# Phase 1.5 Browser Constraints Feasibility Spike

## Scope

This report tracks Phase 1.5 and 1.5.1 feasibility findings for browser constraints under Manifest V3:

- Argon2id viability under MV3 + CSP.
- Baseline parameter benchmarking target for Argon2id (`m=65536`, `t=3`, `p=1`).
- Service worker suspend/resume implications for handshake state.
- Compatibility error behavior when conforming Argon2id is unavailable.

## Completed checks (2026-03-04)

### 1) Toolchain and packaging baseline

- Extension build pipeline validated with Vite and `vite-plugin-web-extension`.
- Build artifacts include separate outputs for:
  - Service worker: `packages/extension/dist/src/background/service-worker.js`
  - Content script: `packages/extension/dist/src/content/content-script.js`
  - Popup: `packages/extension/dist/src/ui/popup/index.html` and `index.js`

### 2) Dependency and update automation baseline

- Dependabot config added at `.github/dependabot.yml`.
- Root workspace dependencies are pinned to exact versions (no `^` / `~`).
- `pnpm audit` remains present in quality gates (`package.json` scripts and CI workflow).

### 3) Localization/perf bootstrap prerequisites

- Added `i18next` with exact pin `25.8.14`.
- Added `web-vitals` with exact pin `5.1.0`.
- Version pins validated using npm registry queries during implementation.

## Pending feasibility tasks (required before Phase 1.5 closure)

### A) Argon2id under MV3 + CSP — RESOLVED

Candidate library evaluation (2026-03-04):

| Library                      | Version | TypeScript types                   | Maintained        | Verdict      |
| ---------------------------- | ------- | ---------------------------------- | ----------------- | ------------ |
| `hash-wasm`                  | 4.12.0  | ✅ bundled (`dist/lib/index.d.ts`) | ✅ MIT, active    | **SELECTED** |
| `argon2-wasm-pro`            | 1.1.0   | ❌ none                            | ⚠️ minimal signal | Eliminated   |
| `@very-amused/argon2-refref` | —       | ❌                                 | ❌ not on npm     | Eliminated   |

**Selected library: `hash-wasm@4.12.0`**

Rationale:

- MIT license; TypeScript types included.
- Actively maintained; exposes `argon2id()` directly.
- WASM binary is bundled with the npm package (not fetched from remote), so it is loadable under strict CSP.

**CSP requirement**: `wasm-unsafe-eval` must be added to `content_security_policy.extension_pages` in `manifest.json`. Chrome MV3 has permitted `wasm-unsafe-eval` since Chrome 95. This is the only viable path for Argon2id in a browser extension and is an acceptable trade-off given the bundled (not remote) WASM origin.

**Fallback behaviour** remains as specified: if `hash-wasm` cannot instantiate its WASM in the current browser context, the hard-stop message must be shown (see Required compatibility error behavior section below).

### B) Argon2id baseline benchmark (Phase 1.5.1) — deferred to Phase 4

Live runtime benchmarks require an instantiated extension running against a real Chromium build. These cannot be faked here. Benchmarks will be executed and appended during Phase 4 (key-store.ts implementation), at which point this section will be updated with:

- Unlock/setup latency distribution (p50, p95, worst observed) at `m=65536, t=3, p=1`.
- Memory pressure observations.
- Go/no-go threshold with rationale.

### C) DH3072 and Ed448 operation timing — deferred to Phase 2 completion

Timing benchmarks will be captured after Phase 2 crypto primitives are implemented (Phase 2 beans: `e2e-anywhere-vssq`, `e2e-anywhere-kw2g`). This section will be updated at Phase 2 close.

### D) Service worker suspend/resume handshake behavior — deferred to Phase 3

The suspend/resume test harness requires the handshake state machine (Phase 3). This section will be updated at Phase 3 close after the `chrome.storage.session` persistence integration is validated.

## Required compatibility error behavior

If no conforming Argon2id implementation is available, UI must show this hard-stop message:

> This browser configuration does not support the required cryptographic operations. WebAssembly may be blocked by a security extension or policy. The extension cannot function safely in this configuration.

No fallback to weaker KDFs (e.g., PBKDF2, scrypt) is permitted.

## Notes

- This report intentionally does not include fabricated benchmark numbers.
- Quantitative benchmark data will be appended once runtime harnesses are in place and executed.
