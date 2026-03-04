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

### A) Argon2id under MV3 + CSP

Run a CSP-constrained smoke test in extension context for these candidates:

- `argon2-wasm-pro`
- `hash-wasm`
- `@very-amused/argon2-refref`

Record:

- Whether instantiation succeeds under MV3 CSP.
- Whether `wasm-unsafe-eval` is required in practice.
- Startup overhead and failure mode details.

### B) Argon2id baseline benchmark (Phase 1.5.1)

Benchmark exact baseline parameters:

- `m=65536` (64 MiB)
- `t=3`
- `p=1`

On lower-end Chromium targets, capture:

- Unlock/setup latency distribution (`p50`, `p95`, worst observed).
- Memory pressure observations.
- Recommended go/no-go threshold with rationale.

### C) DH3072 and Ed448 operation timing

Benchmark core operation timing in representative extension runtime conditions and document whether Phase 0 performance budgets remain viable.

### D) Service worker suspend/resume handshake behavior

Create a deterministic test harness that simulates worker termination during handshake state transitions and validates resume/restart behavior from `chrome.storage.session`.

## Required compatibility error behavior

If no conforming Argon2id implementation is available, UI must show this hard-stop message:

> This browser configuration does not support the required cryptographic operations. WebAssembly may be blocked by a security extension or policy. The extension cannot function safely in this configuration.

No fallback to weaker KDFs (e.g., PBKDF2, scrypt) is permitted.

## Notes

- This report intentionally does not include fabricated benchmark numbers.
- Quantitative benchmark data will be appended once runtime harnesses are in place and executed.
