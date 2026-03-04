# Performance Budgets

These budgets are release gates for v1 and should be measured on representative Chromium targets.

## Budget targets

- Extension startup time: ≤ 500 ms
- Handshake completion time: ≤ 1 s
- Peak memory usage: ≤ 50 MB
- `chrome.storage.session` usage: ≤ 8 MB (headroom below 10 MB quota)

## Measurement definitions

- Startup time:
  - Critical path from content-script bootstrap to adapter-ready state.
  - Includes route-change re-probe behavior for SPA navigation paths.
- Handshake latency:
  - End-to-end DAKE timing from initiation to encrypted-ready state.
  - Includes timeout/retry behavior for stalled DAKE states.
- Peak memory:
  - Worst-case observed heap during expected concurrent sessions and skipped-key load.
- Session storage usage:
  - Serialized state footprint including session map, skipped keys, and fragment buffers.

## Test profile (minimum)

- At least 3 concurrent active conversations.
- Out-of-order and skipped-message simulation.
- Fragment reassembly under stress conditions.
- Service-worker suspend/resume/restart conditions.
- Infinite-scroll DOM mutation pressure with adapter-scoped observers and debounce enabled.
- Argon2id baseline parameter run (`m=65536`, `t=3`, `p=1`) on lower-end hardware to confirm acceptable unlock/setup UX.

## Enforcement strategy

- Add benchmark/regression checks in CI where deterministic.
- Keep manual reproducible performance scripts for browser-only metrics.
- Treat sustained budget regressions as release blockers.

## Reporting

Each performance report should include:

- Browser version and OS.
- Hardware baseline.
- Scenario/setup details.
- Raw measurements and percentile summaries.
- Pass/fail against each budget.
