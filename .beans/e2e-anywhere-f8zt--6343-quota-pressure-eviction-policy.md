---
# e2e-anywhere-f8zt
title: 6343 quota pressure eviction policy
status: todo
type: task
priority: normal
created_at: 2026-03-04T05:05:24Z
updated_at: 2026-03-04T05:06:42Z
parent: e2e-anywhere-lmd2
---

Implement >=80% chrome.storage.session pressure eviction tiers: fragment buffers first, then oldest skipped keys, preserving active handshake/session state.
