/**
 * Start collecting Core Web Vitals and persisting them to extension storage.
 *
 * Collection is gated behind an explicit `debugMode` opt-in stored in
 * `chrome.storage.local`. This prevents creating persistent usage metadata
 * without user consent, in keeping with the extension's zero-telemetry policy.
 *
 * To enable: `chrome.storage.local.set({ debugMode: true })`
 */
export declare function beginPerformanceCollection(): Promise<void>;
export declare function exportMetricsForUser(): Promise<string>;
export declare function clearMetrics(): Promise<void>;
