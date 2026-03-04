import { onCLS, onINP, onLCP, type Metric } from 'web-vitals';

const STORAGE_KEY = 'phase1.performanceMetrics';
const DEBUG_FLAG = 'debugMode';
/** Maximum number of metric records retained in extension storage. */
const MAX_ENTRIES = 50;

type MetricRecord = {
  name: string;
  value: number;
  rating: Metric['rating'];
  delta: number;
  navigationType: Metric['navigationType'];
  timestamp: number;
};

function toMetricRecord(metric: Metric): MetricRecord {
  return {
    name: metric.name,
    value: metric.value,
    rating: metric.rating,
    delta: metric.delta,
    navigationType: metric.navigationType,
    timestamp: Date.now(),
  };
}

/**
 * In-memory buffer for metrics waiting to be flushed.
 * Collected synchronously from web-vitals callbacks, then flushed via the
 * serialised write queue to avoid concurrent read-modify-write races.
 */
const pendingMetrics: MetricRecord[] = [];

/**
 * Serialised write queue: each flush awaits the previous one so concurrent
 * web-vitals callbacks (CLS / INP / LCP can fire close together) never
 * interleave their storage reads and writes.
 */
let flushQueue: Promise<void> = Promise.resolve();

async function doFlush(): Promise<void> {
  if (pendingMetrics.length === 0) return;
  const toWrite = pendingMetrics.splice(0);
  const result = await chrome.storage.local.get(STORAGE_KEY);
  const existing: MetricRecord[] = Array.isArray(result[STORAGE_KEY]) ? (result[STORAGE_KEY] as MetricRecord[]) : [];
  // Merge and cap to prevent unbounded storage growth.
  const merged = [...existing, ...toWrite].slice(-MAX_ENTRIES);
  await chrome.storage.local.set({ [STORAGE_KEY]: merged });
}

function scheduleFlush(): void {
  flushQueue = flushQueue.then(doFlush);
}

function appendMetric(metric: Metric): void {
  pendingMetrics.push(toMetricRecord(metric));
  scheduleFlush();
}

/**
 * Start collecting Core Web Vitals and persisting them to extension storage.
 *
 * Collection is gated behind an explicit `debugMode` opt-in stored in
 * `chrome.storage.local`. This prevents creating persistent usage metadata
 * without user consent, in keeping with the extension's zero-telemetry policy.
 *
 * To enable: `chrome.storage.local.set({ debugMode: true })`
 */
export async function beginPerformanceCollection(): Promise<void> {
  const result = await chrome.storage.local.get(DEBUG_FLAG);
  if (!result[DEBUG_FLAG]) {
    return;
  }
  onCLS(appendMetric);
  onINP(appendMetric);
  onLCP(appendMetric);
}

export async function exportMetricsForUser(): Promise<string> {
  const result = await chrome.storage.local.get(STORAGE_KEY);
  const metrics: MetricRecord[] = Array.isArray(result[STORAGE_KEY]) ? (result[STORAGE_KEY] as MetricRecord[]) : [];
  return JSON.stringify(metrics, null, 2);
}

export async function clearMetrics(): Promise<void> {
  await chrome.storage.local.remove(STORAGE_KEY);
}
