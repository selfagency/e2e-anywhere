import { onCLS, onINP, onLCP, type Metric } from 'web-vitals';

const STORAGE_KEY = 'phase1.performanceMetrics';

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

async function readStoredMetrics(): Promise<MetricRecord[]> {
  const result = await chrome.storage.local.get(STORAGE_KEY);
  const metrics = result[STORAGE_KEY];
  return Array.isArray(metrics) ? (metrics as MetricRecord[]) : [];
}

async function writeStoredMetrics(metrics: MetricRecord[]): Promise<void> {
  await chrome.storage.local.set({
    [STORAGE_KEY]: metrics,
  });
}

async function appendMetric(metric: Metric): Promise<void> {
  const existing = await readStoredMetrics();
  existing.push(toMetricRecord(metric));
  await writeStoredMetrics(existing);
}

export function beginPerformanceCollection(): void {
  onCLS(appendMetric);
  onINP(appendMetric);
  onLCP(appendMetric);
}

export async function exportMetricsForUser(): Promise<string> {
  const metrics = await readStoredMetrics();
  return JSON.stringify(metrics, null, 2);
}
