import { ensureI18n, t } from '../../localization/i18n';
import { beginPerformanceCollection } from '../../performance/metrics';

async function bootstrapPopup(): Promise<void> {
  await ensureI18n();
  await beginPerformanceCollection();

  const app = document.getElementById('app');
  if (!app) {
    return;
  }

  app.textContent = t('popup.title');
}

bootstrapPopup().catch((err: unknown) => {
  // Render a safe fallback so the popup isn't left blank on init failure.
  const app = document.getElementById('app');
  if (app) {
    app.textContent = 'E2E Anywhere';
  }
  console.error('[e2e-anywhere] popup bootstrap failed', err);
});
