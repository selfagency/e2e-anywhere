import { ensureI18n, t } from '../../localization/i18n';
import { beginPerformanceCollection } from '../../performance/metrics';

async function bootstrapPopup(): Promise<void> {
  await ensureI18n();
  beginPerformanceCollection();

  const app = document.getElementById('app');
  if (!app) {
    return;
  }

  app.textContent = t('popup.title');
}

void bootstrapPopup();
