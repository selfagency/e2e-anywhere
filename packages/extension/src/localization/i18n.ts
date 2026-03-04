import i18next from 'i18next';
import enStrings from '../../locales/en.json';

// `en.json` is the single canonical source for English strings.
// Do not duplicate string values in TypeScript — update `en.json` only.
export type TranslationKey = keyof typeof enStrings;

/**
 * Stored on first call so concurrent callers all await the same Promise
 * rather than racing to call `i18next.init()` multiple times.
 */
let initPromise: Promise<typeof i18next> | null = null;

export function ensureI18n(): Promise<typeof i18next> {
  if (!initPromise) {
    initPromise = i18next
      .init({
        lng: 'en',
        fallbackLng: 'en',
        // Keep the default escapeValue: true so interpolated values are HTML-
        // escaped. If a string must contain HTML, use safe DOM APIs (textContent)
        // at the call site rather than disabling escaping globally.
        resources: {
          en: { translation: enStrings },
        },
      })
      .then(() => i18next);
  }
  return initPromise;
}

export function t(key: TranslationKey): string {
  return i18next.t(key);
}
