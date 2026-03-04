import i18next from 'i18next';

export const ENGLISH_STRINGS = {
  'popup.title': 'E2E Anywhere',
} as const;

let initialized = false;

export async function ensureI18n(): Promise<typeof i18next> {
  if (initialized) {
    return i18next;
  }

  await i18next.init({
    lng: 'en',
    fallbackLng: 'en',
    interpolation: {
      escapeValue: false,
    },
    resources: {
      en: {
        translation: ENGLISH_STRINGS,
      },
    },
  });

  initialized = true;
  return i18next;
}

export function t(key: keyof typeof ENGLISH_STRINGS): string {
  return i18next.t(key);
}
