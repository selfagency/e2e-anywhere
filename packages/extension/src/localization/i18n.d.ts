import i18next from 'i18next';
import enStrings from '../../locales/en.json';
export type TranslationKey = keyof typeof enStrings;
export declare function ensureI18n(): Promise<typeof i18next>;
export declare function t(key: TranslationKey): string;
