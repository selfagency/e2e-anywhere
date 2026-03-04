import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

type PackageJson = {
  dependencies?: Record<string, string>;
};

const repoRoot = process.cwd();
const extensionPackageJsonPath = join(repoRoot, 'packages', 'extension', 'package.json');

function readExtensionPackageJson(): PackageJson {
  return JSON.parse(readFileSync(extensionPackageJsonPath, 'utf8')) as PackageJson;
}

describe('phase 1.7 and 1.8 bootstrap artifacts', () => {
  it('adds exact i18next and web-vitals runtime dependencies to extension package', () => {
    const pkg = readExtensionPackageJson();
    expect(pkg.dependencies?.i18next).toBeTypeOf('string');
    expect(pkg.dependencies?.['web-vitals']).toBeTypeOf('string');

    expect(pkg.dependencies?.i18next ?? '').not.toMatch(/^[~^]/);
    expect(pkg.dependencies?.['web-vitals'] ?? '').not.toMatch(/^[~^]/);
  });

  it('commits extension locale baseline and bootstrap modules', () => {
    const localeFile = join(repoRoot, 'packages', 'extension', 'locales', 'en.json');
    const i18nModule = join(repoRoot, 'packages', 'extension', 'src', 'localization', 'i18n.ts');
    const metricsModule = join(repoRoot, 'packages', 'extension', 'src', 'performance', 'metrics.ts');

    expect(existsSync(localeFile)).toBe(true);
    expect(existsSync(i18nModule)).toBe(true);
    expect(existsSync(metricsModule)).toBe(true);

    const locale = JSON.parse(readFileSync(localeFile, 'utf8')) as Record<string, unknown>;
    expect(locale['popup.title']).toBeTypeOf('string');
  });
});
