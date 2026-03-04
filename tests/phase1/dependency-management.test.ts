import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

type PackageJson = {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
};

const repoRoot = process.cwd();
const packageFiles = [
  join(repoRoot, 'package.json'),
  join(repoRoot, 'packages', 'core', 'package.json'),
  join(repoRoot, 'packages', 'extension', 'package.json'),
  join(repoRoot, 'packages', 'test-fixtures', 'package.json'),
];

function readPackageJson(filePath: string): PackageJson {
  return JSON.parse(readFileSync(filePath, 'utf8')) as PackageJson;
}

function getAllDependencyEntries(pkg: PackageJson): Array<[string, string]> {
  return [
    ...Object.entries(pkg.dependencies ?? {}),
    ...Object.entries(pkg.devDependencies ?? {}),
    ...Object.entries(pkg.optionalDependencies ?? {}),
    ...Object.entries(pkg.peerDependencies ?? {}),
  ];
}

describe('phase 1.6 dependency controls', () => {
  it('pins package versions to exact values in all workspace package manifests', () => {
    for (const filePath of packageFiles) {
      const pkg = readPackageJson(filePath);
      const deps = getAllDependencyEntries(pkg);

      for (const [, version] of deps) {
        expect(version).not.toMatch(/^[~^]/);
      }
    }
  });

  it('has Dependabot configuration committed', () => {
    const dependabotPath = join(repoRoot, '.github', 'dependabot.yml');
    expect(existsSync(dependabotPath)).toBe(true);
  });
});
