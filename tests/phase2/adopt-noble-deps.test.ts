import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

type PackageJson = {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
};

const repoRoot = process.cwd();

function readPackageJson(filePath: string): PackageJson {
  return JSON.parse(readFileSync(filePath, 'utf8')) as PackageJson;
}

describe('phase 2.6 @noble crypto dependency adoption', () => {
  const corePkg = readPackageJson(join(repoRoot, 'packages', 'core', 'package.json'));
  const allDeps = { ...corePkg.dependencies, ...corePkg.devDependencies };

  it('has @noble/curves as an exact-pinned dependency', () => {
    expect(allDeps['@noble/curves']).toBeDefined();
    expect(allDeps['@noble/curves']).not.toMatch(/^[~^]/);
  });

  it('has @noble/hashes as an exact-pinned dependency', () => {
    expect(allDeps['@noble/hashes']).toBeDefined();
    expect(allDeps['@noble/hashes']).not.toMatch(/^[~^]/);
  });

  it('has @noble/ciphers as an exact-pinned dependency', () => {
    expect(allDeps['@noble/ciphers']).toBeDefined();
    expect(allDeps['@noble/ciphers']).not.toMatch(/^[~^]/);
  });

  it('has hash-wasm as an exact-pinned dependency (Argon2id, selected in Phase 1.5)', () => {
    expect(allDeps['hash-wasm']).toBeDefined();
    expect(allDeps['hash-wasm']).not.toMatch(/^[~^]/);
  });
});
