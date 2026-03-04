import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const root = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      $core: resolve(root, 'packages/core/src'),
      $extension: resolve(root, 'packages/extension/src'),
      $fixtures: resolve(root, 'packages/test-fixtures/src'),
    },
  },
  test: {
    passWithNoTests: true,
  },
});
