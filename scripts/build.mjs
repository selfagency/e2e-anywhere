import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const viteSignals = [
  'index.html',
  'vite.config.ts',
  'vite.config.mts',
  'vite.config.js',
  'vite.config.mjs',
  'vite.config.cjs',
];

const hasViteProject = viteSignals.some(filePath => existsSync(filePath));

if (!hasViteProject) {
  console.log('build: no Vite project entry/config found yet; skipping.');
  process.exit(0);
}

const result = spawnSync('pnpm', ['exec', 'vite', 'build'], {
  stdio: 'inherit',
  shell: false,
});

if (typeof result.status === 'number') {
  process.exit(result.status);
}

process.exit(1);
