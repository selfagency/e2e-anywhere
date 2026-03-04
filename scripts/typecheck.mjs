import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

const ROOT = process.cwd();
const IGNORE_DIRS = new Set(['.git', 'node_modules', 'dist', 'coverage']);
const TS_EXTENSIONS = ['.ts', '.tsx', '.mts', '.cts'];

function hasTypeScriptSource(dirPath) {
  const entries = readdirSync(dirPath, { withFileTypes: true });

  for (const entry of entries) {
    if (entry.name.startsWith('.') && entry.name !== '.github') {
      continue;
    }

    const fullPath = join(dirPath, entry.name);

    if (entry.isDirectory()) {
      if (IGNORE_DIRS.has(entry.name)) {
        continue;
      }
      if (hasTypeScriptSource(fullPath)) {
        return true;
      }
      continue;
    }

    if (TS_EXTENSIONS.some(ext => entry.name.endsWith(ext))) {
      return true;
    }
  }

  return false;
}

if (!hasTypeScriptSource(ROOT)) {
  console.log('typecheck: no TypeScript source files found yet; skipping.');
  process.exit(0);
}

const result = spawnSync('pnpm', ['exec', 'tsc', '--noEmit'], {
  stdio: 'inherit',
  shell: false,
});

if (typeof result.status === 'number') {
  process.exit(result.status);
}

process.exit(1);
