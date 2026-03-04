import { existsSync } from 'node:fs';

const requiredFiles = [
  'docs/security/threat-model.md',
  'docs/security/security-invariants.md',
  'docs/privacy/data-classification.md',
  'docs/privacy/privacy-policy-draft.md',
];

const missing = requiredFiles.filter(filePath => !existsSync(filePath));

if (missing.length > 0) {
  console.error('Release blocker failed: required documentation is missing.');
  for (const filePath of missing) {
    console.error(`- ${filePath}`);
  }
  process.exit(1);
}

console.log('Release blocker check passed: all required docs are present.');
