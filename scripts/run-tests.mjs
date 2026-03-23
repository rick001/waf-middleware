#!/usr/bin/env node
/**
 * Discover compiled *.test.js under dist/ and run them with node --test.
 * (Shell globs and ** are unreliable in npm scripts across OS/CI.)
 */
import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

async function collectTestFiles(dir) {
  const out = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      out.push(...(await collectTestFiles(p)));
    } else if (e.isFile() && e.name.endsWith('.test.js')) {
      out.push(p);
    }
  }
  return out;
}

const files = (await collectTestFiles('dist')).sort();
if (files.length === 0) {
  console.error('No *.test.js files found under dist/. Run npm run build:test first.');
  process.exit(1);
}

const result = spawnSync(process.execPath, ['--test', ...files], {
  stdio: 'inherit',
  env: process.env,
});

process.exit(result.status === null ? 1 : result.status);
