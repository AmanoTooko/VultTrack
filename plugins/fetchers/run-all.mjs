#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const requested = getArg('--sources') ?? process.env.FETCHER_SOURCES ?? '';
const sources = requested
  ? requested.split(',').map((x) => x.trim()).filter(Boolean)
  : await discoverSources();

let failed = 0;
for (const source of sources) {
  const result = spawnSync(process.execPath, ['plugins/fetchers/run-fetcher.mjs', '--source', source], {
    stdio: 'inherit',
    env: process.env
  });
  if (result.status !== 0) failed++;
}
process.exit(failed ? 1 : 0);

async function discoverSources() {
  const includeInit = ['FETCHER_INCLUDE_INIT', 'FETCHER_INIT', 'FETCHER_FORCE_INIT'].some((name) => {
    const value = process.env[name];
    return value === '1' || String(value).toLowerCase() === 'true';
  });
  const dir = path.join(__dirname, 'sources');
  const files = await fs.readdir(dir);
  const discovered = [];
  for (const file of files.filter((x) => x.endsWith('.mjs')).sort()) {
    const source = file.replace(/\.mjs$/, '');
    const mod = await import(`./sources/${file}`);
    if (!includeInit && mod.runMode === 'init') {
      console.error(`[run-all] skipping init-only source ${source}`);
      continue;
    }
    discovered.push(source);
  }
  return discovered;
}

function getArg(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}
