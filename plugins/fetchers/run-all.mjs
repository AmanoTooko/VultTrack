#!/usr/bin/env node
import { spawnSync } from 'node:child_process';

const sources = [
  'nvd-cve',
  'nvd-cpe',
  'ghsa',
  'osv',
  'cve-list-v5',
  'cisa-kev',
  'first-epss',
  'alpine-secdb',
  'debian-security-tracker',
  'ubuntu-osv'
];

let failed = 0;
for (const source of sources) {
  const result = spawnSync(process.execPath, ['plugins/fetchers/run-fetcher.mjs', '--source', source], {
    stdio: 'inherit',
    env: process.env
  });
  if (result.status !== 0) failed++;
}
process.exit(failed ? 1 : 0);
