import { getIntEnv } from '../lib/env.mjs';
import { runOsvModifiedIdIncremental } from '../lib/osv-database.mjs';

export const sourceCode = 'osv';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const smokeIds = max < Number.MAX_SAFE_INTEGER
    ? (process.env.OSV_IDS ?? 'Maven/GHSA-jfh8-c2jp-5v3q').split(',').map((x) => x.trim()).filter(Boolean)
    : [];

  return runOsvModifiedIdIncremental(client, ctx, {
    smokeIds
  });
}
