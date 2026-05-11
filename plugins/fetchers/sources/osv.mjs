import { getCsvEnv } from '../lib/env.mjs';
import { runOsvModifiedIdIncremental } from '../lib/osv-database.mjs';

export const sourceCode = 'osv';

export async function run(client, ctx) {
  return runOsvModifiedIdIncremental(client, ctx, {
    ids: getCsvEnv('OSV_IDS'),
    smokeIds: ['Maven/GHSA-jfh8-c2jp-5v3q']
  });
}
