import { getIntEnv } from '../lib/env.mjs';
import { runOsvModifiedIdIncremental } from '../lib/osv-database.mjs';

export const sourceCode = 'google-osv';

const GOOGLE_ECOSYSTEMS = ['Android', 'OSS-Fuzz'];

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  if (max < Number.MAX_SAFE_INTEGER) {
    return runOsvModifiedIdIncremental(client, ctx, {
      ecosystem: 'Android',
      smokeIds: (process.env.GOOGLE_OSV_IDS ?? 'ASB-A-111893654,ASB-A-112551163').split(',').map((x) => x.trim()).filter(Boolean)
    });
  }

  const results = [];
  let fetchedCount = 0;
  let parsedCount = 0;
  const prior = ctx.source.checkpoint_json ?? {};
  for (const ecosystem of GOOGLE_ECOSYSTEMS) {
    const childCtx = {
      ...ctx,
      source: {
        ...ctx.source,
        checkpoint_json: prior[ecosystem] ?? {}
      }
    };
    const result = await runOsvModifiedIdIncremental(client, childCtx, {
      ecosystem,
      androidTable: ecosystem === 'Android'
    });
    results.push([ecosystem, result.checkpoint]);
    fetchedCount += result.fetchedCount;
    parsedCount += result.parsedCount;
  }

  return {
    fetchedCount,
    parsedCount,
    checkpoint: Object.fromEntries(results)
  };
}
