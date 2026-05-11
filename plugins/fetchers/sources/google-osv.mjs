import { getCsvEnv } from '../lib/env.mjs';
import { runOsvModifiedIdIncremental } from '../lib/osv-database.mjs';

export const sourceCode = 'google-osv';

const GOOGLE_ECOSYSTEMS = ['Android', 'OSS-Fuzz'];

export async function run(client, ctx) {
  const explicitIds = getCsvEnv('GOOGLE_OSV_IDS');
  if (explicitIds.length) {
    return runOsvModifiedIdIncremental(client, ctx, {
      ecosystem: 'Android',
      androidTable: true,
      ids: explicitIds
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
      androidTable: ecosystem === 'Android',
      smokeIds: ecosystem === 'Android' ? ['ASB-A-111893654', 'ASB-A-112551163'] : []
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
