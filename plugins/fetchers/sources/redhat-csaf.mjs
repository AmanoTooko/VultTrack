import { fetchJson } from '../lib/http.mjs';
import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';

export const sourceCode = 'redhat-csaf';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const items = await fetchJson('https://access.redhat.com/hydra/rest/securitydata/csaf.json');
  const latestReleased = (items ?? []).map((x) => x.released_on).filter(Boolean).sort().at(-1) ?? null;

  if (checkpoint.latestReleased === latestReleased && !process.env.FETCHER_FORCE) {
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { latestReleased, skipped: true } };
  }

  let count = 0;
  for (const item of items ?? []) {
    if (count >= max) break;
    if (checkpoint.latestReleased && item.released_on && item.released_on <= checkpoint.latestReleased && !process.env.FETCHER_FORCE) {
      continue;
    }
    const advisoryId = item.RHSA ?? item.advisory ?? item.id;
    if (!advisoryId) continue;
    const identifiers = [advisoryId, ...(item.CVEs ?? [])].filter(Boolean);
    const sourceUrl = `https://access.redhat.com/errata/${advisoryId}`;
    await writeRecord(client, ctx, {
      externalKey: advisoryId,
      externalId: advisoryId,
      sourceUrl,
      publishedAt: item.released_on ?? null,
      modifiedAt: item.released_on ?? null,
      identifiers,
      recordHash: sha256(stableJson(item)),
      payload: item
    });
    count++;
  }

  return { fetchedCount: count, parsedCount: count, checkpoint: { latestReleased, lastFetched: new Date().toISOString() } };
}
