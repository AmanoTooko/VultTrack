import zlib from 'node:zlib';
import { promisify } from 'node:util';
import { fetchBuffer } from '../lib/http.mjs';
import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertThreatIntel } from '../lib/staging.mjs';

const gunzip = promisify(zlib.gunzip);
export const sourceCode = 'first-epss';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const checkpoint = ctx.source.checkpoint_json ?? {};

  const gz = await fetchBuffer('https://epss.empiricalsecurity.com/epss_scores-current.csv.gz');
  const contentHash = sha256(gz);

  // Skip if content unchanged
  if (checkpoint.contentHash === contentHash) {
    console.error('EPSS data unchanged, skipping.');
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { contentHash, skipped: true } };
  }

  const csv = (await gunzip(gz)).toString('utf8');
  const lines = csv.split(/\r?\n/).filter((line) => line && !line.startsWith('#'));
  let count = 0;
  for (const line of lines.slice(1)) {
    if (count >= max) break;
    const [cve, epss, percentile] = line.split(',');
    if (!cve) continue;
    const item = { cve, epss: Number(epss), percentile: Number(percentile) };
    const rawIndexId = await writeRecord(client, ctx, {
      externalKey: cve,
      externalId: cve,
      sourceUrl: 'https://www.first.org/epss/data_stats',
      identifiers: [cve],
      recordHash: sha256(stableJson(item)),
      payload: item
    });
    await upsertThreatIntel(client, rawIndexId, 'first-epss', cve, item, {
      score: Number(epss),
      percentile: Number(percentile),
      observedAt: new Date().toISOString()
    });
    count++;
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { contentHash, lastFetched: new Date().toISOString() } };
}
