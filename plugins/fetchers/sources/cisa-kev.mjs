import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';

export const sourceCode = 'cisa-kev';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const checkpoint = ctx.source.checkpoint_json ?? {};

  const resp = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
    headers: { 'user-agent': 'VulTrack/0.1', 'accept': 'application/json' }
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} for CISA KEV`);
  const text = await resp.text();
  const contentHash = sha256(Buffer.from(text));

  // Skip if content unchanged
  if (checkpoint.contentHash === contentHash && process.env.FETCHER_FORCE !== '1') {
    console.error('CISA KEV unchanged, skipping.');
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { contentHash, skipped: true } };
  }

  const data = JSON.parse(text);
  let count = 0;
  for (const item of data.vulnerabilities ?? []) {
    if (count >= max) break;
    const cve = item.cveID;
    await writeRecord(client, ctx, {
      externalKey: cve,
      externalId: cve,
      sourceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      publishedAt: item.dateAdded,
      identifiers: [cve],
      recordHash: sha256(stableJson(item)),
      payload: item
    });
    count++;
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { contentHash, lastFetched: new Date().toISOString() } };
}
