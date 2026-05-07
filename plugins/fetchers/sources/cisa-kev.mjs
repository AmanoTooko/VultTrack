import { fetchJson } from '../lib/http.mjs';
import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertThreatIntel } from '../lib/staging.mjs';

export const sourceCode = 'cisa-kev';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const data = await fetchJson('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
  let count = 0;
  for (const item of data.vulnerabilities ?? []) {
    if (count >= max) break;
    const cve = item.cveID;
    const rawIndexId = await writeRecord(client, ctx, {
      externalKey: cve,
      externalId: cve,
      sourceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      publishedAt: item.dateAdded,
      identifiers: [cve],
      recordHash: sha256(stableJson(item)),
      payload: item
    });
    await upsertThreatIntel(client, rawIndexId, 'cisa-kev', cve, item);
    count++;
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { count } };
}
