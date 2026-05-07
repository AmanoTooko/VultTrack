import { fetchJson } from '../lib/http.mjs';
import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertDebian } from '../lib/staging.mjs';

export const sourceCode = 'debian-security-tracker';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const data = await fetchJson('https://security-tracker.debian.org/tracker/data/json');
  let count = 0;
  for (const [cveId, packages] of Object.entries(data)) {
    if (count >= max) break;
    const payload = { cveId, packages };
    const rawIndexId = await writeRecord(client, ctx, {
      externalKey: cveId,
      externalId: cveId,
      sourceUrl: `https://security-tracker.debian.org/tracker/${cveId}`,
      identifiers: [cveId],
      recordHash: sha256(stableJson(payload)),
      payload
    });
    await upsertDebian(client, rawIndexId, cveId, packages, payload);
    count++;
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { count } };
}
