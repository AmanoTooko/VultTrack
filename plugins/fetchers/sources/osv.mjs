import AdmZip from 'adm-zip';
import { fetchBuffer, fetchJson } from '../lib/http.mjs';
import { getEnv, getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertOsv } from '../lib/staging.mjs';

export const sourceCode = 'osv';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const smokeIds = getEnv('OSV_IDS', max < Number.MAX_SAFE_INTEGER ? 'GHSA-jfh8-c2jp-5v3q' : '');
  if (smokeIds) {
    let count = 0;
    for (const id of smokeIds.split(',').map((x) => x.trim()).filter(Boolean)) {
      if (count >= max) break;
      const item = await fetchJson(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`);
      const ids = [item.id, ...(item.aliases ?? [])].filter(Boolean);
      const rawIndexId = await writeRecord(client, ctx, {
        externalKey: item.id,
        externalId: item.id,
        sourceUrl: `https://osv.dev/vulnerability/${item.id}`,
        publishedAt: item.published,
        modifiedAt: item.modified,
        identifiers: ids,
        recordHash: sha256(stableJson(item)),
        payload: item
      });
      await upsertOsv(client, rawIndexId, item);
      count++;
    }
    return { fetchedCount: count, parsedCount: count, checkpoint: { ids: smokeIds } };
  }
  const buffer = await fetchBuffer('https://osv-vulnerabilities.storage.googleapis.com/all.zip');
  const zip = new AdmZip(buffer);
  let count = 0;
  for (const entry of zip.getEntries()) {
    if (count >= max) break;
    if (entry.isDirectory || !entry.entryName.endsWith('.json')) continue;
    const item = JSON.parse(entry.getData().toString('utf8'));
    const ids = [item.id, ...(item.aliases ?? [])].filter(Boolean);
    const rawIndexId = await writeRecord(client, ctx, {
      externalKey: item.id,
      externalId: item.id,
      sourceUrl: `https://osv.dev/vulnerability/${item.id}`,
      publishedAt: item.published,
      modifiedAt: item.modified,
      identifiers: ids,
      recordHash: sha256(stableJson(item)),
      payload: item
    });
    await upsertOsv(client, rawIndexId, item);
    count++;
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { count } };
}
