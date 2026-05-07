import { fetchJson, authHeaders } from '../lib/http.mjs';
import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertNvdCve } from '../lib/staging.mjs';

export const sourceCode = 'nvd-cve';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const pageSize = Math.min(getIntEnv('NVD_PAGE_SIZE', 2000), 2000);
  const { nvdKey } = authHeaders();
  let startIndex = 0;
  let total = Number.MAX_SAFE_INTEGER;
  let count = 0;
  while (startIndex < total && count < max) {
    const url = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
    url.searchParams.set('resultsPerPage', String(Math.min(pageSize, max - count)));
    url.searchParams.set('startIndex', String(startIndex));
    const data = await fetchJson(url, { headers: nvdKey ? { apiKey: nvdKey } : {} });
    total = data.totalResults ?? 0;
    for (const item of data.vulnerabilities ?? []) {
      if (count >= max) break;
      const cve = item.cve;
      const payload = item;
      const rawIndexId = await writeRecord(client, ctx, {
        externalKey: cve.id,
        externalId: cve.id,
        sourceUrl: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
        publishedAt: cve.published,
        modifiedAt: cve.lastModified,
        identifiers: [cve.id],
        recordHash: sha256(stableJson(payload)),
        payload
      });
      await upsertNvdCve(client, rawIndexId, payload);
      count++;
    }
    startIndex += data.resultsPerPage ?? pageSize;
    if ((data.vulnerabilities ?? []).length === 0) break;
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { startIndex, total } };
}
