import { fetchJson, authHeaders } from '../lib/http.mjs';
import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertNvdCpe } from '../lib/staging.mjs';

export const sourceCode = 'nvd-cpe';

const NVD_MAX_DATE_WINDOW_DAYS = 120;

function nvdDate(iso) {
  return String(iso).replace(/(\.\d+)?Z?$/, '.000');
}

// NVD CPE Dictionary API 2.0 (paginated, date-based incremental)
export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const pageSize = Math.min(getIntEnv('NVD_PAGE_SIZE', 2000), 2000);
  const { nvdKey } = authHeaders();

  const checkpoint = ctx.source.checkpoint_json ?? {};
  let lastModStartDate = checkpoint.lastModStartDate ?? null;

  // NVD API rejects date ranges > 120 days; cap if checkpoint is too old
  const now = new Date();
  const maxWindowAgo = new Date(now.getTime() - NVD_MAX_DATE_WINDOW_DAYS * 86400000);
  if (lastModStartDate) {
    const cpDate = new Date(lastModStartDate);
    if (isNaN(cpDate.getTime()) || cpDate < maxWindowAgo) {
      console.error(`[nvd-cpe] checkpoint date too old, capping to ${nvdDate(maxWindowAgo.toISOString())}`);
      lastModStartDate = nvdDate(maxWindowAgo.toISOString());
    }
  }

  const isIncremental = !!lastModStartDate;
  console.error(`[nvd-cpe] ${isIncremental ? 'incremental' : 'full init'} starting...`);

  let startIndex = 0;
  let total = Number.MAX_SAFE_INTEGER;
  let count = 0;
  let latestMod = lastModStartDate;

  while (startIndex < total && count < max) {
    const url = new URL('https://services.nvd.nist.gov/rest/json/cpes/2.0');
    url.searchParams.set('resultsPerPage', String(Math.min(pageSize, max - count)));
    url.searchParams.set('startIndex', String(startIndex));
    if (lastModStartDate) {
      url.searchParams.set('lastModStartDate', lastModStartDate);
      url.searchParams.set('lastModEndDate', nvdDate(now.toISOString()));
    }
    const data = await fetchJson(url, { headers: nvdKey ? { apiKey: nvdKey } : {} });
    total = data.totalResults ?? 0;
    for (const item of data.products ?? []) {
      if (count >= max) break;
      const cpe = item.cpe;
      const uri = cpe?.cpeName ?? cpe?.cpeNameId;
      if (!uri) continue;
      const modDate = cpe?.lastModified ?? cpe?.lastModifiedDate;
      if (modDate && (!latestMod || modDate > latestMod)) latestMod = modDate;
      const rawIndexId = await writeRecord(client, ctx, {
        externalKey: uri,
        externalId: uri,
        sourceUrl: 'https://nvd.nist.gov/products/cpe',
        modifiedAt: modDate,
        identifiers: [uri],
        recordHash: sha256(stableJson(item)),
        payload: item
      });
      await upsertNvdCpe(client, rawIndexId, item);
      count++;
    }
    startIndex += data.resultsPerPage ?? pageSize;
    if ((data.products ?? []).length === 0) break;

    if (count % 50000 === 0 && total > 0) {
      console.error(`[nvd-cpe] ${count}/${total} (${Math.round(count/total*100)}%)`);
    }
    const delayMs = nvdKey ? 600 : 10000;
    if (startIndex < total && count < max) {
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
  console.error(`[nvd-cpe] done, fetched ${count} records`);
  return { fetchedCount: count, parsedCount: count, checkpoint: { lastModStartDate: latestMod ? nvdDate(latestMod) : null, lastFetched: now.toISOString() } };
}
