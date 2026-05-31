import { getIntEnv } from '../lib/env.mjs';
import { fetchJson } from '../lib/http.mjs';
import { checkpointReached, chinaIdentifiers, htmlUrls, latestDate, persistExternalAdvisory, severityLabel, splitProducts } from '../lib/china-advisory.mjs';

export const sourceCode = 'cnnvd';

const BASE = 'https://www.cnnvd.org.cn';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const pageSize = Math.min(100, getIntEnv('CNNVD_PAGE_SIZE', 50));
  const maxPages = getIntEnv('CNNVD_MAX_PAGES', 100);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const force = process.env.FETCHER_FORCE === '1';
  const modifiedDates = [];
  let count = 0;
  let stop = false;

  for (let pageIndex = 1; pageIndex <= maxPages && count < max && !stop; pageIndex++) {
    const result = await fetchJson(`${BASE}/web/homePage/cnnvdVulList`, {
      method: 'POST',
      headers: { 'content-type': 'application/json;charset=utf-8' },
      body: JSON.stringify({ pageIndex, pageSize })
    });
    const records = result?.data?.records ?? [];
    if (!records.length) break;
    for (const row of records) {
      if (count >= max) break;
      const modifiedAt = row.updateTime ?? row.createTime ?? row.publishTime ?? null;
      if (checkpointReached(modifiedAt, checkpoint, force)) {
        stop = true;
        break;
      }
      const detailResult = await fetchJson(`${BASE}/web/cnnvdVul/getCnnnvdDetailOnDatasource`, {
        method: 'POST',
        headers: { 'content-type': 'application/json;charset=utf-8' },
        body: JSON.stringify({ id: row.id, vulType: row.vulType, cnnvdCode: row.cnnvdCode })
      });
      const detail = detailResult?.data?.cnnvdDetail ?? {};
      const references = [
        ...htmlUrls(detail.referUrl),
        ...htmlUrls(detail.patch)
      ];
      const item = {
        provider: 'cnnvd',
        advisoryId: row.cnnvdCode,
        identifiers: chinaIdentifiers(row.cnnvdCode, row.cveCode, detail.cveCode, detail.vulDesc, detail.referUrl),
        title: detail.vulName ?? row.vulName,
        summary: row.vulName,
        description: detail.vulDesc ?? null,
        severityLabel: severityLabel(detail.hazardLevel ?? row.hazardLevel),
        references,
        affectedProducts: splitProducts(detail.affectedProduct, detail.affectedSystem),
        affectedVendors: splitProducts(detail.affectedVendor),
        detailAvailable: true,
        publishedAt: detail.publishTime ?? row.publishTime ?? null,
        modifiedAt: detail.updateTime ?? modifiedAt,
        sourceUrl: `${BASE}/home/detail?cnnvdCode=${encodeURIComponent(row.cnnvdCode)}`,
        payload: { list: row, detail }
      };
      await persistExternalAdvisory(client, ctx, item);
      modifiedDates.push(item.modifiedAt);
      count++;
    }
  }

  return {
    fetchedCount: count,
    parsedCount: count,
    checkpoint: {
      modifiedAt: latestDate(modifiedDates) ?? checkpoint.modifiedAt ?? null,
      lastFetched: new Date().toISOString()
    }
  };
}
