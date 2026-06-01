import { getIntEnv } from '../lib/env.mjs';
import { fetchJson } from '../lib/http.mjs';
import { checkpointReached, chinaIdentifiers, latestDate, limitedUrls, persistExternalAdvisory, severityLabel, splitProducts } from '../lib/china-advisory.mjs';

export const sourceCode = 'chaitin-vuldb';
export const runMode = 'manual';

const BASE = 'https://stack.chaitin.com';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const pageSize = Math.min(100, getIntEnv('CHAITIN_PAGE_SIZE', 50));
  const maxPages = getIntEnv('CHAITIN_MAX_PAGES', 100);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const force = process.env.FETCHER_FORCE === '1';
  const modifiedDates = [];
  let count = 0;
  let stop = false;

  for (let page = 0; page < maxPages && count < max && !stop; page++) {
    const result = await fetchJson(`${BASE}/api/v2/vuln/list/?limit=${pageSize}&offset=${page * pageSize}`);
    const records = result?.data?.list ?? [];
    if (!records.length) break;
    for (const row of records) {
      if (count >= max) break;
      const modifiedAt = row.updated_at ?? row.created_at ?? row.disclosure_date ?? null;
      if (checkpointReached(modifiedAt, checkpoint, force)) {
        stop = true;
        break;
      }
      const detailResult = await fetchJson(`${BASE}/api/v2/vuln/detail/?id=${encodeURIComponent(row.id)}`).catch(() => null);
      const detail = detailResult?.data ?? row;
      const sourceUrl = `${BASE}/vuldb/detail/${row.id}`;
      const item = {
        provider: 'chaitin-vuldb',
        advisoryId: row.ct_id ?? `CT-${row.id}`,
        identifiers: chinaIdentifiers(row.ct_id, row.cve_id, row.cnvd_id, row.cnnvd_id, detail),
        title: detail.title ?? row.title,
        summary: detail.summary ?? row.summary,
        description: [detail.summary, detail.impact, detail.fix_steps].filter(Boolean).join('\n\n'),
        severityLabel: severityLabel(detail.severity ?? row.severity),
        references: limitedUrls([sourceUrl, referenceUrls(detail.references)]),
        affectedProducts: splitProducts(detail.vuln_sec_product_support_info?.map((x) => x.product_name ?? x.product ?? x.name)),
        affectedVendors: [],
        pocAvailable: Boolean(detail.poc_id || detail.poc_disclosure_date || detail.exp_disclosure_date),
        detailAvailable: Boolean(detailResult?.data),
        publishedAt: detail.disclosure_date ?? row.disclosure_date ?? null,
        modifiedAt: detail.updated_at ?? modifiedAt,
        sourceUrl,
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

function referenceUrls(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.flatMap(referenceUrls);
  if (typeof value === 'object') return Object.values(value).flatMap(referenceUrls);
  return String(value).match(/https?:\/\/[^\s<>"']+/gi) ?? [];
}
