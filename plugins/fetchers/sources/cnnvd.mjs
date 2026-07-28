import { getIntEnv } from '../lib/env.mjs';
import { fetchJson } from '../lib/http.mjs';
import { saveCheckpoint } from '../lib/db.mjs';
import { checkpointReached, chinaIdentifiers, htmlUrls, latestDate, persistExternalAdvisory, severityLabel, splitProducts } from '../lib/china-advisory.mjs';

export const sourceCode = 'cnnvd';

const BASE = 'https://www.cnnvd.org.cn';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const pageSize = Math.min(100, getIntEnv('CNNVD_PAGE_SIZE', 50));
  const maxPages = getIntEnv('CNNVD_MAX_PAGES', 100);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const force = process.env.FETCHER_FORCE === '1';
  const baseline = !force && checkpoint.baselineComplete !== true;
  const existingRecords = baseline ? await rawRecordCount(client, ctx.source.id) : 0;
  const firstPage = baseline ? cnnvdBaselinePage(checkpoint, existingRecords, pageSize) : 1;
  const modifiedDates = [];
  let count = 0;
  let stop = false;
  let completed = false;
  let nextPage = firstPage;

  for (let pageIndex = firstPage; pageIndex < firstPage + maxPages && count < max && !stop; pageIndex++) {
    const result = await fetchListPage(pageIndex, pageSize);
    const records = result?.data?.records ?? [];
    if (!records.length) {
      completed = true;
      break;
    }
    for (const row of records) {
      if (count >= max) break;
      const modifiedAt = row.updateTime ?? row.createTime ?? row.publishTime ?? null;
      if (!baseline && checkpointReached(modifiedAt, checkpoint, force)) {
        stop = true;
        break;
      }
      const detail = await fetchDetail(row);
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
        detailAvailable: Object.keys(detail).length > 0,
        publishedAt: detail.publishTime ?? row.publishTime ?? null,
        modifiedAt: detail.updateTime ?? modifiedAt,
        sourceUrl: `${BASE}/home/detail?cnnvdCode=${encodeURIComponent(row.cnnvdCode)}`,
        payload: { list: row, detail }
      };
      await persistExternalAdvisory(client, ctx, item);
      modifiedDates.push(item.modifiedAt);
      count++;
    }
    nextPage = pageIndex + 1;
    if (baseline) {
      await persistProgress(client, ctx, checkpoint, modifiedDates, nextPage, false);
    }
    if (records.length < pageSize) {
      completed = true;
      break;
    }
  }

  const modifiedAt = latestDate([...modifiedDates, checkpoint.modifiedAt]) ?? null;
  const baselineComplete = baseline ? completed : checkpoint.baselineComplete === true;
  return {
    fetchedCount: count,
    parsedCount: count,
    checkpoint: {
      modifiedAt,
      baselineComplete,
      ...(baselineComplete ? {} : { nextPage }),
      lastFetched: new Date().toISOString()
    }
  };
}

export function cnnvdBaselinePage(checkpoint, existingRecords, pageSize) {
  const savedPage = Number(checkpoint?.nextPage);
  if (Number.isSafeInteger(savedPage) && savedPage > 0) return savedPage;
  if (!checkpoint?.modifiedAt) return 1;
  return Math.max(1, Math.floor(Math.max(0, existingRecords) / Math.max(1, pageSize)) + 1);
}

async function fetchListPage(pageIndex, pageSize, retries = 3) {
  let error;
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await fetchJson(`${BASE}/web/homePage/cnnvdVulList`, {
        method: 'POST',
        headers: { 'content-type': 'application/json;charset=utf-8' },
        body: JSON.stringify({ pageIndex, pageSize })
      });
    } catch (err) {
      error = err;
      if (attempt < retries) await new Promise((resolve) => setTimeout(resolve, attempt * 1000));
    }
  }
  throw error;
}

async function rawRecordCount(client, sourceId) {
  if (client.__spool) return 0;
  const result = await client.query('select count(*)::bigint as count from source_raw_index where source_id = $1', [sourceId]);
  return Number(result.rows[0]?.count ?? 0);
}

async function persistProgress(client, ctx, previous, modifiedDates, nextPage, baselineComplete) {
  const checkpoint = {
    ...previous,
    modifiedAt: latestDate([...modifiedDates, previous.modifiedAt]) ?? null,
    baselineComplete,
    ...(baselineComplete ? {} : { nextPage }),
    lastFetched: new Date().toISOString()
  };
  await saveCheckpoint(client, ctx.source.id, checkpoint);
  ctx.source.checkpoint_json = checkpoint;
}

async function fetchDetail(row, retries = 3) {
  let error;
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const result = await fetchJson(`${BASE}/web/cnnvdVul/getCnnnvdDetailOnDatasource`, {
        method: 'POST',
        headers: { 'content-type': 'application/json;charset=utf-8' },
        body: JSON.stringify({ id: row.id, vulType: row.vulType, cnnvdCode: row.cnnvdCode })
      });
      return result?.data?.cnnvdDetail ?? {};
    } catch (err) {
      error = err;
      if (attempt < retries) await new Promise((resolve) => setTimeout(resolve, attempt * 500));
    }
  }
  console.error(`CNNVD detail unavailable for ${row.cnnvdCode}: ${error?.message ?? 'unknown error'}`);
  return {};
}
