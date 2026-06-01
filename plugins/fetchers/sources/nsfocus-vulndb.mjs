import { getIntEnv } from '../lib/env.mjs';
import { fetchText } from '../lib/http.mjs';
import { checkpointReached, chinaIdentifiers, htmlText, htmlUrls, latestDate, limitedUrls, persistExternalAdvisory, splitProducts } from '../lib/china-advisory.mjs';

export const sourceCode = 'nsfocus-vulndb';
export const runMode = 'manual';

const BASE = 'https://www.nsfocus.net';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const maxPages = getIntEnv('NSFOCUS_MAX_PAGES', 100);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const force = process.env.FETCHER_FORCE === '1';
  const modifiedDates = [];
  let count = 0;
  let stop = false;

  for (let page = 1; page <= maxPages && count < max && !stop; page++) {
    const html = await fetchText(`${BASE}/index.php?act=sec_bug&page=${page}`);
    const rows = parseRows(html);
    if (!rows.length) break;
    for (const row of rows) {
      if (count >= max) break;
      if (checkpointReached(row.listDate, checkpoint, force)) {
        stop = true;
        break;
      }
      const detailHtml = await fetchText(row.sourceUrl);
      const detail = parseDetail(detailHtml);
      const item = {
        provider: 'nsfocus-vulndb',
        advisoryId: row.advisoryId,
        identifiers: chinaIdentifiers(row.title, detailHtml),
        title: detail.title ?? row.title,
        summary: row.title,
        description: detail.description,
        references: limitedUrls([row.sourceUrl, htmlUrls(detailHtml, BASE)]),
        affectedProducts: splitProducts(detail.affectedProducts),
        affectedVendors: [],
        detailAvailable: true,
        publishedAt: detail.publishedAt ?? row.listDate,
        modifiedAt: detail.modifiedAt ?? row.listDate,
        sourceUrl: row.sourceUrl,
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

export function parseRows(html) {
  const rows = [];
  for (const match of String(html).matchAll(/<li><span>([^<]+)<\/span>\s*<a href=['"]\/vulndb\/(\d+)['"]>([\s\S]*?)<\/a><\/li>/gi)) {
    rows.push({
      advisoryId: `NSFOCUS-${match[2]}`,
      listDate: match[1].trim(),
      title: htmlText(match[3]),
      sourceUrl: `${BASE}/vulndb/${match[2]}`
    });
  }
  return rows;
}

export function parseDetail(html) {
  const source = String(html);
  return {
    title: htmlText(source.match(/<div align=['"]center['"]><b>([\s\S]*?)<\/b><\/div>/i)?.[1] ?? ''),
    publishedAt: htmlText(source.match(/<b>发布日期：<\/b>([^<]+)/i)?.[1] ?? '') || null,
    modifiedAt: htmlText(source.match(/<b>更新日期：<\/b>([^<]+)/i)?.[1] ?? '') || null,
    affectedProducts: htmlText(source.match(/<b>受影响系统：<\/b><blockquote>([\s\S]*?)<\/blockquote>/i)?.[1] ?? ''),
    description: htmlText(source.match(/<b>描述：<\/b><hr>([\s\S]*?)<b>建议：<\/b>/i)?.[1] ?? '')
  };
}
