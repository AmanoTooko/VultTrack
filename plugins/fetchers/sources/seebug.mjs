import { getIntEnv } from '../lib/env.mjs';
import { fetchText } from '../lib/http.mjs';
import { checkpointReached, chinaIdentifiers, decodeHtml, htmlText, htmlUrls, latestDate, limitedUrls, persistExternalAdvisory, severityLabel, splitProducts } from '../lib/china-advisory.mjs';

export const sourceCode = 'seebug';

const BASE = 'https://www.seebug.org';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const maxPages = getIntEnv('SEEBUG_MAX_PAGES', 100);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const force = process.env.FETCHER_FORCE === '1';
  const modifiedDates = [];
  let count = 0;
  let stop = false;

  for (let page = 1; page <= maxPages && count < max && !stop; page++) {
    const html = await fetchText(`${BASE}/vuldb/vulnerabilities?page=${page}`);
    const rows = parseRows(html);
    if (!rows.length) break;
    for (const row of rows) {
      if (count >= max) break;
      if (checkpointReached(row.publishedAt, checkpoint, force)) {
        stop = true;
        break;
      }
      const detailHtml = row.detailAvailable || process.env.SEEBUG_FETCH_DETAILS === '1'
        ? await fetchText(row.sourceUrl).catch(() => '')
        : '';
      const summary = metaContent(detailHtml, 'description') || row.title;
      const description = htmlText(detailHtml.match(/id=["']j-md-summary["'][^>]*>([\s\S]*?)<\/div>/i)?.[1] ?? '') || summary;
      const products = [...detailHtml.matchAll(/href=["']\/appdir\/[^"']+["'][^>]*>([\s\S]*?)<\/a>/gi)]
        .map((match) => htmlText(match[1]))
        .filter(Boolean);
      const item = {
        provider: 'seebug',
        advisoryId: row.advisoryId,
        identifiers: chinaIdentifiers(row.advisoryId, row.title, row.identifiers, detailHtml),
        title: row.title,
        summary,
        description,
        severityLabel: row.severityLabel,
        references: limitedUrls([row.sourceUrl, htmlUrls(detailHtml, BASE)]),
        affectedProducts: splitProducts(products),
        affectedVendors: [],
        pocAvailable: row.pocAvailable,
        detailAvailable: row.detailAvailable,
        publishedAt: row.publishedAt,
        modifiedAt: row.publishedAt,
        sourceUrl: row.sourceUrl,
        payload: { list: row, detailHtml }
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
  for (const match of String(html).matchAll(/<tr>([\s\S]*?\/vuldb\/ssvid-(\d+)[\s\S]*?)<\/tr>/gi)) {
    const block = match[1];
    const id = match[2];
    const advisoryId = `SSV-${id}`;
    const title = decodeHtml(block.match(/class=["']vul-title["'][^>]*title=["']([^"']+)["']/i)?.[1] ?? advisoryId);
    const publishedAt = block.match(/class=["'][^"']*datetime[^"']*["'][^>]*>\s*([^<]+)</i)?.[1]?.trim() ?? null;
    const severity = block.match(/class=["'][^"']*vul-level\s+([a-z]+)[^"']*["']/i)?.[1] ?? null;
    rows.push({
      advisoryId,
      title,
      publishedAt,
      severityLabel: severityLabel({ high: 'high', mid: 'medium', low: 'low' }[severity] ?? severity),
      identifiers: chinaIdentifiers(block),
      pocAvailable: /fa-rocket(?![^>]*text-muted)[^>]*data-original-title=["']有 PoC/i.test(block),
      detailAvailable: /fa-file-text-o(?![^>]*text-muted)[^>]*data-original-title=["']有详情/i.test(block),
      sourceUrl: `${BASE}/vuldb/ssvid-${id}`
    });
  }
  return rows;
}

function metaContent(html, name) {
  return decodeHtml(String(html).match(new RegExp(`<meta[^>]+name=["']${name}["'][^>]+content=["']([^"']*)["']`, 'i'))?.[1] ?? '');
}
