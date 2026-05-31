import { spawnSync } from 'node:child_process';
import { getIntEnv } from '../lib/env.mjs';
import { fetchText } from '../lib/http.mjs';
import { chinaIdentifiers, decodeHtml, htmlText, htmlUrls, latestDate, limitedUrls, persistExternalAdvisory } from '../lib/china-advisory.mjs';

export const sourceCode = 'cert-360';
export const runMode = 'manual';

const FEED = 'https://cert.360.cn/feed';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const xml = await certText(FEED);
  const items = parseFeed(xml);
  const modifiedDates = [];
  let count = 0;
  for (const row of items) {
    if (count >= max) break;
    const detailHtml = process.env.CERT360_FETCH_DETAILS === '1'
      ? await certText(row.sourceUrl).catch(() => '')
      : '';
    const item = {
      provider: 'cert-360',
      advisoryId: row.advisoryId,
      identifiers: chinaIdentifiers(row.title, row.description, detailHtml),
      title: row.title,
      summary: row.description,
      description: detailHtml ? htmlText(detailHtml).slice(0, 12000) : row.description,
      references: limitedUrls([row.sourceUrl, htmlUrls(detailHtml, 'https://cert.360.cn')]),
      affectedProducts: [],
      affectedVendors: [],
      detailAvailable: Boolean(detailHtml),
      publishedAt: row.publishedAt,
      modifiedAt: row.publishedAt,
      sourceUrl: row.sourceUrl,
      payload: { feed: row, detailHtml }
    };
    await persistExternalAdvisory(client, ctx, item);
    modifiedDates.push(item.modifiedAt);
    count++;
  }
  return {
    fetchedCount: count,
    parsedCount: count,
    checkpoint: { modifiedAt: latestDate(modifiedDates), lastFetched: new Date().toISOString() }
  };
}

export function parseFeed(xml) {
  const rows = [];
  for (const match of String(xml).matchAll(/<item>([\s\S]*?)<\/item>/gi)) {
    const block = match[1];
    const sourceUrl = xmlValue(block, 'link');
    if (!sourceUrl) continue;
    const rawId = sourceUrl.match(/[?&]id=([a-z0-9]+)/i)?.[1] ?? sourceUrl;
    rows.push({
      advisoryId: `CERT360-${rawId}`,
      title: xmlValue(block, 'title') || `360CERT ${rawId}`,
      description: xmlValue(block, 'description'),
      publishedAt: xmlValue(block, 'pubDate'),
      sourceUrl
    });
  }
  return rows;
}

async function certText(url) {
  if (process.env.CERT360_ALLOW_INSECURE_TLS === '1') {
    const result = spawnSync('curl', ['-ksSL', '--max-time', '30', '-A', 'VulTrack/0.1', url], {
      encoding: 'utf8',
      maxBuffer: 20 * 1024 * 1024
    });
    if (result.status !== 0) throw new Error(`curl failed for ${url}: ${result.stderr}`);
    return result.stdout;
  }
  return await fetchText(url);
}

function xmlValue(block, tag) {
  return decodeHtml(String(block).match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i'))?.[1] ?? '')
    .replace(/^<!\[CDATA\[|\]\]>$/g, '')
    .trim();
}
