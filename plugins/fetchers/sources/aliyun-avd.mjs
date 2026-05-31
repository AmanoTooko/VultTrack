import { getIntEnv } from '../lib/env.mjs';
import { fetchText } from '../lib/http.mjs';
import { checkpointReached, chinaIdentifiers, htmlText, htmlUrls, latestDate, limitedUrls, persistExternalAdvisory } from '../lib/china-advisory.mjs';

export const sourceCode = 'aliyun-avd';

const BASE = 'https://avd.aliyun.com';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const maxPages = getIntEnv('ALIYUN_AVD_MAX_PAGES', 50);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const force = process.env.FETCHER_FORCE === '1';
  const sections = ['/', '/high-risk/list', '/nvd/list', '/nonvd/list'];
  const seen = new Set();
  const modifiedDates = [];
  let count = 0;

  for (const section of sections) {
    for (let page = 1; page <= maxPages && count < max; page++) {
      const separator = section.includes('?') ? '&' : '?';
      const html = await fetchText(`${BASE}${section}${separator}page=${page}`);
      const rows = parseRows(html);
      if (!rows.length) break;
      for (const row of rows) {
        if (count >= max) break;
        if (seen.has(row.advisoryId)) continue;
        seen.add(row.advisoryId);
        if (checkpointReached(row.publishedAt, checkpoint, force)) continue;
        const detailHtml = process.env.ALIYUN_AVD_FETCH_DETAILS === '1'
          ? await fetchText(row.sourceUrl).catch(() => '')
          : '';
        const usableDetail = /本站开启了验证码保护|__jsl_clearance|interfaceacting/i.test(detailHtml) ? '' : detailHtml;
        const item = {
          provider: 'aliyun-avd',
          advisoryId: row.advisoryId,
          identifiers: chinaIdentifiers(row.advisoryId, row.title, row.identifiers, usableDetail),
          title: row.title,
          summary: row.title,
          description: usableDetail ? htmlText(usableDetail).slice(0, 8000) : null,
          references: limitedUrls([row.sourceUrl, htmlUrls(usableDetail, BASE)]),
          affectedProducts: [],
          affectedVendors: [],
          pocAvailable: row.pocAvailable,
          detailAvailable: Boolean(usableDetail),
          publishedAt: row.publishedAt,
          modifiedAt: row.publishedAt,
          sourceUrl: row.sourceUrl,
          payload: { list: row, detailHtml: usableDetail }
        };
        await persistExternalAdvisory(client, ctx, item);
        modifiedDates.push(item.modifiedAt);
        count++;
      }
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
  for (const match of String(html).matchAll(/<tr>([\s\S]*?href=["']\/detail\?id=(AVD-\d{4}-\d+)["'][\s\S]*?)<\/tr>/gi)) {
    const block = match[1];
    const advisoryId = match[2].toUpperCase();
    const cells = [...block.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/gi)].map((cell) => htmlText(cell[1]));
    rows.push({
      advisoryId,
      title: cells[1] || advisoryId,
      publishedAt: cells[3] || null,
      identifiers: chinaIdentifiers(block),
      pocAvailable: /title=["']POC 已公开["']/i.test(block),
      sourceUrl: `${BASE}/detail?id=${encodeURIComponent(advisoryId)}`
    });
  }
  return rows;
}
