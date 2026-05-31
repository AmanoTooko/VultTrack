import { getIntEnv } from '../lib/env.mjs';
import { fetchText } from '../lib/http.mjs';
import { chinaIdentifiers, htmlText, htmlUrls, latestDate, limitedUrls, persistExternalAdvisory, severityLabel, splitProducts } from '../lib/china-advisory.mjs';

export const sourceCode = 'cnvd';
export const runMode = 'manual';

const BASE = 'https://www.cnvd.org.cn';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const maxPages = getIntEnv('CNVD_MAX_PAGES', 5);
  const cookie = process.env.CNVD_COOKIE ?? '';
  const requestedIds = String(process.env.CNVD_IDS ?? '')
    .split(',')
    .map((value) => value.trim().toUpperCase())
    .filter(Boolean);
  const ids = requestedIds.length ? requestedIds : await discoverIds(maxPages, cookie);
  const modifiedDates = [];
  let count = 0;

  for (const id of ids) {
    if (count >= max) break;
    const sourceUrl = `${BASE}/flaw/show/${encodeURIComponent(id)}`;
    const html = await cnvdText(sourceUrl, cookie);
    const detail = parseDetail(html, id);
    const item = {
      provider: 'cnvd',
      advisoryId: id,
      identifiers: chinaIdentifiers(id, html),
      title: detail.title ?? id,
      summary: detail.title ?? id,
      description: detail.description,
      severityLabel: detail.severityLabel,
      references: limitedUrls([sourceUrl, htmlUrls(html, BASE)]),
      affectedProducts: splitProducts(detail.affectedProducts),
      affectedVendors: splitProducts(detail.affectedVendors),
      detailAvailable: true,
      publishedAt: detail.publishedAt,
      modifiedAt: detail.modifiedAt,
      sourceUrl,
      payload: { detail, html }
    };
    await persistExternalAdvisory(client, ctx, item);
    modifiedDates.push(item.modifiedAt);
    count++;
  }

  return {
    fetchedCount: count,
    parsedCount: count,
    checkpoint: {
      modifiedAt: latestDate(modifiedDates) ?? ctx.source.checkpoint_json?.modifiedAt ?? null,
      lastFetched: new Date().toISOString()
    }
  };
}

async function discoverIds(maxPages, cookie) {
  const ids = new Set();
  for (let page = 1; page <= maxPages; page++) {
    const html = await cnvdText(`${BASE}/flaw/list?flag=true&offset=${(page - 1) * 20}&max=20`, cookie);
    for (const match of html.matchAll(/\/flaw\/show\/(CNVD-\d{4}-\d+)/gi)) ids.add(match[1].toUpperCase());
  }
  return [...ids];
}

async function cnvdText(url, cookie) {
  const html = await fetchText(url, { headers: cookie ? { cookie } : {} }).catch((error) => {
    if (/HTTP 521|fetch failed/i.test(error.message)) {
      throw new Error('CNVD anti-bot challenge detected. Apply for CNVD shared-data access or provide a permitted browser session via CNVD_COOKIE.');
    }
    throw error;
  });
  if (/__jsl_clearance|验证码保护|document\.cookie|x-via-jsl/i.test(html)) {
    throw new Error('CNVD anti-bot challenge detected. Apply for CNVD shared-data access or provide a permitted browser session via CNVD_COOKIE.');
  }
  return html;
}

export function parseDetail(html, fallbackId) {
  const text = htmlText(html);
  const title = htmlText(String(html).match(/<h1[^>]*>([\s\S]*?)<\/h1>/i)?.[1] ?? '')
    || text.match(/(?:漏洞名称|标题)[:：]\s*([^\n]+)/)?.[1]
    || fallbackId;
  return {
    title,
    publishedAt: text.match(/(?:公开日期|发布日期)[:：]\s*(\d{4}-\d{2}-\d{2})/)?.[1] ?? null,
    modifiedAt: text.match(/(?:更新日期|最后更新)[:：]\s*(\d{4}-\d{2}-\d{2})/)?.[1] ?? null,
    severityLabel: severityLabel(text.match(/(?:危害级别|危害等级|漏洞级别)[:：]\s*([^\n]+)/)?.[1] ?? null),
    affectedProducts: text.match(/(?:影响产品|受影响产品|受影响系统)[:：]\s*([\s\S]*?)(?:\n(?:漏洞描述|描述|参考链接|解决方案)[:：]|$)/)?.[1] ?? '',
    affectedVendors: text.match(/(?:厂商|受影响厂商)[:：]\s*([^\n]+)/)?.[1] ?? '',
    description: text.match(/(?:漏洞描述|描述)[:：]\s*([\s\S]*?)(?:\n(?:参考链接|解决方案|厂商补丁)[:：]|$)/)?.[1] ?? null
  };
}
