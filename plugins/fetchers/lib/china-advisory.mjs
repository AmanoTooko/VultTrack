import { sha256, stableJson } from './hash.mjs';
import { writeRecord } from './db.mjs';

const ID_PATTERNS = [
  /\bCVE-\d{4}-\d{4,10}\b/gi,
  /\bGHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b/gi,
  /\bCNNVD-\d{6}-\d+\b/gi,
  /\bCNVD-\d{4}-\d+\b/gi,
  /\bSSV-\d+\b/gi,
  /\bAVD-\d{4}-\d+\b/gi,
  /\bCT-\d+\b/gi,
  /\bNSFOCUS-\d+\b/gi,
  /\bCERT360-[0-9a-z]+\b/gi,
  /\bQIANXINTI-SV-\d{4}-\d+\b/gi
];

export function chinaIdentifiers(...values) {
  const text = values.filter(Boolean).flat().join(' ');
  const identifiers = new Set();
  for (const pattern of ID_PATTERNS) {
    for (const match of text.matchAll(pattern)) identifiers.add(match[0].toUpperCase());
  }
  return [...identifiers];
}

export function htmlText(value) {
  return decodeHtml(String(value ?? '')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(?:p|div|li|blockquote|h[1-6]|tr)>/gi, '\n')
    .replace(/<[^>]+>/g, ' '))
    .replace(/\r/g, '')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n[ \t]+/g, '\n')
    .replace(/[ \t]{2,}/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

export function decodeHtml(value) {
  return String(value ?? '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(Number.parseInt(dec, 10)));
}

export function htmlUrls(value, baseUrl = null) {
  const urls = new Set();
  for (const match of String(value ?? '').matchAll(/href=["']([^"'#]+)["']/gi)) {
    const url = absoluteUrl(match[1], baseUrl);
    if (url) urls.add(url);
  }
  for (const match of htmlText(value).matchAll(/https?:\/\/[^\s<>"']+/gi)) {
    urls.add(match[0].replace(/[),.;]+$/, ''));
  }
  return [...urls];
}

export function limitedUrls(values, max = 50) {
  return [...new Set(values.filter(Boolean).flat())].slice(0, max);
}

export function absoluteUrl(value, baseUrl) {
  if (!value) return null;
  try {
    return new URL(value, baseUrl ?? undefined).toString();
  } catch {
    return null;
  }
}

export function severityLabel(value) {
  if (value == null || value === '') return null;
  const normalized = String(value).trim().toLowerCase();
  if (['4', 'critical', '严重', '超危'].includes(normalized)) return 'critical';
  if (['3', 'high', '高危', '高'].includes(normalized)) return 'high';
  if (['2', 'medium', 'moderate', '中危', '中'].includes(normalized)) return 'medium';
  if (['1', 'low', '低危', '低'].includes(normalized)) return 'low';
  if (['0', 'unknown', '未知'].includes(normalized)) return 'unknown';
  return normalized;
}

export function splitProducts(...values) {
  return [...new Set(values
    .filter(Boolean)
    .flatMap((value) => String(value).split(/[\r\n,，;；|]+/))
    .map((value) => value.trim())
    .filter(Boolean))];
}

export async function persistExternalAdvisory(client, ctx, item) {
  const identifiers = [...new Set([item.advisoryId, ...(item.identifiers ?? [])].filter(Boolean).map((x) => String(x).toUpperCase()))];
  const normalized = { ...item, identifiers };
  const rawIndexId = await writeRecord(client, ctx, {
    externalKey: normalized.advisoryId,
    externalId: normalized.advisoryId,
    sourceUrl: normalized.sourceUrl ?? null,
    publishedAt: normalized.publishedAt ?? null,
    modifiedAt: normalized.modifiedAt ?? null,
    identifiers,
    recordHash: sha256(stableJson(normalized)),
    schemaHint: 'external-advisory',
    payload: normalized
  });
  return rawIndexId;
}

export function checkpointReached(itemModifiedAt, checkpoint, force = false) {
  if (force || !checkpoint?.modifiedAt || !itemModifiedAt) return false;
  const current = Date.parse(itemModifiedAt);
  const previous = Date.parse(checkpoint.modifiedAt);
  return Number.isFinite(current) && Number.isFinite(previous) && current <= previous;
}

export function latestDate(values) {
  return values
    .filter(Boolean)
    .map((value) => ({ value, time: Date.parse(value) }))
    .filter((x) => Number.isFinite(x.time))
    .sort((a, b) => b.time - a.time)[0]?.value ?? null;
}
