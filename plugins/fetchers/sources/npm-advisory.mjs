import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { validGithubToken } from '../lib/exploit-utils.mjs';

export const sourceCode = 'npm-advisory';

const BROWSER_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36';

// GHSA cursor-based pagination helper
async function fetchGhsaPage(url, githubToken) {
  const headers = {
    'accept': 'application/vnd.github+json',
    'user-agent': BROWSER_UA,
    ...(githubToken ? { authorization: `Bearer ${githubToken}` } : {})
  };
  const res = await fetch(url, { headers });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status} for ${url}: ${text.slice(0, 500)}`);
  }
  const items = await res.json();
  let nextUrl = null;
  const link = res.headers.get('link');
  if (link) {
    const m = link.match(/<([^>]+)>;\s*rel="next"/);
    if (m) nextUrl = m[1];
  }
  return { items, nextUrl };
}

// Fetch npm advisories via GitHub Advisory API (ecosystem=npm, cursor-based)
export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const updatedSince = checkpoint.updatedSince ?? null;
  const githubToken = validGithubToken(process.env.GITHUB_TOKEN);

  let nextUrl = `https://api.github.com/advisories?per_page=100&type=reviewed&ecosystem=npm&sort=updated&direction=desc`;
  let count = 0;
  let latestUpdated = updatedSince;
  let seenOld = false;
  let pageNum = 0;

  while (count < max && !seenOld && nextUrl) {
    pageNum++;
    const { items, nextUrl: newNext } = await fetchGhsaPage(nextUrl, githubToken);
    nextUrl = newNext;
    console.error(`[npm-advisory] page ${pageNum} +${(items ?? []).length} records, total=${count}`);

    if (!Array.isArray(items) || items.length === 0) break;

    for (const item of items) {
      if (count >= max) break;
      if (updatedSince && item.updated_at && item.updated_at <= updatedSince) {
        seenOld = true;
        break;
      }
      const ids = [item.ghsa_id, ...(item.identifiers ?? []).map((x) => x.value)].filter(Boolean);
      if (item.updated_at && (!latestUpdated || item.updated_at > latestUpdated)) {
        latestUpdated = item.updated_at;
      }
      await writeRecord(client, ctx, {
        externalKey: item.ghsa_id,
        externalId: item.ghsa_id,
        sourceUrl: item.html_url,
        publishedAt: item.published_at,
        modifiedAt: item.updated_at,
        identifiers: ids,
        recordHash: sha256(stableJson(item)),
        payload: item
      });
      count++;
    }
  }
  console.error(`[npm-advisory] done, fetched ${count} records`);
  return {
    fetchedCount: count,
    parsedCount: count,
    checkpoint: { updatedSince: latestUpdated, lastFetched: new Date().toISOString() }
  };
}
