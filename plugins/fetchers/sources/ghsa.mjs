import { fetchJson, authHeaders } from '../lib/http.mjs';
import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertGhsa } from '../lib/staging.mjs';

export const sourceCode = 'ghsa';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const { githubToken } = authHeaders();
  let page = 1;
  let count = 0;
  while (count < max) {
    const url = new URL('https://api.github.com/advisories');
    url.searchParams.set('per_page', String(Math.min(100, max - count)));
    url.searchParams.set('page', String(page));
    const headers = {
      'accept': 'application/vnd.github+json',
      ...(githubToken ? { authorization: `Bearer ${githubToken}` } : {})
    };
    const items = await fetchJson(url, { headers });
    if (!Array.isArray(items) || items.length === 0) break;
    for (const item of items) {
      if (count >= max) break;
      const ids = [item.ghsa_id, ...(item.identifiers ?? []).map((x) => x.value)].filter(Boolean);
      const rawIndexId = await writeRecord(client, ctx, {
        externalKey: item.ghsa_id,
        externalId: item.ghsa_id,
        sourceUrl: item.html_url,
        publishedAt: item.published_at,
        modifiedAt: item.updated_at,
        identifiers: ids,
        recordHash: sha256(stableJson(item)),
        payload: item
      });
      await upsertGhsa(client, rawIndexId, item);
      count++;
    }
    page++;
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { page } };
}
