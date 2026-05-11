import { fetchJson, fetchText } from '../lib/http.mjs';
import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertEcosystemAdvisory } from '../lib/staging.mjs';
import { extractIdentifiers } from '../lib/advisory.mjs';

export const sourceCode = 'suse-csaf';

const BASE_URL = 'https://ftp.suse.com/pub/projects/security/csaf';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const fetchConcurrency = Math.max(1, getIntEnv('CSAF_FETCH_CONCURRENCY', 8));
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const indexText = await fetchText(`${BASE_URL}/index.txt`);
  const indexHash = sha256(Buffer.from(indexText));
  if (checkpoint.indexHash === indexHash && !process.env.FETCHER_FORCE) {
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { indexHash, skipped: true } };
  }

  const entries = indexText.split(/\r?\n/).map((x) => x.trim()).filter((x) => x.endsWith('.json'));
  let count = 0;
  for (let offset = 0; offset < entries.length && count < max; offset += fetchConcurrency) {
    const batch = entries.slice(offset, offset + fetchConcurrency);
    const items = await Promise.all(batch.map(async (entry) => ({
      entry,
      item: await fetchJson(`${BASE_URL}/${entry}`).catch(() => null)
    })));
    for (const { entry, item } of items) {
      if (count >= max) break;
      if (!item) continue;
      const url = `${BASE_URL}/${entry}`;
      const doc = item.document ?? {};
      const tracking = doc.tracking ?? {};
      const advisoryId = tracking.id ?? entry.replace(/\.json$/, '');
      const identifiers = [...new Set([advisoryId, ...extractIdentifiers(JSON.stringify(item.vulnerabilities ?? []), doc.title)])];
      const rawIndexId = await writeRecord(client, ctx, {
        externalKey: advisoryId,
        externalId: advisoryId,
        sourceUrl: url,
        publishedAt: tracking.initial_release_date ?? null,
        modifiedAt: tracking.current_release_date ?? null,
        identifiers,
        recordHash: sha256(stableJson(item)),
        payload: item
      });
      await upsertEcosystemAdvisory(client, rawIndexId, {
        provider: 'suse-csaf',
        ecosystem: 'rpm',
        advisoryId,
        identifiers,
        severityLabel: item.vulnerabilities?.[0]?.scores?.[0]?.cvss_v3?.baseSeverity ?? null,
        references: [{ url }],
        publishedAt: tracking.initial_release_date ?? null,
        modifiedAt: tracking.current_release_date ?? null,
        payload: item
      });
      count++;
    }
  }

  return { fetchedCount: count, parsedCount: count, checkpoint: { indexHash, lastFetched: new Date().toISOString() } };
}
