import { fetchJson } from '../lib/http.mjs';
import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertEcosystemAdvisory } from '../lib/staging.mjs';
import { extractIdentifiers } from '../lib/advisory.mjs';

export const sourceCode = 'suse-csaf';

const BASE_URL = 'https://ftp.suse.com/pub/projects/security/csaf';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const indexText = await (await fetch(`${BASE_URL}/index.txt`, { headers: { 'user-agent': 'VulTrack/0.1' } })).text();
  const indexHash = sha256(Buffer.from(indexText));
  if (checkpoint.indexHash === indexHash && !process.env.FETCHER_FORCE) {
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { indexHash, skipped: true } };
  }

  const entries = indexText.split(/\r?\n/).map((x) => x.trim()).filter((x) => x.endsWith('.json'));
  let count = 0;
  for (const entry of entries) {
    if (count >= max) break;
    const url = `${BASE_URL}/${entry}`;
    const item = await fetchJson(url).catch(() => null);
    if (!item) continue;
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

  return { fetchedCount: count, parsedCount: count, checkpoint: { indexHash, lastFetched: new Date().toISOString() } };
}
