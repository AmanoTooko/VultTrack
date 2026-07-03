import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertDebian } from '../lib/staging.mjs';

export const sourceCode = 'debian-security-tracker';
const TRANSFORM_VERSION = 2;

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const checkpoint = ctx.source.checkpoint_json ?? {};

  const resp = await fetch('https://security-tracker.debian.org/tracker/data/json', {
    headers: { 'user-agent': 'VulTrack/0.1', 'accept': 'application/json' }
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} for Debian tracker`);
  const text = await resp.text();
  const contentHash = sha256(Buffer.from(text));

  if (checkpoint.contentHash === contentHash && checkpoint.transformVersion === TRANSFORM_VERSION) {
    console.error('Debian tracker unchanged, skipping.');
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { contentHash, transformVersion: TRANSFORM_VERSION, skipped: true } };
  }

  const data = JSON.parse(text);
  const records = groupByCve(data);
  const unchanged = await loadSucceededRecordHashes(client, ctx.source.id);
  let count = 0;
  let changed = 0;
  for (const [cveId, packages] of records) {
    if (count >= max) break;
    const payload = { cveId, packages };
    const recordHash = sha256(stableJson(payload));
    if (unchanged.get(cveId)?.has(recordHash)) {
      count++;
      continue;
    }

    const rawIndexId = await writeRecord(client, ctx, {
      externalKey: cveId,
      externalId: cveId,
      sourceUrl: `https://security-tracker.debian.org/tracker/${cveId}`,
      identifiers: [cveId],
      recordHash,
      payload
    });
    await upsertDebian(client, rawIndexId, cveId, packages, payload);
    count++;
    changed++;
  }
  return { fetchedCount: records.size, changedCount: changed, parsedCount: changed, checkpoint: { contentHash, transformVersion: TRANSFORM_VERSION, lastFetched: new Date().toISOString() } };
}

export function groupByCve(data) {
  const records = new Map();
  for (const [packageName, advisories] of Object.entries(data ?? {})) {
    for (const [cveId, advisory] of Object.entries(advisories ?? {})) {
      if (!/^(CVE|TEMP)-/i.test(cveId)) continue;
      if (!records.has(cveId)) records.set(cveId, {});
      records.get(cveId)[packageName] = advisory;
    }
  }
  return records;
}

async function loadSucceededRecordHashes(client, sourceId) {
  const result = await client.query(
    `select external_key, record_hash
     from source_raw_index
     where source_id = $1
       and normalize_status in ('succeeded', 'superseded')`,
    [sourceId]
  );
  const hashes = new Map();
  for (const row of result.rows) {
    if (!hashes.has(row.external_key)) hashes.set(row.external_key, new Set());
    hashes.get(row.external_key).add(row.record_hash);
  }
  return hashes;
}
