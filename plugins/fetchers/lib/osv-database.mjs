import fs from 'node:fs/promises';
import { createWriteStream, existsSync } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import { spawnSync } from 'node:child_process';
import { getBoolEnv, getIntEnv, getRootPath } from './env.mjs';
import { sha256, stableJson } from './hash.mjs';
import { writeRecord } from './db.mjs';
import { upsertAndroidOsv, upsertOsv } from './staging.mjs';

const BASE_URL = 'https://storage.googleapis.com/osv-vulnerabilities';

export async function runOsvAllZipInit(client, ctx, options = {}) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const zipUrl = options.ecosystem ? `${BASE_URL}/${encodeURIComponent(options.ecosystem)}/all.zip` : `${BASE_URL}/all.zip`;
  const zipName = options.ecosystem ? `osv-${options.ecosystem.toLowerCase()}-all.zip` : 'osv-all.zip';
  const tmpDir = getRootPath('data/mirrors');
  await fs.mkdir(tmpDir, { recursive: true });
  const zipPath = `${tmpDir}/${zipName}`;

  if (!existsSync(zipPath) || process.env.FETCHER_REFRESH_MIRROR) {
    const resp = await fetch(zipUrl, { headers: { 'user-agent': 'VulTrack/0.1' } });
    if (!resp.ok || !resp.body) throw new Error(`Failed to download OSV all.zip: HTTP ${resp.status}`);
    await pipeline(Readable.fromWeb(resp.body), createWriteStream(zipPath));
  }

  const contentHash = sha256(await fs.readFile(zipPath));
  if (checkpoint.contentHash === contentHash && !process.env.FETCHER_FORCE) {
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { contentHash, skipped: true } };
  }

  const list = spawnSync('unzip', ['-Z1', zipPath], { encoding: 'utf8', maxBuffer: 80 * 1024 * 1024 });
  if (list.status !== 0) throw new Error(`Failed to list OSV all.zip entries: ${list.stderr}`);
  const entries = list.stdout
    .split('\n')
    .filter((entry) => entry.endsWith('.json'))
    .filter((entry) => !options.prefixes || options.prefixes.some((prefix) => entry.startsWith(prefix)));

  let count = 0;
  for (const entryName of entries) {
    if (count >= max) break;
    const result = spawnSync('unzip', ['-p', zipPath, entryName], { encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 });
    if (result.status !== 0) continue;
    const item = JSON.parse(result.stdout);
    if (options.filter && !options.filter(item)) continue;
    await writeOsvItem(client, ctx, item, options);
    count++;
  }

  return { fetchedCount: count, parsedCount: count, checkpoint: { contentHash, lastFetched: new Date().toISOString() } };
}

export async function runOsvModifiedIdIncremental(client, ctx, options = {}) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const explicitIds = options.ids ?? [];
  if (explicitIds.length) {
    return runOsvIds(client, ctx, explicitIds.slice(0, max), options);
  }
  if (getBoolEnv('FETCHER_SMOKE') && options.smokeIds?.length) {
    return runOsvIds(client, ctx, options.smokeIds.slice(0, max), options);
  }

  const checkpoint = ctx.source.checkpoint_json ?? {};
  const csvUrl = options.ecosystem ? `${BASE_URL}/${encodeURIComponent(options.ecosystem)}/modified_id.csv` : `${BASE_URL}/modified_id.csv`;
  const csvResp = await fetch(csvUrl, { headers: { 'user-agent': 'VulTrack/0.1' } });
  if (!csvResp.ok) throw new Error(`HTTP ${csvResp.status} for ${csvUrl}`);
  const csv = await csvResp.text();

  const fallbackSince = new Date(Date.now() - getIntEnv('OSV_INCREMENTAL_LOOKBACK_DAYS', 2) * 86400000).toISOString();
  const watermark = checkpoint.lastModifiedWatermark ?? fallbackSince;
  const ids = [];
  let latestSeen = null;
  let lastProcessedTimestamp = null;
  let eligibleSeen = 0;
  let hitLimit = false;
  let reachedWatermark = false;
  let resumeOffset = 0;

  for (const line of csv.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const [modifiedAt, rawId] = line.split(',', 2);
    if (!modifiedAt || !rawId) continue;
    latestSeen ??= modifiedAt;
    const partial = checkpoint.partial;
    if (
      max < Number.MAX_SAFE_INTEGER &&
      partial?.latestSeen === latestSeen &&
      partial?.watermark === watermark &&
      Number.isInteger(partial.offset) &&
      !process.env.FETCHER_FORCE
    ) {
      resumeOffset = partial.offset;
    }
    if (modifiedAt <= watermark) break;
    if (options.idFilter && !options.idFilter(rawId)) continue;
    if (eligibleSeen < resumeOffset) {
      eligibleSeen++;
      continue;
    }
    ids.push({ modifiedAt, rawId });
    eligibleSeen++;
    if (ids.length >= max) break;
  }

  let count = 0;
  for (const itemRef of ids) {
    const item = await fetchOsvItem(itemRef.rawId, options.ecosystem);
    if (options.filter && !options.filter(item)) continue;
    await writeOsvItem(client, ctx, item, options);
    count++;
    lastProcessedTimestamp = itemRef.modifiedAt;
  }

  const processedOffset = resumeOffset + ids.length;
  hitLimit = ids.length >= max && max < Number.MAX_SAFE_INTEGER;
  reachedWatermark = !hitLimit;

  if (hitLimit) {
    return {
      fetchedCount: count,
      parsedCount: count,
      checkpoint: {
        lastModifiedWatermark: watermark,
        latestSeen,
        partial: {
          latestSeen,
          watermark,
          offset: processedOffset,
          lastProcessedTimestamp
        },
        lastFetched: new Date().toISOString()
      }
    };
  }

  return {
    fetchedCount: count,
    parsedCount: count,
    checkpoint: {
      lastModifiedWatermark: reachedWatermark ? (latestSeen ?? watermark) : (lastProcessedTimestamp ?? checkpoint.lastModifiedWatermark ?? latestSeen ?? watermark),
      latestSeen,
      lastFetched: new Date().toISOString()
    }
  };
}

async function runOsvIds(client, ctx, ids, options) {
  let count = 0;
  for (const id of ids) {
    const item = await fetchOsvItem(id, options.ecosystem);
    if (options.filter && !options.filter(item)) continue;
    await writeOsvItem(client, ctx, item, options);
    count++;
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { ids, lastFetched: new Date().toISOString() } };
}

async function fetchOsvItem(rawId, ecosystem) {
  const path = ecosystem ? `${encodeURIComponent(ecosystem)}/${encodeURIComponent(rawId)}.json` : `${rawId}.json`;
  const resp = await fetch(`${BASE_URL}/${path}`, { headers: { 'user-agent': 'VulTrack/0.1' } });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} for OSV record ${rawId}`);
  return resp.json();
}

async function writeOsvItem(client, ctx, item, options) {
  const ids = [item.id, ...(item.aliases ?? [])].filter(Boolean);
  const rawIndexId = await writeRecord(client, ctx, {
    externalKey: item.id,
    externalId: item.id,
    sourceUrl: `https://osv.dev/vulnerability/${item.id}`,
    publishedAt: item.published,
    modifiedAt: item.modified,
    identifiers: ids,
    recordHash: sha256(stableJson(item)),
    payload: item
  });

  if (options.androidTable) {
    await upsertAndroidOsv(client, rawIndexId, item).catch(async () => upsertOsv(client, rawIndexId, item));
    return;
  }

  await upsertOsv(client, rawIndexId, item, options.table);
}
