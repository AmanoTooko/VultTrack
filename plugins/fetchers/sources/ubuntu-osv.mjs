import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { getBoolEnv, getCsvEnv, getIntEnv, getRootPath } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertOsv } from '../lib/staging.mjs';

export const sourceCode = 'ubuntu-osv';
const UBUNTU_OSV_URL = 'https://security-metadata.canonical.com/osv/osv-all.tar.xz';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const explicitIds = getCsvEnv('UBUNTU_OSV_IDS');
  if (explicitIds.length || getBoolEnv('FETCHER_SMOKE')) {
    return runBoundedApi(client, ctx, max, explicitIds.length ? explicitIds : ['UBUNTU-CVE-2002-2443', 'UBUNTU-CVE-2004-2771']);
  }
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const metadata = await fetchMetadata(UBUNTU_OSV_URL);
  if (metadata.etag && checkpoint.etag === metadata.etag) {
    console.error('Ubuntu OSV tarball unchanged by ETag, skipping.');
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { ...checkpoint, ...metadata, skipped: true } };
  }

  const mirrorDir = getRootPath('data/mirrors');
  await fs.mkdir(mirrorDir, { recursive: true });
  const archive = path.join(mirrorDir, 'ubuntu-osv-all.tar.xz');
  const timeoutMs = getIntEnv('FETCHER_TIMEOUT_MS', 600000);
  const download = spawnSync('curl', ['-fL', '--retry', '3', '--retry-delay', '2', '-o', archive, UBUNTU_OSV_URL], {
    encoding: 'utf8',
    timeout: timeoutMs
  });
  if (download.status !== 0) throw new Error(`Failed to download Ubuntu OSV tarball: ${download.stderr}`);

  const contentHash = sha256(await fs.readFile(archive));
  if (checkpoint.contentHash === contentHash) {
    console.error('Ubuntu OSV tarball unchanged, skipping.');
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { contentHash, ...metadata, skipped: true } };
  }
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-ubuntu-osv-'));
  const result = spawnSync('tar', ['-xJf', archive, '-C', tmpDir], { stdio: 'pipe' });
  if (result.status !== 0) throw new Error(`Failed to extract Ubuntu OSV tarball: ${result.stderr.toString()}`);
  const files = [];
  await walk(tmpDir, files, max);
  let count = 0;
  for (const file of files) {
    if (count >= max) break;
    const item = JSON.parse(await fs.readFile(file, 'utf8'));
    const ids = [item.id, ...(item.aliases ?? [])].filter(Boolean);
    const rawIndexId = await writeRecord(client, ctx, {
      externalKey: item.id,
      externalId: item.id,
      sourceUrl: 'https://security-metadata.canonical.com/osv/',
      identifiers: ids,
      publishedAt: item.published,
      modifiedAt: item.modified,
      recordHash: sha256(stableJson(item)),
      payload: item
    });
    await upsertOsv(client, rawIndexId, item, 'stg_ubuntu_osv');
    count++;
  }
  await fs.rm(tmpDir, { recursive: true, force: true });
  return { fetchedCount: count, parsedCount: count, checkpoint: { contentHash, ...metadata, lastFetched: new Date().toISOString() } };
}

async function fetchMetadata(url) {
  try {
    const res = await fetch(url, { method: 'HEAD', headers: { 'user-agent': 'VulTrack/0.1' } });
    if (!res.ok) return {};
    return {
      etag: res.headers.get('etag') ?? undefined,
      lastModified: res.headers.get('last-modified') ?? undefined,
      contentLength: res.headers.get('content-length') ?? undefined
    };
  } catch {
    return {};
  }
}

async function runBoundedApi(client, ctx, max, ids) {
  let count = 0;
  for (const id of ids) {
    if (count >= max) break;
    const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, {
      headers: { 'user-agent': 'VulTrack/0.1' }
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} for OSV vuln ${id}`);
    const item = await res.json();
    const identifiers = [item.id, ...(item.aliases ?? [])].filter(Boolean);
    const rawIndexId = await writeRecord(client, ctx, {
      externalKey: item.id,
      externalId: item.id,
      sourceUrl: `https://osv.dev/vulnerability/${item.id}`,
      identifiers,
      publishedAt: item.published,
      modifiedAt: item.modified,
      recordHash: sha256(stableJson(item)),
      payload: item
    });
    await upsertOsv(client, rawIndexId, item, 'stg_ubuntu_osv');
    count++;
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { ids: ids.slice(0, count), lastFetched: new Date().toISOString() } };
}

async function walk(dir, files, max) {
  if (files.length >= max) return;
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (files.length >= max) break;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) await walk(full, files, max);
    else if (entry.isFile() && entry.name.endsWith('.json')) files.push(full);
  }
}
