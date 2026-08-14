import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fetchJson, fetchText } from '../lib/http.mjs';
import { getIntEnv, getRootPath } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { extractIdentifiers } from '../lib/advisory.mjs';

export const sourceCode = 'suse-csaf';

const BASE_URL = 'https://ftp.suse.com/pub/projects/security/csaf';
const ARCHIVE_URL = 'https://ftp.suse.com/pub/projects/security/csaf.tar.bz2';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const fetchConcurrency = Math.max(1, getIntEnv('CSAF_FETCH_CONCURRENCY', 8));
  const checkpoint = ctx.source.checkpoint_json ?? {};
  if (max === Number.MAX_SAFE_INTEGER) {
    return runArchiveImport(client, ctx, checkpoint);
  }

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
      await writeSuseItem(client, ctx, item, url, entry.replace(/\.json$/, ''));
      count++;
    }
  }

  return { fetchedCount: count, parsedCount: count, checkpoint: { indexHash, lastFetched: new Date().toISOString() } };
}

async function runArchiveImport(client, ctx, checkpoint) {
  const mirrorDir = getRootPath('data/mirrors');
  await fs.mkdir(mirrorDir, { recursive: true });
  const archive = path.join(mirrorDir, 'suse-csaf.tar.bz2');

  // Check existing file hash before re-downloading
  try {
    const existingHash = sha256(await fs.readFile(archive));
    if (checkpoint.archiveHash === existingHash && !process.env.FETCHER_FORCE) {
      console.error('[suse-csaf] archive unchanged, skipping download.');
      return { fetchedCount: 0, parsedCount: 0, checkpoint: { archiveHash: existingHash, skipped: true } };
    }
  } catch {
    // File doesn't exist yet, proceed with download
  }

  const timeoutMs = getIntEnv('FETCHER_TIMEOUT_MS', 600000);
  console.error('[suse-csaf] downloading SUSE CSAF archive...');
  const download = spawnSync('curl', ['-fL', '--retry', '3', '--retry-delay', '2', '-o', archive, ARCHIVE_URL], {
    encoding: 'utf8',
    timeout: timeoutMs
  });
  if (download.status !== 0) throw new Error(`Failed to download SUSE CSAF archive: ${download.stderr}`);

  const archiveHash = sha256(await fs.readFile(archive));
  if (checkpoint.archiveHash === archiveHash && !process.env.FETCHER_FORCE) {
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { archiveHash, skipped: true } };
  }

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-suse-csaf-'));
  try {
    const result = spawnSync('tar', ['-xjf', archive, '-C', tmpDir], { stdio: 'pipe' });
    if (result.status !== 0) throw new Error(`Failed to extract SUSE CSAF archive: ${result.stderr.toString()}`);
    const files = [];
    await walk(tmpDir, files);
    let count = 0;
    for (const file of files) {
      const item = JSON.parse(await fs.readFile(file, 'utf8'));
      const entry = path.basename(file, '.json');
      await writeSuseItem(client, ctx, item, `${BASE_URL}/${path.basename(file)}`, entry);
      count++;
    }
    return { fetchedCount: count, parsedCount: count, checkpoint: { archiveHash, lastFetched: new Date().toISOString() } };
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
}

async function walk(dir, files) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) await walk(full, files);
    else if (entry.isFile() && entry.name.endsWith('.json')) files.push(full);
  }
}

async function writeSuseItem(client, ctx, item, url, fallbackId) {
  const doc = item.document ?? {};
  const tracking = doc.tracking ?? {};
  const advisoryId = tracking.id ?? fallbackId;
  const identifiers = [...new Set([advisoryId, ...extractIdentifiers(JSON.stringify(item.vulnerabilities ?? []), doc.title)])];

  await writeRecord(client, ctx, {
    externalKey: advisoryId,
    externalId: advisoryId,
    sourceUrl: url,
    publishedAt: tracking.initial_release_date ?? null,
    modifiedAt: tracking.current_release_date ?? null,
    identifiers,
    recordHash: sha256(stableJson(item)),
    payload: item
  });
}
