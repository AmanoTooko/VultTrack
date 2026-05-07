import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fetchBuffer } from '../lib/http.mjs';
import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertOsv } from '../lib/staging.mjs';

export const sourceCode = 'ubuntu-osv';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const buffer = await fetchBuffer('https://security-metadata.canonical.com/osv/osv-all.tar.xz');
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-ubuntu-osv-'));
  const archive = path.join(tmpDir, 'osv-all.tar.xz');
  await fs.writeFile(archive, buffer);
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
  return { fetchedCount: count, parsedCount: count, checkpoint: { count } };
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
