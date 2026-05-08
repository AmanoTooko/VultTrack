import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { getIntEnv, getRootPath } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertOsv } from '../lib/staging.mjs';

export const sourceCode = 'go-advisory';

// Clone golang/vulndb and process OSV JSON files
async function ensureRepo(repoPath) {
  try {
    await fs.access(path.join(repoPath, '.git'));
    console.error('[go-advisory] pulling golang/vulndb...');
    spawnSync('git', ['-C', repoPath, 'pull', '--depth', '1'], { stdio: 'inherit' });
  } catch {
    console.error('[go-advisory] cloning golang/vulndb...');
    await fs.mkdir(repoPath, { recursive: true });
    spawnSync('git', ['clone', '--depth', '1', 'https://github.com/golang/vulndb.git', repoPath], { stdio: 'inherit' });
  }
}

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const repoPath = getRootPath('data/mirrors/go-vulndb');

  await ensureRepo(repoPath);

  const headResult = spawnSync('git', ['-C', repoPath, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
  const headCommit = headResult.status === 0 ? headResult.stdout.trim() : null;
  if (headCommit && checkpoint.commit === headCommit) {
    console.error('[go-advisory] unchanged, skipping.');
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { commit: headCommit, skipped: true } };
  }

  // Walk OSV JSON files (data/osv/ or similar structure)
  const walkDirs = [path.join(repoPath, 'data', 'osv'), path.join(repoPath, 'data', 'reports')];
  const files = [];
  for (const dir of walkDirs) {
    try { await fs.access(dir); } catch { continue; }
    async function walk(d) {
      for (const item of await fs.readdir(d, { withFileTypes: true })) {
        const full = path.join(d, item.name);
        if (item.isDirectory()) await walk(full);
        else if (item.name.endsWith('.json')) files.push(full);
      }
    }
    await walk(dir);
  }

  console.error(`[go-advisory] found ${files.length} advisory files`);

  let count = 0;
  for (const file of files) {
    if (count >= max) break;
    const raw = await fs.readFile(file, 'utf8');
    let item;
    try { item = JSON.parse(raw); } catch { continue; }
    if (!item.id) continue;

    // Convert to standard format if needed
    const ids = [item.id, ...(item.aliases ?? [])].filter(Boolean);
    const rawIndexId = await writeRecord(client, ctx, {
      externalKey: item.id,
      externalId: item.id,
      sourceUrl: item.id.startsWith('GO-') ? `https://pkg.go.dev/vuln/${item.id}` : `https://osv.dev/vulnerability/${item.id}`,
      publishedAt: item.published,
      modifiedAt: item.modified || item.published,
      identifiers: ids,
      recordHash: sha256(stableJson(item)),
      payload: item
    });
    await upsertOsv(client, rawIndexId, item);
    count++;
    if (count % 100 === 0) console.error(`[go-advisory] ${count} records...`);
  }

  console.error(`[go-advisory] done, ${count} records`);
  return { fetchedCount: count, parsedCount: count, checkpoint: { commit: headCommit, lastFetched: new Date().toISOString() } };
}
