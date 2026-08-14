import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { parse as yamlParse } from 'yaml';
import { getEnv, getIntEnv, getRootPath } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';

export const sourceCode = 'pypi-advisory';

// Clone pypa/advisory-database repo and process OSV-format YAML files
export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const repoPath = getEnv('PYPI_ADVISORY_PATH', getRootPath('data/mirrors/pypi-advisory-db'));

  await ensureRepo(repoPath);

  // Checkpoint: git HEAD commit hash
  const headResult = spawnSync('git', ['-C', repoPath, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
  const headCommit = headResult.status === 0 ? headResult.stdout.trim() : null;

  if (headCommit && checkpoint.commit === headCommit) {
    console.error('PyPI advisory DB unchanged, skipping.');
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { commit: headCommit, skipped: true } };
  }

  const vulnsDir = path.join(repoPath, 'vulns');
  const files = [];
  await walkYaml(vulnsDir, files, max);

  console.error(`Processing ${files.length} PyPI advisory files...`);
  let count = 0;

  for (const file of files) {
    if (count >= max) break;
    try {
      const text = await fs.readFile(file, 'utf8');
      const item = yamlParse(text);
      if (!item || !item.id) continue;

      const ids = [item.id, ...(item.aliases ?? [])].filter(Boolean);
      await writeRecord(client, ctx, {
        externalKey: item.id,
        externalId: item.id,
        sourceUrl: `https://github.com/pypa/advisory-database/blob/main/vulns/${path.basename(file)}`,
        publishedAt: item.published ?? null,
        modifiedAt: item.modified ?? null,
        identifiers: ids,
        recordHash: sha256(stableJson(item)),
        payload: item
      });
      count++;
      if (count % 500 === 0) {
        console.error(`  ${count}/${files.length}...`);
      }
    } catch { continue; }
  }

  return {
    fetchedCount: count,
    parsedCount: count,
    checkpoint: { commit: headCommit, lastFetched: new Date().toISOString() }
  };
}

async function ensureRepo(repoPath) {
  try {
    await fs.access(path.join(repoPath, '.git'));
    const pullResult = spawnSync('git', ['-C', repoPath, 'pull', '--ff-only'], { stdio: 'pipe', timeout: 120000 });
    if (pullResult.status !== 0) {
      await fs.rm(repoPath, { recursive: true, force: true });
      throw new Error('Pull failed, need fresh clone');
    }
  } catch {
    await fs.mkdir(path.dirname(repoPath), { recursive: true });
    await fs.rm(repoPath, { recursive: true, force: true }).catch(() => {});
    console.error('Cloning PyPI advisory database...');
    const result = spawnSync('git', [
      '-c', 'http.version=HTTP/1.1',
      'clone', '--depth=1', '--single-branch',
      'https://github.com/pypa/advisory-database.git', repoPath
    ], { stdio: 'inherit', timeout: 300000 });
    if (result.status !== 0) {
      await fs.rm(repoPath, { recursive: true, force: true }).catch(() => {});
      throw new Error('Failed to clone PyPI advisory database');
    }
  }
}

async function walkYaml(dir, files, max) {
  if (files.length >= max) return;
  let entries;
  try { entries = await fs.readdir(dir, { withFileTypes: true }); }
  catch { return; }
  for (const entry of entries) {
    if (files.length >= max) break;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) await walkYaml(full, files, max);
    else if (entry.isFile() && (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml'))) {
      files.push(full);
    }
  }
}
