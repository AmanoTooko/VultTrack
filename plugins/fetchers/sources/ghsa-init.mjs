import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { getIntEnv, getRootPath } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { commitSpoolSegment, writeRecord } from '../lib/db.mjs';

export const sourceCode = 'ghsa-init';
export const runMode = 'init';

const DEFAULT_REPOSITORY = 'https://github.com/github/advisory-database.git';
const DEFAULT_MIRROR_DIR = 'data/mirrors/github-advisory-database';
const INIT_MODE = 'github-reviewed-v1';
const DEFAULT_SEGMENT_SIZE = 5000;

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const segmentSize = getIntEnv('GHSA_INIT_SEGMENT_SIZE', DEFAULT_SEGMENT_SIZE);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const incrementalSince = checkpoint.incrementalSince ?? new Date().toISOString();
  const repository = process.env.GHSA_ADVISORY_REPOSITORY ?? DEFAULT_REPOSITORY;
  const mirrorPath = getRootPath(process.env.GHSA_ADVISORY_MIRROR_PATH ?? DEFAULT_MIRROR_DIR);
  await prepareMirror(mirrorPath, checkpoint, repository);

  const revision = gitOutput(mirrorPath, ['rev-parse', 'HEAD']);
  const entries = gitOutput(mirrorPath, ['ls-files', 'advisories/github-reviewed'])
    .split('\n')
    .filter((entry) => entry.endsWith('.json'))
    .sort();
  const canResume = checkpoint.initComplete === false
    && checkpoint.initMode === INIT_MODE
    && checkpoint.revision === revision;
  const startOffset = canResume ? Math.max(0, Number(checkpoint.offset) || 0) : 0;
  let nextOffset = startOffset;
  let latestModified = canResume ? checkpoint.latestModified ?? null : null;
  let skippedEntries = canResume ? Math.max(0, Number(checkpoint.skippedEntries) || 0) : 0;
  let count = 0;

  for (let index = startOffset; index < entries.length && count < max; index++) {
    const entry = entries[index];
    nextOffset = index + 1;
    let item;
    try {
      item = JSON.parse(await fs.readFile(path.join(mirrorPath, entry), 'utf8'));
    } catch (error) {
      skippedEntries++;
      console.error(`[ghsa-init] skipped invalid JSON ${entry}: ${error.message}`);
      continue;
    }
    if (!item.id?.startsWith('GHSA-')) {
      skippedEntries++;
      console.error(`[ghsa-init] skipped non-GHSA advisory ${entry}`);
      continue;
    }
    const modified = item.modified ?? null;
    if (modified && (!latestModified || modified > latestModified)) latestModified = modified;
    await writeRecord(client, ctx, {
      externalKey: item.id,
      externalId: item.id,
      sourceUrl: `https://github.com/advisories/${item.id}`,
      publishedAt: item.published,
      modifiedAt: modified,
      identifiers: [item.id, ...(item.aliases ?? [])],
      recordHash: sha256(stableJson(item)),
      payload: item
    });
    count++;

    if (client.__spool && count % segmentSize === 0) {
      const segmentCheckpoint = makeCheckpoint({
        revision,
        incrementalSince,
        latestModified,
        skippedEntries,
        offset: nextOffset,
        totalEntries: entries.length
      });
      await commitSpoolSegment(client, ctx.source.id, segmentCheckpoint);
      ctx.source.checkpoint_json = segmentCheckpoint;
      console.error(`[ghsa-init] committed ${nextOffset}/${entries.length}`);
    }
  }

  const complete = nextOffset >= entries.length;
  const nextCheckpoint = makeCheckpoint({
    revision,
    incrementalSince,
    latestModified,
    skippedEntries,
    offset: nextOffset,
    totalEntries: entries.length,
    complete
  });
  return { fetchedCount: count, parsedCount: count, checkpoint: nextCheckpoint };
}

function makeCheckpoint({ revision, incrementalSince, latestModified, skippedEntries, offset, totalEntries, complete = false }) {
  return {
    initMode: INIT_MODE,
    initComplete: complete,
    revision,
    incrementalSince,
    latestModified,
    skippedEntries,
    offset,
    totalEntries,
    lastFetched: new Date().toISOString()
  };
}

async function prepareMirror(mirrorPath, checkpoint, repository) {
  const localRevision = tryGitOutput(mirrorPath, ['rev-parse', 'HEAD']);
  const resumePinned = checkpoint.initComplete === false
    && checkpoint.initMode === INIT_MODE
    && checkpoint.revision === localRevision;
  if (resumePinned) return;

  if (localRevision) {
    runGit(mirrorPath, ['fetch', '--depth', '1', 'origin', 'main']);
    runGit(mirrorPath, ['reset', '--hard', 'FETCH_HEAD']);
    return;
  }

  await fs.mkdir(path.dirname(mirrorPath), { recursive: true });
  const result = spawnSync('git', ['clone', '--depth', '1', '--branch', 'main', repository, mirrorPath], {
    stdio: 'inherit'
  });
  if (result.status !== 0) throw new Error('Unable to clone GitHub advisory database');
}

function runGit(repo, args) {
  const result = spawnSync('git', ['-C', repo, ...args], { stdio: 'inherit' });
  if (result.status !== 0) throw new Error(`git ${args.join(' ')} failed`);
}

function gitOutput(repo, args) {
  const result = spawnSync('git', ['-C', repo, ...args], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024
  });
  if (result.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${result.stderr}`);
  return result.stdout.trim();
}

function tryGitOutput(repo, args) {
  try {
    return gitOutput(repo, args);
  } catch {
    return null;
  }
}
