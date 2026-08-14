import fs from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { getRootPath } from './env.mjs';
import { sha256, stableJson } from './hash.mjs';

export async function withClient(fn) {
  const client = { __spool: true, activeRun: null, stream: null };
  try {
    return await fn(client);
  } finally {
    await closeSpool(client, false);
    await rollbackSpoolCommitHooks(client);
  }
}

export async function getSource(client, code) {
  const state = await readSpoolState(code);
  return {
    id: code,
    code,
    name: code,
    kind: 'vulnerability',
    enabled: true,
    config_json: {},
    checkpoint_json: state.checkpoint ?? {},
    has_records: Boolean(state.hasRecords)
  };
}

export async function startRun(client, sourceId, trigger = 'manual') {
  const run = {
    id: crypto.randomUUID(),
    source_id: sourceId,
    trigger,
    status: 'running',
    started_at: new Date().toISOString()
  };
  client.activeRun = run;
  return run;
}

export async function finishRun(client, runId, patch) {
  const run = client.activeRun ?? { id: runId, source_id: 'unknown' };
  const state = await readSpoolState(run.source_id);
  await writeSpoolState(run.source_id, {
    ...state,
    checkpoint: patch.checkpoint ?? state.checkpoint ?? {},
    hasRecords: Boolean(state.hasRecords || (patch.fetchedCount ?? 0) > 0),
    lastRun: {
      ...run,
      status: patch.status,
      finished_at: new Date().toISOString(),
      fetched_count: patch.fetchedCount ?? 0,
      parsed_count: patch.parsedCount ?? 0,
      error_count: patch.errorCount ?? 0,
      log_summary: patch.logSummary ?? null
    }
  });
}

export async function writeRecord(client, ctx, record) {
  await writeSpoolRecord(client, ctx, record);
  return null;
}

export async function flushWriteBatch(client) {
  await closeSpool(client, true);
  await commitSpoolCommitHooks(client);
}

export async function rollbackWriteBatch(client) {
  await closeSpool(client, false);
  await rollbackSpoolCommitHooks(client);
}

export async function saveCheckpoint(client, sourceId, checkpoint) {
  // Commit a checkpoint only after the corresponding spool is atomically
  // promoted to .ready. A mid-run checkpoint plus a lost .partial file
  // would otherwise skip records after restart.
  client.pendingCheckpoint = checkpoint;
}

// Some fetchers keep compact local indexes beside their spool state. These
// hooks make the index visible only after the matching .partial was promoted.
export function registerSpoolCommitHook(client, hook) {
  if (typeof hook?.commit !== 'function') throw new Error('Spool commit hook must provide commit()');
  (client.spoolCommitHooks ??= []).push(hook);
}

export function resumeInitOffset(checkpoint, identity = {}) {
  if (checkpoint?.initComplete !== false) return 0;
  for (const [key, value] of Object.entries(identity)) {
    if (checkpoint[key] !== value) return 0;
  }
  const offset = Number(checkpoint.offset);
  return Number.isSafeInteger(offset) && offset >= 0 ? offset : 0;
}

export async function saveInitProgress(client, ctx, checkpoint) {
  const next = { ...checkpoint, initComplete: false };
  await saveCheckpoint(client, ctx.source.id, next);
  ctx.source.checkpoint_json = next;
  return next;
}

export async function sourceHasRawRecords(client, sourceId) {
  const state = await readSpoolState(sourceId);
  return Boolean(state.hasRecords);
}

/**
 * Bulk init fetcher: download archive from URL, extract, and run processFile for each entry.
 * Supports .zip, .tar.xz, .json.gz formats via system tools.
 * Skips if archive hash matches checkpoint.
 */
export async function initFetch({ ctx, archiveUrl, format, processFile }) {
  const fs = await import('node:fs/promises');
  const path = await import('node:path');
  const { createWriteStream } = await import('node:fs');
  const { pipeline } = await import('node:stream/promises');
  const { Readable } = await import('node:stream');
  const { spawnSync } = await import('node:child_process');

  const checkpoint = ctx.source.checkpoint_json ?? {};
  const max = Number(process.env.FETCHER_MAX_RECORDS) || Number.MAX_SAFE_INTEGER;
  const tmpDir = getRootPath('data/mirrors');
  await fs.mkdir(tmpDir, { recursive: true });

  const ext = archiveUrl.split('.').pop();
  const archivePath = path.default.join(tmpDir, `init-${ctx.source.code}-${Date.now()}.${ext}`);

  // Download
  console.error(`Downloading ${archiveUrl}...`);
  const resp = await fetch(archiveUrl, {
    headers: {
      'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
    }
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} for ${archiveUrl}`);
  if (!resp.body) throw new Error('Response has no body');

  const fileStream = createWriteStream(archivePath);
  await pipeline(Readable.fromWeb(resp.body), fileStream);

  // Check hash
  const fileHash = sha256(await fs.readFile(archivePath));
  if (checkpoint.archiveHash === fileHash) {
    console.error('Archive unchanged, skipping.');
    await fs.unlink(archivePath).catch(() => {});
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { archiveHash: fileHash, skipped: true } };
  }

  console.error('Download complete, extracting...');
  if (format === 'zip-list' || ext === 'zip') {
    // List .json entries
    const list = spawnSync('unzip', ['-Z1', archivePath], { encoding: 'utf8', maxBuffer: 50 * 1024 * 1024 });
    if (list.status !== 0) throw new Error(`Failed to list archive: ${list.stderr}`);
    const files = list.stdout.split('\n').filter(f => f.endsWith('.json'));
    for (const entry of files) {
      const result = spawnSync('unzip', ['-p', archivePath, entry], { encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 });
      if (result.status !== 0) continue;
      try {
        await processFile(entry, JSON.parse(result.stdout));
      } catch { continue; }
    }
  } else if (format === 'tar-xz-list' || ext === 'xz') {
    const extractDir = path.default.join(tmpDir, `init-extract-${Date.now()}`);
    await fs.mkdir(extractDir, { recursive: true });
    spawnSync('tar', ['-xJf', archivePath, '-C', extractDir], { stdio: 'pipe' });
    const walked = [];
    await walkDir(extractDir, walked, max);
    for (const f of walked) {
      try {
        const item = JSON.parse(await fs.readFile(f, 'utf8'));
        await processFile(path.default.basename(f), item);
      } catch { continue; }
    }
    await fs.rm(extractDir, { recursive: true, force: true }).catch(() => {});
  } else {
    // Assume JSON or gzip JSON
    throw new Error(`Unsupported format: ${format}`);
  }

  await fs.unlink(archivePath).catch(() => {});
  return { checkpoint: { archiveHash: fileHash, lastFetched: new Date().toISOString() } };
}

async function walkDir(dir, files, max) {
  const fs = await import('node:fs/promises');
  const path = await import('node:path');
  if (files.length >= max) return;
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (files.length >= max) break;
    const full = path.default.join(dir, entry.name);
    if (entry.isDirectory()) await walkDir(full, files, max);
    else if (entry.isFile() && entry.name.endsWith('.json')) files.push(full);
  }
}

export async function recordError(client, ctx, stage, error, externalKey = null) {
  const state = await readSpoolState(ctx.source?.code ?? ctx.source?.id ?? 'unknown');
  await writeSpoolState(ctx.source?.code ?? ctx.source?.id ?? 'unknown', {
    ...state,
    lastError: {
      at: new Date().toISOString(),
      stage,
      externalKey,
      code: error.code ?? error.name ?? 'ERROR',
      message: error.message ?? String(error)
    }
  });
}

async function writeSpoolRecord(client, ctx, record) {
  if (!client.stream) {
    const dir = spoolPath('incoming');
    await fs.mkdir(dir, { recursive: true });
    const sequence = client.spoolSequence ?? 0;
    const suffix = `-s${String(sequence).padStart(4, '0')}`;
    const base = `${safeFilePart(ctx.source.code)}-${ctx.run.id}${suffix}`;
    client.partialPath = path.join(dir, `${base}.ndjson.partial`);
    client.readyPath = path.join(dir, `${base}.ndjson.ready`);
    client.stream = createWriteStream(client.partialPath, {
      flags: 'wx',
      highWaterMark: 4 * 1024 * 1024
    });
  }

  const payload = stableJson({
    schemaVersion: 1,
    sourceCode: ctx.source.code,
    sourceMode: (client.spoolSequence ?? 0) > 0 ||
      (ctx.source.has_records && ctx.source.checkpoint_json?.initComplete === false)
      ? 'append'
      : null,
    runId: ctx.run.id,
    externalKey: record.externalKey,
    externalId: record.externalId ?? record.externalKey,
    sourceUrl: record.sourceUrl ?? null,
    publishedAt: record.publishedAt ?? null,
    modifiedAt: record.modifiedAt ?? null,
    snapshotId: record.snapshotId ?? null,
    snapshotComplete: record.snapshotComplete ?? null,
    recordHash: record.recordHash ?? sha256(Buffer.from(stableJson(record.payload))),
    identifiers: record.identifiers ?? [],
    payload: record.payload
  });
  if (!client.stream.write(`${payload}\n`)) {
    await new Promise((resolve, reject) => {
      const onDrain = () => {
        client.stream.off('error', onError);
        resolve();
      };
      const onError = (error) => {
        client.stream.off('drain', onDrain);
        reject(error);
      };
      client.stream.once('drain', onDrain);
      client.stream.once('error', onError);
    });
  }
}

async function closeSpool(client, commit) {
  if (!client.stream) return;
  const stream = client.stream;
  client.stream = null;
  await new Promise((resolve, reject) => {
    stream.once('error', reject);
    stream.end(resolve);
  });
  if (commit) {
    await fs.rename(client.partialPath, client.readyPath);
    client.spoolSequence = (client.spoolSequence ?? 0) + 1;
  } else {
    await fs.rm(client.partialPath, { force: true }).catch(() => {});
  }
}

async function commitSpoolCommitHooks(client) {
  const hooks = client.spoolCommitHooks ?? [];
  if (!hooks.length) return;
  for (const hook of hooks) await hook.commit();
  client.spoolCommitHooks = [];
}

async function rollbackSpoolCommitHooks(client) {
  const hooks = client.spoolCommitHooks ?? [];
  client.spoolCommitHooks = [];
  await Promise.all(hooks.map((hook) => hook.rollback?.().catch(() => {})));
}

export async function commitSpoolSegment(client, sourceId, checkpoint) {
  await closeSpool(client, true);
  const state = await readSpoolState(sourceId);
  await writeSpoolState(sourceId, {
    ...state,
    checkpoint,
    hasRecords: true,
    lastSegmentCommittedAt: new Date().toISOString()
  });
  client.pendingCheckpoint = checkpoint;
}

function spoolPath(...parts) {
  return getRootPath(process.env.VULTRACK_SPOOL_PATH ?? 'data/spool', ...parts);
}

function spoolStatePath(sourceCode) {
  return spoolPath('state', `${safeFilePart(sourceCode)}.json`);
}

async function readSpoolState(sourceCode) {
  try {
    return JSON.parse(await fs.readFile(spoolStatePath(sourceCode), 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return {};
    throw error;
  }
}

async function writeSpoolState(sourceCode, state) {
  const statePath = spoolStatePath(sourceCode);
  await fs.mkdir(path.dirname(statePath), { recursive: true });
  const temporary = `${statePath}.${process.pid}.tmp`;
  await fs.writeFile(temporary, `${JSON.stringify(state)}\n`, 'utf8');
  await fs.rename(temporary, statePath);
}

function safeFilePart(value) {
  return String(value).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 100);
}
