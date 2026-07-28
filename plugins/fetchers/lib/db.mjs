import pg from 'pg';
import fs from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { getEnv, getRootPath } from './env.mjs';
import { sha256, stableJson } from './hash.mjs';

const gzip = promisify(zlib.gzip);
let sourceObjectStorageSchemaEnsured = false;
const writeBatchStates = new WeakMap();

export function isSpoolBackend() {
  return String(process.env.VULTRACK_STORAGE_BACKEND ?? process.env.FETCHER_BACKEND ?? '').toLowerCase() === 'duckdb';
}

export function createPool() {
  return new pg.Pool({
    connectionString: getEnv('DATABASE_URL', 'postgres://vultrack:vultrack@localhost:5432/vultrack')
  });
}

export async function withClient(fn) {
  if (isSpoolBackend()) {
    const client = { __spool: true, activeRun: null, stream: null };
    try {
      return await fn(client);
    } finally {
      await closeSpool(client, false);
      await rollbackSpoolCommitHooks(client);
    }
  }
  const pool = createPool();
  const client = await pool.connect();
  try {
    return await fn(client);
  } finally {
    client.release();
    await pool.end();
  }
}

export async function getSource(client, code) {
  if (client.__spool) {
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
  const result = await client.query('select * from sources where code = $1', [code]);
  if (!result.rowCount) throw new Error(`Unknown source: ${code}`);
  return result.rows[0];
}

export async function startRun(client, sourceId, trigger = 'manual') {
  if (client.__spool) {
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
  const result = await client.query(
    `insert into source_sync_runs (source_id, status, trigger, checkpoint_before)
     select id, 'running', $2, checkpoint_json
     from sources
     where id = $1
     returning *`,
    [sourceId, trigger]
  );
  return result.rows[0];
}

export async function finishRun(client, runId, patch) {
  if (client.__spool) {
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
    return;
  }
  await client.query(
    `update source_sync_runs
     set status = $2,
         checkpoint_after = coalesce($3, checkpoint_after),
         finished_at = now(),
         fetched_count = $4,
         changed_count = $5,
         parsed_count = $6,
         error_count = $7,
         log_summary = $8
     where id = $1`,
    [
      runId,
      patch.status,
      patch.checkpoint ?? null,
      patch.fetchedCount ?? 0,
      patch.changedCount ?? 0,
      patch.parsedCount ?? 0,
      patch.errorCount ?? 0,
      patch.logSummary ?? null
    ]
  );
}

export async function writeRecord(client, ctx, record) {
  if (client.__spool) {
    await writeSpoolRecord(client, ctx, record);
    return null;
  }
  await rotateWriteBatch(client);
  const json = Buffer.from(stableJson(record.payload));
  const contentHash = sha256(json);
  const recordHash = record.recordHash ?? contentHash;
  const existing = await client.query(
    `select id
       from source_raw_index
      where source_id = $1
        and external_key = $2
        and record_hash = $3
        and normalize_status = 'succeeded'
      limit 1`,
    [ctx.source.id, record.externalKey, recordHash]
  );
  if (existing.rowCount) {
    await client.query(
      `update source_raw_index
          set sync_run_id = $2, updated_at = now()
        where id = $1`,
      [existing.rows[0].id, ctx.run.id]
    );
    return null;
  }

  const store = getRawObjectStore();
  let objectId = null;
  if (store !== 'none') {
    const compressed = await gzip(json);
    const stored = await storeRawObject(client, ctx, {
      compressed,
      contentHash,
      externalKey: record.externalKey,
      suffix: `${recordHash.slice(0, 12)}.json.gz`
    });

    const objectResult = await client.query(
      `insert into source_objects
         (source_id, sync_run_id, object_uri, content_type, compression, sha256, size_bytes, compressed_size_bytes, schema_hint, compressed_content)
       values ($1,$2,$3,'application/json','gzip',$4,$5,$6,$7,$8)
       on conflict (source_id, sha256) do update set
         object_uri = excluded.object_uri,
         sync_run_id = excluded.sync_run_id,
         compressed_content = coalesce(excluded.compressed_content, source_objects.compressed_content),
         fetched_at = now()
       returning id`,
      [
        ctx.source.id,
        ctx.run.id,
        stored.objectUri,
        contentHash,
        json.length,
        compressed.length,
        record.schemaHint ?? ctx.source.code,
        stored.compressedContent
      ]
    );
    objectId = objectResult.rows[0].id;
  }

  const rawResult = await client.query(
    `insert into source_raw_index
      (source_id, sync_run_id, object_id, external_key, external_id, source_url,
       source_published_at, source_modified_at, content_hash, record_hash,
       identifier_summary, status, parse_status, normalize_status)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'new','succeeded','pending')
     on conflict (source_id, external_key, record_hash) do update set
       updated_at = now(),
       sync_run_id = excluded.sync_run_id,
       object_id = excluded.object_id
     returning id`,
    [
      ctx.source.id,
      ctx.run.id,
      objectId,
      record.externalKey,
      record.externalId ?? record.externalKey,
      record.sourceUrl ?? null,
      record.publishedAt ?? null,
      record.modifiedAt ?? null,
      contentHash,
      recordHash,
      record.identifiers ?? []
    ]
  );
  return rawResult.rows[0].id;
}

export async function flushWriteBatch(client) {
  if (client.__spool) {
    await closeSpool(client, true);
    await commitSpoolCommitHooks(client);
    return;
  }
  const state = writeBatchStates.get(client);
  if (!state?.active) return;
  await client.query('commit');
  writeBatchStates.delete(client);
}

export async function rollbackWriteBatch(client) {
  if (client.__spool) {
    await closeSpool(client, false);
    await rollbackSpoolCommitHooks(client);
    return;
  }
  const state = writeBatchStates.get(client);
  if (!state?.active) return;
  await client.query('rollback').catch(() => {});
  writeBatchStates.delete(client);
}

async function rotateWriteBatch(client) {
  const batchSize = Math.max(1, Number.parseInt(process.env.FETCHER_DB_BATCH_SIZE ?? '1000', 10) || 1000);
  let state = writeBatchStates.get(client);
  if (!state) {
    await client.query('begin');
    state = { active: true, count: 0 };
    writeBatchStates.set(client, state);
  } else if (state.count >= batchSize) {
    await client.query('commit');
    await client.query('begin');
    state.count = 0;
  }
  state.count += 1;
}

export async function writeArtifact(client, ctx, artifact) {
  const body = Buffer.isBuffer(artifact.body)
    ? artifact.body
    : Buffer.from(String(artifact.body ?? ''), artifact.encoding ?? 'utf8');
  const contentHash = sha256(body);
  if (client.__spool) {
    return {
      objectId: null,
      sha256: contentHash,
      sizeBytes: body.length,
      compressedSizeBytes: 0,
      objectUri: null
    };
  }
  if (getRawObjectStore() === 'none') {
    return {
      objectId: null,
      sha256: contentHash,
      sizeBytes: body.length,
      compressedSizeBytes: 0,
      objectUri: null
    };
  }

  const compressed = await gzip(body);
  const extension = artifact.compressedExtension ?? '.gz';
  const stored = await storeRawObject(client, ctx, {
    compressed,
    contentHash,
    externalKey: artifact.externalKey ?? artifact.filename ?? contentHash,
    suffix: `${contentHash.slice(0, 12)}${extension}`,
    artifact: true
  });

  const result = await client.query(
    `insert into source_objects
       (source_id, sync_run_id, object_uri, content_type, compression, sha256, size_bytes, compressed_size_bytes, schema_hint, retention_class, compressed_content)
     values ($1,$2,$3,$4,'gzip',$5,$6,$7,$8,$9,$10)
     on conflict (source_id, sha256) do update set
       object_uri = excluded.object_uri,
       sync_run_id = excluded.sync_run_id,
       compressed_content = coalesce(excluded.compressed_content, source_objects.compressed_content),
       fetched_at = now()
     returning id`,
    [
      ctx.source.id,
      ctx.run.id,
      stored.objectUri,
      artifact.contentType ?? 'application/octet-stream',
      contentHash,
      body.length,
      compressed.length,
      artifact.schemaHint ?? `${ctx.source.code}-artifact`,
      artifact.retentionClass ?? 'hot',
      stored.compressedContent
    ]
  );

  return {
    objectId: result.rows[0].id,
    sha256: contentHash,
    sizeBytes: body.length,
    compressedSizeBytes: compressed.length,
    objectUri: stored.objectUri
  };
}

export async function ensureSourceObjectStorageSchema(client) {
  if (sourceObjectStorageSchemaEnsured) return;
  const existing = await client.query(
    `select 1
     from information_schema.columns
     where table_schema = 'public'
       and table_name = 'source_objects'
       and column_name = 'compressed_content'
     limit 1`
  );
  if (!existing.rowCount) {
    await client.query(`
      alter table source_objects
        add column compressed_content bytea
    `);
  }
  sourceObjectStorageSchemaEnsured = true;
}

async function storeRawObject(client, ctx, { compressed, contentHash, externalKey, suffix, artifact = false }) {
  await ensureSourceObjectStorageSchema(client);
  const store = getRawObjectStore();
  if (store === 'filesystem' || store === 'dual') {
    const dir = artifact
      ? getRootPath(getEnv('RAW_OBJECT_PATH', './data/raw-objects'), ctx.source.code, 'artifacts', new Date().toISOString().slice(0, 10))
      : getRootPath(getEnv('RAW_OBJECT_PATH', './data/raw-objects'), ctx.source.code, new Date().toISOString().slice(0, 10));
    await fs.mkdir(dir, { recursive: true });
    const safeName = String(externalKey ?? contentHash)
      .replaceAll('/', '_')
      .replaceAll('\\', '_')
      .slice(0, 160);
    const file = path.join(dir, `${safeName}-${suffix}`);
    await fs.writeFile(file, compressed);
    return {
      objectUri: `file://${file}`,
      compressedContent: store === 'dual' ? compressed : null
    };
  }

  return {
    objectUri: `pg://source_objects/${ctx.source.code}/${contentHash}`,
    compressedContent: compressed
  };
}

function getRawObjectStore() {
  const value = getEnv('RAW_OBJECT_STORE', getEnv('RAW_OBJECT_STORAGE', 'pgsql')).toLowerCase();
  if (value === 'postgres') return 'pgsql';
  if (['none', 'pgsql', 'filesystem', 'dual'].includes(value)) return value;
  throw new Error(`Unsupported RAW_OBJECT_STORE: ${value}`);
}

export async function saveCheckpoint(client, sourceId, checkpoint) {
  if (client.__spool) {
    // Commit a checkpoint only after the corresponding spool is atomically
    // promoted to .ready. A mid-run checkpoint plus a lost .partial file
    // would otherwise skip records after restart.
    client.pendingCheckpoint = checkpoint;
    return;
  }
  await client.query(
    'update sources set checkpoint_json = $2, updated_at = now() where id = $1',
    [sourceId, JSON.stringify(checkpoint)]
  );
}

// Some fetchers keep compact local indexes beside their spool state. These
// hooks make the index visible only after the matching .partial was promoted.
export function registerSpoolCommitHook(client, hook) {
  if (!client.__spool) throw new Error('Spool commit hooks require the DuckDB spool backend');
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
  if (client.__spool) {
    const state = await readSpoolState(sourceId);
    return Boolean(state.hasRecords);
  }
  const result = await client.query(
    'select exists(select 1 from source_raw_index where source_id = $1) as has_records',
    [sourceId]
  );
  return Boolean(result.rows[0]?.has_records);
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
  if (client.__spool) {
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
    return;
  }
  const cause = error.cause;
  await client.query(
    `insert into source_task_errors
       (sync_run_id, source_id, stage, external_key, error_code, error_message, error_detail)
     values ($1,$2,$3,$4,$5,$6,$7)`,
    [
      ctx.run?.id ?? null,
      ctx.source?.id ?? null,
      stage,
      externalKey,
      error.code ?? error.name ?? 'ERROR',
      error.message ?? String(error),
      {
        stack: error.stack ?? null,
        cause: cause
          ? {
              name: cause.name ?? null,
              message: cause.message ?? null,
              code: cause.code ?? null,
              errno: cause.errno ?? null,
              syscall: cause.syscall ?? null,
              hostname: cause.hostname ?? null
            }
          : null
      }
    ]
  );
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
  if (!client.__spool) return;
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
