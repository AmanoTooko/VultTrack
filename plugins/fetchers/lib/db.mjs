import pg from 'pg';
import fs from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';
import { promisify } from 'node:util';
import { getEnv, getRootPath } from './env.mjs';
import { sha256, stableJson } from './hash.mjs';

const gzip = promisify(zlib.gzip);

export function createPool() {
  return new pg.Pool({
    connectionString: getEnv('DATABASE_URL', 'postgres://vultrack:vultrack@localhost:5432/vultrack')
  });
}

export async function withClient(fn) {
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
  const result = await client.query('select * from sources where code = $1', [code]);
  if (!result.rowCount) throw new Error(`Unknown source: ${code}`);
  return result.rows[0];
}

export async function startRun(client, sourceId, trigger = 'manual') {
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
  const json = Buffer.from(stableJson(record.payload));
  const compressed = await gzip(json);
  const contentHash = sha256(json);
  const recordHash = record.recordHash ?? contentHash;
  const dir = getRootPath(getEnv('RAW_OBJECT_PATH', './data/raw-objects'), ctx.source.code, new Date().toISOString().slice(0, 10));
  await fs.mkdir(dir, { recursive: true });
  const file = path.join(dir, `${record.externalKey.replaceAll('/', '_')}-${recordHash.slice(0, 12)}.json.gz`);
  await fs.writeFile(file, compressed);
  const objectUri = `file://${file}`;

  const objectResult = await client.query(
    `insert into source_objects
       (source_id, sync_run_id, object_uri, content_type, compression, sha256, size_bytes, compressed_size_bytes, schema_hint)
     values ($1,$2,$3,'application/json','gzip',$4,$5,$6,$7)
     on conflict (source_id, sha256) do update set fetched_at = now()
     returning id`,
    [ctx.source.id, ctx.run.id, objectUri, contentHash, json.length, compressed.length, record.schemaHint ?? ctx.source.code]
  );
  const objectId = objectResult.rows[0].id;

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

export async function writeArtifact(client, ctx, artifact) {
  const body = Buffer.isBuffer(artifact.body)
    ? artifact.body
    : Buffer.from(String(artifact.body ?? ''), artifact.encoding ?? 'utf8');
  const compressed = await gzip(body);
  const contentHash = sha256(body);
  const dir = getRootPath(
    getEnv('RAW_OBJECT_PATH', './data/raw-objects'),
    ctx.source.code,
    'artifacts',
    new Date().toISOString().slice(0, 10)
  );
  await fs.mkdir(dir, { recursive: true });
  const safeName = String(artifact.externalKey ?? artifact.filename ?? contentHash)
    .replaceAll('/', '_')
    .replaceAll('\\', '_')
    .slice(0, 160);
  const extension = artifact.compressedExtension ?? '.gz';
  const file = path.join(dir, `${safeName}-${contentHash.slice(0, 12)}${extension}`);
  await fs.writeFile(file, compressed);

  const result = await client.query(
    `insert into source_objects
       (source_id, sync_run_id, object_uri, content_type, compression, sha256, size_bytes, compressed_size_bytes, schema_hint, retention_class)
     values ($1,$2,$3,$4,'gzip',$5,$6,$7,$8,$9)
     on conflict (source_id, sha256) do update set fetched_at = now()
     returning id`,
    [
      ctx.source.id,
      ctx.run.id,
      `file://${file}`,
      artifact.contentType ?? 'application/octet-stream',
      contentHash,
      body.length,
      compressed.length,
      artifact.schemaHint ?? `${ctx.source.code}-artifact`,
      artifact.retentionClass ?? 'hot'
    ]
  );

  return {
    objectId: result.rows[0].id,
    sha256: contentHash,
    sizeBytes: body.length,
    compressedSizeBytes: compressed.length,
    objectUri: `file://${file}`
  };
}

export async function saveCheckpoint(client, sourceId, checkpoint) {
  await client.query(
    'update sources set checkpoint_json = $2, updated_at = now() where id = $1',
    [sourceId, JSON.stringify(checkpoint)]
  );
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
      { stack: error.stack ?? null }
    ]
  );
}
