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
    `insert into source_sync_runs (source_id, status, trigger)
     values ($1, 'running', $2)
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
