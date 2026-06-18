#!/usr/bin/env node
import fs from 'node:fs/promises';
import { gunzip } from 'node:zlib';
import { promisify } from 'node:util';
import pg from 'pg';
import { sha256 } from '../plugins/fetchers/lib/hash.mjs';

const inflate = promisify(gunzip);
const { Client } = pg;

const databaseUrl = process.env.DATABASE_URL ?? 'postgres://vultrack:vultrack@127.0.0.1:5432/vultrack';
const limit = positiveInt(argValue('--limit') ?? process.env.RAW_OBJECT_MIGRATION_LIMIT, 1000);
const deleteConcurrency = positiveInt(argValue('--delete-concurrency') ?? process.env.RAW_OBJECT_DELETE_CONCURRENCY, 32);
const deleteFiles = hasArg('--delete-files');
const markMissing = !hasArg('--keep-missing-file-uri');
const verifyHash = hasArg('--verify-hash');
const pruneUnreferenced = hasArg('--prune-unreferenced');
const backfill = hasArg('--backfill') || !pruneUnreferenced;

const client = new Client({ connectionString: databaseUrl });
await client.connect();

try {
  await ensureSchema();
  if (pruneUnreferenced) {
    await pruneUnreferencedObjects();
  }
  if (backfill) {
    await backfillObjects();
  }
} finally {
  await client.end();
}

async function ensureSchema() {
  await client.query(`
    alter table source_objects
      add column if not exists compressed_content bytea
  `);
}

async function backfillObjects() {
  const rows = await client.query(
    `
      select id, object_uri, compression, sha256, compressed_size_bytes
      from source_objects
      where compressed_content is null
        and object_uri like 'file://%'
      order by id
      limit $1
    `,
    [limit]
  );

  let migrated = 0;
  let missing = 0;
  let invalid = 0;
  let deleted = 0;
  const missingIds = [];

  for (const row of rows.rows) {
    const file = fileFromUri(row.object_uri);
    let compressed;
    try {
      compressed = await fs.readFile(file);
    } catch (error) {
      if (error.code === 'ENOENT') {
        if (markMissing) {
          missingIds.push(row.id);
        }
        missing++;
        continue;
      }
      throw error;
    }

    if (verifyHash) {
      const body = row.compression === 'gzip' ? await inflate(compressed) : compressed;
      if (sha256(body) !== row.sha256) {
        invalid++;
        continue;
      }
    }

    await client.query(
      `
        update source_objects
        set compressed_content = $2,
            compressed_size_bytes = $3,
            object_uri = 'pg://source_objects/' || id::text
        where id = $1
      `,
      [row.id, compressed, compressed.length]
    );
    migrated++;

    if (deleteFiles) {
      await fs.rm(file, { force: true });
      deleted++;
    }
  }

  if (missingIds.length > 0) {
    await client.query(
      "update source_objects set object_uri = 'missing://source_objects/' || id::text where id = any($1::uuid[])",
      [missingIds]
    );
  }

  console.log(JSON.stringify({
    mode: 'backfill',
    scanned: rows.rowCount,
    migrated,
    missing,
    invalid,
    deletedFiles: deleted,
    remainingBatchHint: rows.rowCount === limit
  }, null, 2));
}

async function pruneUnreferencedObjects() {
  const rows = await client.query(
    `
      select o.id, o.object_uri
      from source_objects o
      where not exists (select 1 from source_raw_index r where r.object_id = o.id)
        and not exists (select 1 from stg_exploit_pocs p where p.artifact_object_id = o.id)
        and not exists (select 1 from vulnerability_exploits e where e.artifact_object_id = o.id)
      order by o.id
      limit $1
    `,
    [limit]
  );

  let deletedFiles = 0;
  if (deleteFiles) {
    deletedFiles = await deleteFileUris(rows.rows.map((row) => row.object_uri));
  }

  if (rows.rowCount > 0) {
    await client.query(
      'delete from source_objects where id = any($1::uuid[])',
      [rows.rows.map((row) => row.id)]
    );
  }

  console.log(JSON.stringify({
    mode: 'prune-unreferenced',
    pruned: rows.rowCount,
    deletedFiles,
    remainingBatchHint: rows.rowCount === limit
  }, null, 2));
}

async function deleteFileUris(uris) {
  let deleted = 0;
  let index = 0;
  const workers = Array.from({ length: Math.min(deleteConcurrency, Math.max(1, uris.length)) }, async () => {
    while (index < uris.length) {
      const uri = uris[index++];
      if (!uri?.startsWith('file://')) continue;
      await fs.rm(fileFromUri(uri), { force: true });
      deleted++;
    }
  });
  await Promise.all(workers);
  return deleted;
}

function fileFromUri(uri) {
  if (!uri?.startsWith('file://')) throw new Error(`Unsupported object_uri: ${uri}`);
  return decodeURIComponent(uri.slice('file://'.length));
}

function hasArg(name) {
  return process.argv.includes(name);
}

function argValue(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(value ?? '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}
