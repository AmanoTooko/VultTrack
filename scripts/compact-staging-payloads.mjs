#!/usr/bin/env node
import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config({ quiet: true });

const TABLES = [
  'stg_osv_vulnerabilities',
  'stg_ubuntu_osv',
  'stg_nvd_cves',
  'stg_cve_list_records',
  'stg_android_osv',
  'stg_ecosystem_advisories',
  'stg_debian_security_tracker',
  'stg_ghsa_advisories',
  'stg_npm_advisories',
  'stg_pypi_advisories',
  'stg_external_advisories',
  'stg_exploit_pocs',
  'stg_alpine_secdb'
];

const args = new Set(process.argv.slice(2));
const selectedTables = valueArg('--tables')
  ?.split(',')
  .map((value) => value.trim())
  .filter(Boolean) ?? TABLES;
const limit = Number(valueArg('--limit') ?? 50000);
const dryRun = args.has('--dry-run');
const vacuumFull = args.has('--vacuum-full');
const databaseUrl = process.env.DATABASE_URL ?? `postgres://vultrack:${encodeURIComponent(process.env.POSTGRES_PASSWORD ?? 'vultrack')}@localhost:5432/vultrack`;

function valueArg(name) {
  const prefix = `${name}=`;
  const item = process.argv.slice(2).find((arg) => arg.startsWith(prefix));
  return item ? item.slice(prefix.length) : null;
}

function quoteIdent(value) {
  if (!/^[a-z_][a-z0-9_]*$/i.test(value)) throw new Error(`Unsafe identifier: ${value}`);
  return `"${value.replaceAll('"', '""')}"`;
}

const invalid = selectedTables.filter((table) => !TABLES.includes(table));
if (invalid.length) throw new Error(`Unsupported staging table(s): ${invalid.join(', ')}`);
if (!Number.isSafeInteger(limit) || limit <= 0) throw new Error('--limit must be a positive integer');

const client = new pg.Client({ connectionString: databaseUrl });
await client.connect();

try {
  await ensureCompactionSchema();
  await prepareCompressedObjectIds();
  const results = [];
  for (const table of selectedTables) {
    const before = await tableSize(table);
    const candidates = await prepareCandidates(table);
    let compacted = 0;

    if (!dryRun) {
      for (;;) {
        const changed = await compactBatch(table, limit);
        compacted += changed;
        if (changed < limit) break;
      }
      if (vacuumFull && compacted > 0) {
        await client.query(`vacuum full analyze ${quoteIdent(table)}`);
      } else if (compacted > 0) {
        await client.query(`vacuum analyze ${quoteIdent(table)}`);
      }
    }

    const after = await tableSize(table);
    results.push({ table, candidates, compacted, before, after });
  }

  console.log(JSON.stringify({
    dryRun,
    vacuumFull,
    limit,
    generatedAt: new Date().toISOString(),
    results
  }, null, 2));
} finally {
  await client.end();
}

async function prepareCandidates(table) {
  await client.query('drop table if exists compact_staging_payload_candidates');
  await client.query('create temp table compact_staging_payload_candidates (raw_index_id uuid primary key)');
  const sql = `
    insert into compact_staging_payload_candidates (raw_index_id)
    select t.raw_index_id
    from ${quoteIdent(table)} t
    join source_raw_index r on r.id = t.raw_index_id
    join compact_source_object_ids o on o.id = r.object_id
    left join staging_payload_compactions c
      on c.table_name = $1 and c.raw_index_id = t.raw_index_id
    where r.normalize_status in ('succeeded', 'superseded')
      and t.payload <> '{}'::jsonb
      and c.raw_index_id is null
    on conflict do nothing
  `;
  const result = await client.query(sql, [table]);
  return result.rowCount;
}

async function prepareCompressedObjectIds() {
  await client.query('drop table if exists compact_source_object_ids');
  await client.query('create temp table compact_source_object_ids (id uuid primary key)');
  await client.query(`
    insert into compact_source_object_ids (id)
    select id
    from source_objects
    where compressed_content is not null
  `);
}

async function compactBatch(table, batchLimit) {
  const sql = `
    with batch as (
      select raw_index_id
      from compact_staging_payload_candidates
      limit $1
    ),
    updated as (
      update ${quoteIdent(table)} t
         set payload = '{}'::jsonb
        from batch
       where t.raw_index_id = batch.raw_index_id
      returning t.raw_index_id
    ),
    marked as (
      insert into staging_payload_compactions (table_name, raw_index_id)
      select $2, raw_index_id
      from updated
      on conflict do nothing
      returning raw_index_id
    )
    delete from compact_staging_payload_candidates c
    using marked u
    where c.raw_index_id = u.raw_index_id
  `;
  const result = await client.query(sql, [batchLimit, table]);
  return result.rowCount;
}

async function ensureCompactionSchema() {
  await client.query(`
    create table if not exists staging_payload_compactions (
      table_name text not null,
      raw_index_id uuid not null,
      compacted_at timestamptz not null default now(),
      primary key (table_name, raw_index_id)
    )
  `);
}

async function tableSize(table) {
  const result = await client.query(`
    select pg_total_relation_size($1::regclass)::bigint as total_bytes,
           pg_relation_size($1::regclass)::bigint as heap_bytes,
           pg_indexes_size($1::regclass)::bigint as index_bytes,
           (pg_total_relation_size($1::regclass) - pg_relation_size($1::regclass) - pg_indexes_size($1::regclass))::bigint as toast_bytes
  `, [table]);
  return result.rows[0];
}
