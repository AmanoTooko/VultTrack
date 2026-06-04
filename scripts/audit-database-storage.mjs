#!/usr/bin/env node
import { readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import pg from 'pg';

const { Client } = pg;
const databaseUrl = process.env.DATABASE_URL ?? 'postgres://vultrack:vultrack@127.0.0.1:5432/vultrack';
const detailSnapshotDir = path.resolve(process.env.VULTRACK_DETAIL_SNAPSHOT_DIR ?? 'data/vulnerability-details');
const client = new Client({ connectionString: databaseUrl });
await client.connect();

try {
  const database = await client.query(`
    select current_database() name,
           pg_database_size(current_database())::bigint size_bytes,
           pg_size_pretty(pg_database_size(current_database())) size
  `);
  const tables = await client.query(`
    select s.relname table_name,
           pg_total_relation_size(s.relid)::bigint total_bytes,
           pg_size_pretty(pg_total_relation_size(s.relid)) total_size,
           pg_size_pretty(pg_relation_size(s.relid)) heap_size,
           pg_size_pretty(pg_indexes_size(s.relid)) index_size,
           s.n_live_tup::bigint live_rows,
           s.n_dead_tup::bigint dead_rows,
           s.seq_scan::bigint,
           s.idx_scan::bigint
    from pg_stat_user_tables s
    order by pg_total_relation_size(s.relid) desc
    limit 40
  `);
  const indexes = await client.query(`
    select i.relname table_name,
           x.relname index_name,
           pg_relation_size(x.oid)::bigint size_bytes,
           pg_size_pretty(pg_relation_size(x.oid)) size,
           coalesce(s.idx_scan, 0)::bigint scans,
           pg_get_indexdef(x.oid) definition
    from pg_class x
    join pg_index d on d.indexrelid = x.oid
    join pg_class i on i.oid = d.indrelid
    left join pg_stat_user_indexes s on s.indexrelid = x.oid
    where i.relnamespace = 'public'::regnamespace
    order by pg_relation_size(x.oid) desc
    limit 80
  `);
  const residualTables = await client.query(`
    select table_name
    from information_schema.tables
    where table_schema = 'public' and table_name like '%\\_new' escape '\\'
    order by table_name
  `);
  const missingForeignKeyIndexes = await client.query(`
    select c.conrelid::regclass::text table_name,
           c.conname constraint_name,
           c.confrelid::regclass::text references_table,
           pg_get_constraintdef(c.oid) definition
    from pg_constraint c
    where c.contype = 'f'
      and not exists (
        select 1
        from pg_index i
        where i.indrelid = c.conrelid
          and i.indisvalid
          and (i.indkey::smallint[])[0:cardinality(c.conkey) - 1] @> c.conkey
      )
    order by c.conrelid::regclass::text, c.conname
  `);
  const rawStatus = await client.query(`
    select s.code,
           r.normalize_status,
           count(*)::bigint records,
           pg_size_pretty(sum(pg_column_size(r.*))::bigint) approx_raw_index_size
    from source_raw_index r
    join sources s on s.id = r.source_id
    group by s.code, r.normalize_status
    order by s.code, r.normalize_status
  `);
  const rawPendingBySource = await client.query(`
    select s.code,
           count(*)::bigint pending
    from source_raw_index r
    join sources s on s.id = r.source_id
    where r.normalize_status in ('pending', 'failed')
    group by s.code
    having count(*) > 0
    order by count(*) desc, s.code
  `);
  const detailQueue = await client.query(`
    select count(*)::bigint queued,
           min(queued_at) oldest_queued_at,
           max(queued_at) newest_queued_at
    from vulnerability_detail_snapshot_queue
  `);
  const candidateUnusedIndexes = indexes.rows.filter(index =>
    Number(index.scans) === 0 &&
    Number(index.size_bytes) >= 50 * 1024 * 1024 &&
    !index.index_name.endsWith('_pkey')
  );
  const detailSnapshots = await directorySummary(detailSnapshotDir);

  console.log(JSON.stringify({
    generatedAt: new Date().toISOString(),
    database: database.rows[0],
    rawPendingBySource: rawPendingBySource.rows,
    rawStatus: rawStatus.rows,
    detailSnapshotQueue: detailQueue.rows[0],
    detailSnapshots,
    residualTables: residualTables.rows.map(row => row.table_name),
    missingForeignKeyIndexes: missingForeignKeyIndexes.rows,
    largestTables: tables.rows,
    candidateUnusedIndexes,
    largestIndexes: indexes.rows
  }, null, 2));
} finally {
  await client.end();
}

async function directorySummary(root) {
  try {
    const entries = await walk(root);
    const gzipShards = entries.filter(entry => entry.path.endsWith('.json.gz'));
    return {
      root,
      exists: true,
      files: entries.length,
      bytes: entries.reduce((sum, entry) => sum + entry.bytes, 0),
      gzipShards: gzipShards.length,
      gzipShardBytes: gzipShards.reduce((sum, entry) => sum + entry.bytes, 0),
      largestFiles: entries
        .sort((a, b) => b.bytes - a.bytes)
        .slice(0, 20)
    };
  } catch (error) {
    if (error.code === 'ENOENT') {
      return { root, exists: false, files: 0, bytes: 0, gzipShards: 0, gzipShardBytes: 0, largestFiles: [] };
    }
    throw error;
  }
}

async function walk(root) {
  const entries = [];
  const children = await readdir(root, { withFileTypes: true });
  for (const child of children) {
    const fullPath = path.join(root, child.name);
    if (child.isDirectory()) {
      entries.push(...await walk(fullPath));
      continue;
    }

    if (!child.isFile()) continue;
    const info = await stat(fullPath);
    entries.push({
      path: path.relative(root, fullPath),
      bytes: info.size
    });
  }
  return entries;
}
