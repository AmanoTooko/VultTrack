#!/usr/bin/env node
import pg from 'pg';

const { Client } = pg;
const databaseUrl = process.env.DATABASE_URL ?? 'postgres://vultrack:vultrack@127.0.0.1:5432/vultrack';
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
  const candidateUnusedIndexes = indexes.rows.filter(index =>
    Number(index.scans) === 0 &&
    Number(index.size_bytes) >= 50 * 1024 * 1024 &&
    !index.index_name.endsWith('_pkey')
  );

  console.log(JSON.stringify({
    generatedAt: new Date().toISOString(),
    database: database.rows[0],
    residualTables: residualTables.rows.map(row => row.table_name),
    largestTables: tables.rows,
    candidateUnusedIndexes,
    largestIndexes: indexes.rows
  }, null, 2));
} finally {
  await client.end();
}
