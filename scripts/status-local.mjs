#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config({ quiet: true });

const FAST_LIMIT = 15;

function env(name, fallback = '') {
  return process.env[name] || fallback;
}

function databaseUrl() {
  if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
  const password = env('POSTGRES_PASSWORD', 'vultrack');
  return `postgres://vultrack:${encodeURIComponent(password)}@localhost:5432/vultrack`;
}

function section(title) {
  console.log(`\n== ${title} ==`);
}

function dockerCompose(args) {
  try {
    return execFileSync('docker', ['compose', ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    }).trim();
  } catch (error) {
    const detail = error.stderr?.toString().trim() || error.message;
    return `docker compose ${args.join(' ')} failed: ${detail}`;
  }
}

function printRows(rows, columns) {
  if (!rows.length) {
    console.log('(none)');
    return;
  }
  const widths = columns.map((column) =>
    Math.max(
      column.length,
      ...rows.map((row) => String(row[column] ?? '').length)
    )
  );
  console.log(columns.map((column, index) => column.padEnd(widths[index])).join('  '));
  console.log(widths.map((width) => '-'.repeat(width)).join('  '));
  for (const row of rows) {
    console.log(columns.map((column, index) => formatValue(row[column]).padEnd(widths[index])).join('  '));
  }
}

function formatValue(value) {
  if (value === null || value === undefined) return '';
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

async function query(client, sql, params = []) {
  const result = await client.query(sql, params);
  return result.rows;
}

async function tryDuckDbStatus() {
  const baseUrl = env('API_BASE_URL', 'http://127.0.0.1:5099').replace(/\/$/, '');
  let ready;
  try {
    const response = await fetch(`${baseUrl}/api/v1/system.ready`);
    if (!response.ok) return false;
    ready = await response.json();
  } catch {
    return false;
  }
  if (ready?.data?.storageBackend !== 'duckdb') return false;

  const login = await fetch(`${baseUrl}/api/v1/auth.login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      username: env('VULTRACK_ADMIN_USERNAME', 'admin'),
      password: env('VULTRACK_ADMIN_PASSWORD', 'change-me')
    })
  });
  const cookie = login.headers.get('set-cookie')?.split(';', 1)[0];
  if (!login.ok || !cookie) throw new Error('DuckDB API is ready, but admin authentication failed.');

  const [statusResponse, sourcesResponse] = await Promise.all([
    fetch(`${baseUrl}/api/v1/system.status?fast=true`, { headers: { cookie } }),
    fetch(`${baseUrl}/api/v1/admin.source.list`, { headers: { cookie } })
  ]);
  const status = await statusResponse.json();
  const sources = await sourcesResponse.json();
  if (!statusResponse.ok || !status.ok) throw new Error(status?.error?.message ?? 'DuckDB status request failed.');

  section('DuckDB Storage');
  printRows([status.data.database], Object.keys(status.data.database));
  section('Spool Queue');
  printRows([status.data.queue], Object.keys(status.data.queue));
  section('Scheduler');
  printRows([{
    enabled: status.data.scheduler.enabled,
    sources: (status.data.scheduler.sources ?? []).join(',')
  }], ['enabled', 'sources']);
  section('Latest Source Runs');
  const sourceRows = (sources?.data ?? []).map((source) => ({
    code: source.code,
    status: source.latestRun?.status ?? '',
    finishedAt: source.latestRun?.finished_at ?? '',
    fetched: source.latestRun?.fetched_count ?? '',
    errors: source.latestRun?.error_count ?? ''
  }));
  printRows(sourceRows, ['code', 'status', 'finishedAt', 'fetched', 'errors']);
  return true;
}

async function main() {
  section('Compose');
  console.log(dockerCompose(['ps', '--format', 'table {{.Name}}\t{{.Service}}\t{{.State}}\t{{.Status}}']));

  if (await tryDuckDbStatus()) return;

  const client = new pg.Client({ connectionString: databaseUrl() });
  await client.connect();
  try {
    section('Storage Mode');
    const database = await query(client, `
      select current_database() as database,
             pg_size_pretty(pg_database_size(current_database())) as size
    `);
    printRows(database, ['database', 'size']);

    const storage = await query(client, `
      select greatest(reltuples::bigint, 0) as estimated_objects,
             'postgres-bytea'::text as payload_mode
      from pg_class
      where oid = 'source_objects'::regclass
    `);
    printRows(storage, ['estimated_objects', 'payload_mode']);

    section('Compacted Staging Payloads');
    const compacted = await query(client, `
      select table_name, count(*) as rows, max(compacted_at) as latest
      from staging_payload_compactions
      group by table_name
      order by rows desc, table_name
    `);
    printRows(compacted, ['table_name', 'rows', 'latest']);

    section('Vulnerability State');
    const counts = await query(client, `
      select relname as table_name, greatest(reltuples::bigint, 0) as estimated_rows
      from pg_class
      where relname in (
        'vulnerabilities',
        'source_raw_index',
        'source_objects',
        'vulnerability_affected_facts',
        'vulnerability_affected_components'
      )
      order by relname
    `);
    printRows(counts, ['table_name', 'estimated_rows']);

    section('Pending Normalization');
    const pending = await query(client, `
      select s.code, r.normalize_status, count(*) as rows, max(r.updated_at) as latest
      from source_raw_index r
      join sources s on s.id = r.source_id
      where r.normalize_status in ('pending', 'failed')
      group by s.code, r.normalize_status
      order by rows desc, s.code
      limit $1
    `, [FAST_LIMIT]);
    printRows(pending, ['code', 'normalize_status', 'rows', 'latest']);

    section('Latest Source Runs');
    const runs = await query(client, `
      select s.code, r.status, r.started_at, r.finished_at,
             r.fetched_count, r.parsed_count, r.normalized_count, r.error_count,
             left(coalesce(r.log_summary, ''), 96) as summary
      from source_sync_runs r
      join sources s on s.id = r.source_id
      order by r.started_at desc
      limit $1
    `, [FAST_LIMIT]);
    printRows(runs, ['code', 'status', 'started_at', 'finished_at', 'fetched_count', 'parsed_count', 'normalized_count', 'error_count', 'summary']);

    section('Recent Fetcher Errors');
    const errors = await query(client, `
      select coalesce(s.code, '(unknown)') as code,
             e.stage,
             e.error_code,
             count(*) as errors,
             max(e.created_at) as latest,
             left(max(e.error_message), 160) as sample
      from source_task_errors e
      left join sources s on s.id = e.source_id
      where e.created_at > now() - interval '7 days'
      group by s.code, e.stage, e.error_code
      order by latest desc
      limit $1
    `, [FAST_LIMIT]);
    printRows(errors, ['code', 'stage', 'error_code', 'errors', 'latest', 'sample']);

    section('Largest PostgreSQL Tables');
    const sizes = await query(client, `
      select relname as table_name,
             pg_size_pretty(pg_total_relation_size(relid)) as total,
             pg_size_pretty(pg_relation_size(relid)) as heap,
             pg_size_pretty(pg_indexes_size(relid)) as indexes,
             pg_size_pretty(pg_total_relation_size(relid) - pg_relation_size(relid) - pg_indexes_size(relid)) as toast,
             n_live_tup,
             n_dead_tup
      from pg_stat_user_tables
      order by pg_total_relation_size(relid) desc
      limit $1
    `, [FAST_LIMIT]);
    printRows(sizes, ['table_name', 'total', 'heap', 'indexes', 'toast', 'n_live_tup', 'n_dead_tup']);

    section('Snapshot Queue');
    const snapshot = await query(client, `
      select count(*) as queued, min(queued_at) as oldest, max(queued_at) as newest
      from vulnerability_detail_snapshot_queue
    `);
    printRows(snapshot, ['queued', 'oldest', 'newest']);
  } finally {
    await client.end();
  }
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
