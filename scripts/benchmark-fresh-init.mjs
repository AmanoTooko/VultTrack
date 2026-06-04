#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import pg from 'pg';

const { Client } = pg;

const args = new Set(process.argv.slice(2));
const reset = args.has('--reset') || truthy(process.env.BENCHMARK_RESET_STACK);
const smoke = args.has('--smoke') || truthy(process.env.BENCHMARK_SMOKE);
const skipFetch = args.has('--skip-fetch') || truthy(process.env.BENCHMARK_SKIP_FETCH);
const skipNormalize = args.has('--skip-normalize') || truthy(process.env.BENCHMARK_SKIP_NORMALIZE);
const skipSnapshot = args.has('--skip-snapshot') || truthy(process.env.BENCHMARK_SKIP_SNAPSHOT);
const skipApiCheck = args.has('--skip-api-check') || truthy(process.env.BENCHMARK_SKIP_API_CHECK);
const apiBaseUrl = process.env.API_BASE_URL ?? 'http://127.0.0.1:5199';
const databaseUrl = process.env.DATABASE_URL ?? 'postgres://vultrack:vultrack-benchmark@127.0.0.1:55432/vultrack';
const detailSnapshotDir = path.resolve(process.env.VULTRACK_DETAIL_SNAPSHOT_DIR ?? 'data/benchmark-vulnerability-details');
const reportDir = path.resolve(process.env.BENCHMARK_REPORT_DIR ?? 'data/benchmark-reports');
const reportPath = path.join(reportDir, `fresh-init-${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
const fetcherMaxRecords = process.env.FETCHER_MAX_RECORDS ?? (smoke ? '2' : '');
const fetchSources = process.env.BENCHMARK_FETCH_SOURCES ?? process.env.FETCHER_SOURCES ?? '';
const normalizeBatchSize = process.env.LIMIT_PER_SOURCE ?? (smoke ? '20' : '5000');
const normalizeParallelism = process.env.NORMALIZE_PARALLELISM ?? (smoke ? '2' : '4');
const normalizeMaxCycles = process.env.MAX_CYCLES ?? (smoke ? '3' : '0');
const snapshotLimit = process.env.BENCHMARK_SNAPSHOT_LIMIT ?? (smoke ? '100' : '0');

const report = {
  generatedAt: new Date().toISOString(),
  apiBaseUrl,
  databaseUrl: redactedDatabaseUrl(databaseUrl),
  mode: { reset, smoke, skipFetch, skipNormalize, skipSnapshot, skipApiCheck },
  settings: {
    fetcherMaxRecords,
    fetchSources: fetchSources || null,
    normalizeBatchSize,
    normalizeParallelism,
    normalizeMaxCycles,
    snapshotLimit,
    detailSnapshotDir
  },
  phases: [],
  snapshots: {}
};

await mkdir(reportDir, { recursive: true });

try {
  await collectSnapshot('before');

  if (reset) {
    await phase('reset benchmark stack', 'bash', ['scripts/reset-benchmark-stack.sh']);
    await collectSnapshot('afterReset');
  } else {
    await waitForReady(apiBaseUrl, 90_000);
  }

  if (!skipFetch) {
    const fetchArgs = ['plugins/fetchers/run-all.mjs'];
    if (fetchSources) {
      fetchArgs.push('--sources', fetchSources);
    }
    await phase('fetch all sources', process.execPath, fetchArgs, {
      FETCHER_INCLUDE_INIT: '1',
      FETCHER_MAX_RECORDS: fetcherMaxRecords
    });
    await collectSnapshot('afterFetch');
  }

  if (!skipNormalize) {
    await phase('normalize pending sources', process.execPath, ['scripts/run-parallel-normalization.mjs'], {
      API_BASE_URL: apiBaseUrl,
      DATABASE_URL: databaseUrl,
      LIMIT_PER_SOURCE: normalizeBatchSize,
      NORMALIZE_PARALLELISM: normalizeParallelism,
      MAX_CYCLES: normalizeMaxCycles,
      REQUEST_TIMEOUT_MS: process.env.REQUEST_TIMEOUT_MS ?? '0'
    });
    await collectSnapshot('afterNormalize');
  }

  if (!skipSnapshot) {
    const snapshotArgs = ['scripts/build-detail-snapshot.mjs'];
    if (Number.parseInt(snapshotLimit, 10) > 0) {
      snapshotArgs.push('--limit', snapshotLimit);
    }
    await phase('build detail snapshots', process.execPath, snapshotArgs, {
      API_BASE_URL: apiBaseUrl,
      DATABASE_URL: databaseUrl,
      VULTRACK_DETAIL_SNAPSHOT_DIR: detailSnapshotDir,
      DETAIL_SNAPSHOT_CONCURRENCY: process.env.DETAIL_SNAPSHOT_CONCURRENCY ?? (smoke ? '2' : '8')
    });
    await collectSnapshot('afterSnapshot');
  }

  if (!skipApiCheck) {
    await phase('api performance check', process.execPath, ['scripts/api-performance-check.mjs'], {
      API_BASE_URL: apiBaseUrl,
      INCLUDE_MUTATING: smoke ? '0' : (process.env.INCLUDE_MUTATING ?? '0')
    });
  }

  await writeReport('succeeded');
} catch (error) {
  report.error = error instanceof Error ? error.message : String(error);
  await writeReport('failed');
  process.exitCode = 1;
}

async function phase(name, command, args, extraEnv = {}) {
  const startedAt = new Date().toISOString();
  const started = performance.now();
  console.log(JSON.stringify({ event: 'phase_start', name, command, args, startedAt }));
  const result = await run(command, args, extraEnv);
  const elapsedMs = Math.round(performance.now() - started);
  const item = {
    name,
    command,
    args,
    startedAt,
    finishedAt: new Date().toISOString(),
    elapsedMs,
    exitCode: result.exitCode
  };
  report.phases.push(item);
  console.log(JSON.stringify({ event: 'phase_finish', ...item }));
  if (result.exitCode !== 0) {
    throw new Error(`${name} failed with exit code ${result.exitCode}`);
  }
}

function run(command, args, extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: 'inherit',
      env: {
        ...process.env,
        API_BASE_URL: apiBaseUrl,
        DATABASE_URL: databaseUrl,
        ...Object.fromEntries(Object.entries(extraEnv).filter(([, value]) => value !== undefined))
      }
    });
    child.on('error', reject);
    child.on('close', (exitCode) => resolve({ exitCode }));
  });
}

function runCapture(command, args, extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ['ignore', 'pipe', 'inherit'],
      env: {
        ...process.env,
        API_BASE_URL: apiBaseUrl,
        DATABASE_URL: databaseUrl,
        ...Object.fromEntries(Object.entries(extraEnv).filter(([, value]) => value !== undefined))
      }
    });
    const chunks = [];
    child.stdout.on('data', chunk => chunks.push(chunk));
    child.on('error', reject);
    child.on('close', (exitCode) => resolve({
      exitCode,
      stdout: Buffer.concat(chunks).toString('utf8')
    }));
  });
}

async function collectSnapshot(name) {
  const started = performance.now();
  const db = await databaseSummary().catch(error => ({ error: error.message }));
  const storage = await storageAudit().catch(error => ({ error: error.message }));
  report.snapshots[name] = {
    collectedAt: new Date().toISOString(),
    elapsedMs: Math.round(performance.now() - started),
    db,
    storage
  };
  console.log(JSON.stringify({ event: 'snapshot', name, db: summarizeDb(db), storage: summarizeStorage(storage) }));
}

async function databaseSummary() {
  const client = new Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    const totals = await client.query(`
      select
        (select count(*)::bigint from sources) sources,
        (select count(*)::bigint from source_raw_index) raw_records,
        (select count(*)::bigint from source_raw_index where normalize_status in ('pending','failed')) raw_pending,
        (select count(*)::bigint from vulnerabilities) vulnerabilities,
        (select count(*)::bigint from vulnerability_affected_facts) affected_facts,
        (select count(*)::bigint from vulnerability_affected_components) affected_components,
        (select count(*)::bigint from vulnerability_exploits) exploits,
        (select count(*)::bigint from vulnerability_detail_snapshot_queue) detail_snapshot_queue,
        pg_database_size(current_database())::bigint database_bytes
    `);
    const pending = await client.query(`
      select s.code, count(*)::bigint pending
      from source_raw_index r
      join sources s on s.id = r.source_id
      where r.normalize_status in ('pending', 'failed')
      group by s.code
      having count(*) > 0
      order by count(*) desc, s.code
    `);
    return {
      totals: totals.rows[0],
      pending: pending.rows
    };
  } finally {
    await client.end();
  }
}

async function storageAudit() {
  const result = await runCapture(process.execPath, ['scripts/audit-database-storage.mjs'], {
    DATABASE_URL: databaseUrl,
    VULTRACK_DETAIL_SNAPSHOT_DIR: detailSnapshotDir
  });
  if (result.exitCode !== 0) throw new Error(`storage audit failed with exit code ${result.exitCode}`);
  return JSON.parse(result.stdout);
}

async function waitForReady(baseUrl, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/api/v1/system.ready`);
      if (response.ok) return;
    } catch {
      // Keep waiting while the benchmark API starts.
    }
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  throw new Error(`API did not become ready before ${timeoutMs}ms: ${baseUrl}`);
}

async function writeReport(status) {
  report.status = status;
  report.finishedAt = new Date().toISOString();
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify({ event: 'report_written', status, reportPath }));
}

function summarizeDb(db) {
  if (db.error) return db;
  return {
    rawRecords: db.totals?.raw_records,
    rawPending: db.totals?.raw_pending,
    vulnerabilities: db.totals?.vulnerabilities,
    affectedFacts: db.totals?.affected_facts,
    affectedComponents: db.totals?.affected_components,
    exploits: db.totals?.exploits,
    queue: db.totals?.detail_snapshot_queue,
    databaseBytes: db.totals?.database_bytes,
    pendingSources: db.pending?.length ?? 0
  };
}

function summarizeStorage(storage) {
  if (storage.error) return storage;
  return {
    database: storage.database,
    rawPendingSources: storage.rawPendingBySource?.length ?? 0,
    detailSnapshotQueue: storage.detailSnapshotQueue,
    detailSnapshots: storage.detailSnapshots && {
      files: storage.detailSnapshots.files,
      bytes: storage.detailSnapshots.bytes,
      gzipShards: storage.detailSnapshots.gzipShards,
      gzipShardBytes: storage.detailSnapshots.gzipShardBytes
    }
  };
}

function redactedDatabaseUrl(value) {
  try {
    const url = new URL(value);
    if (url.password) url.password = '***';
    return url.toString();
  } catch {
    return '<unparsed>';
  }
}

function truthy(value) {
  return value === '1' || String(value).toLowerCase() === 'true';
}
