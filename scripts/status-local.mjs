#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import dotenv from 'dotenv';

dotenv.config({ quiet: true });

function env(name, fallback = '') {
  return process.env[name] || fallback;
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

  console.error('DuckDB API is not ready; start the stack with scripts/start-local.sh first.');
  process.exit(1);
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
