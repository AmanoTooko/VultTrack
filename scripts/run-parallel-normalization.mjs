import http from 'node:http';
import https from 'node:https';
import pg from 'pg';
import { getAdminCookie } from './lib/admin-auth.mjs';

const { Client } = pg;
const apiBaseUrl = process.env.API_BASE_URL ?? 'http://localhost:5099';
const databaseUrl = process.env.DATABASE_URL ?? 'postgres://vultrack:vultrack@localhost:5432/vultrack';
const batchSize = Number.parseInt(process.env.LIMIT_PER_SOURCE ?? '50', 10) || 50;
const parallelism = Number.parseInt(process.env.NORMALIZE_PARALLELISM ?? '4', 10) || 4;
const maxCycles = Number.parseInt(process.env.MAX_CYCLES ?? '0', 10) || 0;
const sleepMs = Number.parseInt(process.env.SLEEP_MS ?? '0', 10) || 0;
const requestTimeoutMs = Number.parseInt(process.env.REQUEST_TIMEOUT_MS ?? '0', 10) || 0;
const sourceDiscovery = process.env.NORMALIZE_SOURCE_DISCOVERY ?? 'pending';
const adminCookie = await getAdminCookie(apiBaseUrl);
const configuredSources = process.env.NORMALIZE_SOURCES;
const fallbackSources = [
  'nvd-cve',
  'nvd-cve-init',
  'osv',
  'osv-init',
  'google-osv',
  'google-osv-init',
  'android-osv',
  'android-osv-init',
  'ubuntu-osv',
  'go-advisory',
  'cargo-advisory',
  'maven-osv',
  'maven-osv-init',
  'ghsa',
  'npm-advisory',
  'npm-audit',
  'pypi-advisory',
  'maven-advisory',
  'nuget-advisory',
  'redhat-csaf',
  'suse-csaf',
  'cve-list-v5',
  'alpine-secdb',
  'debian-security-tracker',
  'nvd-cpe',
  'first-epss',
  'cisa-kev',
  'exploitdb',
  'metasploit',
  'nuclei-templates',
  'poc-in-github',
  'trickest-cve',
  'cnnvd',
  'cnvd',
  'seebug',
  'aliyun-avd',
  'nsfocus-vulndb',
  'chaitin-vuldb',
  'cert-360',
  'npm-registry',
  'nuget-registry',
  'maven-registry',
  'pypi-registry',
  'crates-registry',
  'rubygems-registry',
  'packagist-registry'
];

function parseSources(value) {
  return value
    .split(',')
    .map((source) => source.trim())
    .filter(Boolean);
}

function postJson(path, payload) {
  const url = new URL(path, apiBaseUrl);
  const body = JSON.stringify(payload);
  const client = url.protocol === 'https:' ? https : http;

  return new Promise((resolve, reject) => {
    const request = client.request(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        cookie: adminCookie
      }
    }, (response) => {
      response.setEncoding('utf8');
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const text = chunks.join('');
        let parsed;
        try {
          parsed = text.length > 0 ? JSON.parse(text) : null;
        } catch (error) {
          reject(new Error(`Invalid JSON response from ${path}: ${error.message}: ${text}`));
          return;
        }

        resolve({
          ok: response.statusCode >= 200 && response.statusCode < 300,
          statusCode: response.statusCode,
          body: parsed
        });
      });
    });

    request.on('error', reject);
    if (requestTimeoutMs > 0) {
      request.setTimeout(requestTimeoutMs, () => {
        request.destroy(new Error(`Request timed out after ${requestTimeoutMs}ms: ${path}`));
      });
    }

    request.write(body);
    request.end();
  });
}

async function loadPendingSources() {
  if (configuredSources) {
    return parseSources(configuredSources).map((sourceCode) => ({ sourceCode, pending: null }));
  }

  if (sourceDiscovery === 'static') {
    return fallbackSources.map((sourceCode) => ({ sourceCode, pending: null }));
  }

  const client = new Client({ connectionString: databaseUrl });
  try {
    await client.connect();
    const result = await client.query(`
      select s.code as source_code, count(*)::bigint as pending
      from source_raw_index r
      join sources s on s.id = r.source_id
      where s.enabled = true
        and r.normalize_status in ('pending', 'failed')
      group by s.code
      having count(*) > 0
      order by count(*) desc, s.code
    `);
    return result.rows.map((row) => ({
      sourceCode: row.source_code,
      pending: Number(row.pending)
    }));
  } catch (error) {
    if (sourceDiscovery === 'pending') {
      console.warn(JSON.stringify({
        event: 'pending_source_discovery_failed',
        databaseUrl: redactedDatabaseUrl(databaseUrl),
        error: error.message,
        fallback: 'static'
      }));
    }
    return fallbackSources.map((sourceCode) => ({ sourceCode, pending: null }));
  } finally {
    await client.end().catch(() => {});
  }
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

async function normalizeSource(sourceCode, cycle) {
  const response = await postJson('/api/v1/raw.normalizeSource', {
    sourceCode,
    limit: batchSize
  });
  if (!response.ok || response.body?.ok === false) {
    throw new Error(`raw.normalizeSource failed for ${sourceCode}: ${JSON.stringify(response.body)}`);
  }

  const result = response.body.data ?? { sourceCode, processed: 0, failed: 0 };
  return {
    cycle,
    sourceCode,
    processed: Number(result.processed ?? 0),
    failed: Number(result.failed ?? 0)
  };
}

async function runPool(items, workerCount, cycle) {
  const results = [];
  let index = 0;

  async function worker() {
    while (index < items.length) {
      const source = items[index];
      index += 1;
      const startedAt = Date.now();
      try {
        const result = await normalizeSource(source, cycle);
        results.push({ ...result, elapsedMs: Date.now() - startedAt });
      } catch (error) {
        results.push({
          cycle,
          sourceCode: source,
          processed: 0,
          failed: 1,
          elapsedMs: Date.now() - startedAt,
          error: error.message
        });
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(workerCount, items.length) }, () => worker()));
  return results;
}

let cycle = 0;
while (true) {
  if (maxCycles > 0 && cycle >= maxCycles) {
    break;
  }

  cycle += 1;
  const pendingSources = await loadPendingSources();
  const sources = pendingSources.map((source) => source.sourceCode);
  if (sources.length === 0) {
    console.log(JSON.stringify({ cycle, event: 'no_pending_sources' }));
    break;
  }

  const cycleStartedAt = Date.now();
  console.log(JSON.stringify({
    cycle,
    event: 'cycle_start',
    batchSize,
    parallelism,
    sourceDiscovery,
    sources: pendingSources
  }));
  const results = await runPool(sources, parallelism, cycle);
  results.sort((a, b) => sources.indexOf(a.sourceCode) - sources.indexOf(b.sourceCode));
  const processed = results.reduce((sum, item) => sum + item.processed, 0);
  const failed = results.reduce((sum, item) => sum + item.failed, 0);
  const elapsedMs = Date.now() - cycleStartedAt;
  const throughputPerSecond = elapsedMs > 0 ? Math.round((processed / elapsedMs) * 100000) / 100 : 0;
  console.log(JSON.stringify({
    cycle,
    processed,
    failed,
    elapsedMs,
    throughputPerSecond,
    results: results.map((item) => ({
      ...item,
      throughputPerSecond: item.elapsedMs > 0 ? Math.round((item.processed / item.elapsedMs) * 100000) / 100 : 0
    }))
  }));

  if (processed === 0) {
    break;
  }

  if (sleepMs > 0) {
    await new Promise((resolve) => setTimeout(resolve, sleepMs));
  }
}
