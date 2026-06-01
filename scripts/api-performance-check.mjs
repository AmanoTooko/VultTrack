#!/usr/bin/env node
import { performance } from 'node:perf_hooks';
import { getAdminCookie } from './lib/admin-auth.mjs';

const baseUrl = process.env.API_BASE_URL ?? 'http://127.0.0.1:5099';
const includeMutating = process.env.INCLUDE_MUTATING === '1';
const includeExactStatus = process.env.INCLUDE_EXACT_STATUS === '1';
const adminCookie = await getAdminCookie(baseUrl);

const cyclonedx = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  metadata: { component: { type: 'application', name: 'vultrack-api-check', version: '1.0.0' } },
  components: [
    {
      type: 'library',
      name: 'log4j-core',
      version: '2.14.1',
      purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'
    }
  ]
};

const rows = [];
let sampleVulnerabilityId = null;
let sampleVulnerabilityIdentifier = null;
let tempSbomId;

async function timed(name, request, validate = () => {}) {
  const start = performance.now();
  let status = 0;
  let ok;
  let data = null;
  let error = null;
  try {
    const response = await fetch(typeof request === 'string' ? request : request.url, typeof request === 'string' ? undefined : request);
    status = response.status;
    const text = await response.text();
    const body = text ? JSON.parse(text) : null;
    ok = response.ok && body?.ok !== false;
    if (!ok) throw new Error(body?.error?.message ?? `HTTP ${status}`);
    data = body?.data;
    await validate(data);
  } catch (err) {
    ok = false;
    error = err instanceof Error ? err.message : String(err);
  }
  const durationMs = Math.round((performance.now() - start) * 10) / 10;
  rows.push({ name, ok, status, durationMs, error });
  return data;
}

async function timedRaw(name, request, validate = () => {}) {
  const start = performance.now();
  let status = 0;
  let ok;
  let error = null;
  try {
    const response = await fetch(typeof request === 'string' ? request : request.url, typeof request === 'string' ? undefined : request);
    status = response.status;
    const text = await response.text();
    ok = response.ok;
    if (!ok) throw new Error(`HTTP ${status}`);
    await validate(text, response);
  } catch (err) {
    ok = false;
    error = err instanceof Error ? err.message : String(err);
  }
  const durationMs = Math.round((performance.now() - start) * 10) / 10;
  rows.push({ name, ok, status, durationMs, error });
}

const get = (path) => ({ url: `${baseUrl}${path}`, headers: { cookie: adminCookie } });
const post = (path, body) => ({
  url: `${baseUrl}${path}`,
  method: 'POST',
  headers: { 'content-type': 'application/json', cookie: adminCookie },
  body: typeof body === 'string' ? body : JSON.stringify(body)
});

await timedRaw('GET /', get('/'), (text) => {
  if (!text.includes('VulTrack')) throw new Error('missing frontend shell');
});
await timedRaw('GET /index.html', get('/index.html'), (text) => {
  if (!text.includes('VulTrack')) throw new Error('missing frontend shell');
});
await timed('GET /api/v1/system.health', get('/api/v1/system.health'));
await timed('GET /api/v1/system.ready', get('/api/v1/system.ready'));
await timed('GET /api/v1/source.list', get('/api/v1/source.list'), (data) => {
  if (!Array.isArray(data) || data.length === 0) throw new Error('empty source list');
});
await timed('GET /api/v1/system.status fast', get('/api/v1/system.status?fast=true'), (data) => {
  if (typeof data.vulnerabilities !== 'number') throw new Error('missing vulnerability count');
});
if (includeExactStatus) {
  await timed('GET /api/v1/system.status exact', get('/api/v1/system.status'), (data) => {
    if (typeof data.vulnerabilities !== 'number' || data.countsEstimated) throw new Error('missing exact vulnerability count');
  });
}

await timed('POST /api/v1/vulnerability.search latest', post('/api/v1/vulnerability.search', {
  query: '',
  page: 1,
  pageSize: 10,
  sort: 'modifiedDesc'
}), (data) => {
  if (!Array.isArray(data.items) || data.items.length === 0) throw new Error('no vulnerabilities');
  sampleVulnerabilityId = data.items[0].id;
  sampleVulnerabilityIdentifier = data.items[0].primaryIdentifier;
});

await timed('POST /api/v1/vulnerability.search CVE prefix', post('/api/v1/vulnerability.search', {
  query: 'CVE-2021',
  page: 1,
  pageSize: 25,
  sort: 'modifiedDesc'
}), (data) => {
  if (!data.items.every((item) => item.primaryIdentifier.startsWith('CVE-2021'))) throw new Error('prefix mismatch');
});

await timed('POST /api/v1/vulnerability.search CVSS sort', post('/api/v1/vulnerability.search', {
  query: 'CVE-2021',
  page: 1,
  pageSize: 25,
  sort: 'cvssDesc'
}), (data) => {
  if (data.sort !== 'cvssDesc') throw new Error('sort not applied');
});

if (sampleVulnerabilityIdentifier) {
  await timed('GET /api/v1/vulnerability.getByIdentifier', get(`/api/v1/vulnerability.getByIdentifier?identifier=${encodeURIComponent(sampleVulnerabilityIdentifier)}`));
}
if (sampleVulnerabilityId) {
  await timed('GET /api/v1/vulnerability.get', get(`/api/v1/vulnerability.get?id=${encodeURIComponent(sampleVulnerabilityId)}`));
  await timed('GET /api/v1/vulnerability.detail', get(`/api/v1/vulnerability.detail?id=${encodeURIComponent(sampleVulnerabilityId)}`), (data) => {
    if (!data.vulnerability) throw new Error('missing detail vulnerability');
  });
}

await timed('POST /api/v1/component.search', post('/api/v1/component.search', {
  query: 'log4j-core',
  name: 'log4j-core',
  ecosystem: 'maven',
  pageSize: 25
}));
await timed('POST /api/v1/component.vulnerabilitySearch', post('/api/v1/component.vulnerabilitySearch', {
  componentName: 'log4j-core',
  name: 'log4j-core',
  ecosystem: 'maven',
  version: '2.14.1',
  pageSize: 25
}));

await timed('GET /api/v1/benchmark.ecosystemCveCount', get('/api/v1/benchmark.ecosystemCveCount?ecosystem=maven&package=log4j-core'));
await timed('GET /api/v1/benchmark.packageCves', get('/api/v1/benchmark.packageCves?name=log4j-core'));
await timed('GET /api/v1/benchmark.matchingQuality', get('/api/v1/benchmark.matchingQuality?ecosystem=maven&packageName=log4j-core'));

const upload = await timed('POST /api/v1/sbom.upload', post('/api/v1/sbom.upload', JSON.stringify(cyclonedx)), (data) => {
  if (!data.id) throw new Error('missing sbom id');
});
tempSbomId = upload?.id;
await timed('GET /api/v1/sbom.list', get('/api/v1/sbom.list'));
if (tempSbomId) {
  await timed('GET /api/v1/sbom.get', get(`/api/v1/sbom.get?id=${encodeURIComponent(tempSbomId)}`));
  await timed('POST /api/v1/sbom.match', post('/api/v1/sbom.match', { sbomId: tempSbomId }));
  await timedRaw('GET /api/v1/sbom.export', get(`/api/v1/sbom.export?id=${encodeURIComponent(tempSbomId)}`), (text) => {
    if (!text.includes('Component Name') || !text.includes('CVE')) throw new Error('missing export columns');
  });
  await timed('GET /api/v1/benchmark.matchingQuality sbom', get(`/api/v1/benchmark.matchingQuality?sbomId=${encodeURIComponent(tempSbomId)}`));
  await timed('POST /api/v1/sbom.delete', post('/api/v1/sbom.delete', { sbomId: tempSbomId }));
}

if (includeMutating) {
  await timed('POST /api/v1/nvd.processPending limit 1', post('/api/v1/nvd.processPending', { limit: 1 }));
  await timed('POST /api/v1/raw.normalizeSource ghsa limit 1', post('/api/v1/raw.normalizeSource', { sourceCode: 'ghsa', limit: 1 }));
  await timed('POST /api/v1/raw.normalizeSource poc-in-github limit 1', post('/api/v1/raw.normalizeSource', { sourceCode: 'poc-in-github', limit: 1 }));
  await timed('POST /api/v1/raw.normalizePending limit 1', post('/api/v1/raw.normalizePending', { limitPerSource: 1 }));
}

const failed = rows.filter((row) => !row.ok);
const slow = rows.filter((row) => row.ok && row.durationMs > 1000);

console.table(rows);
console.log(JSON.stringify({
  baseUrl,
  includeMutating,
  includeExactStatus,
  total: rows.length,
  failed: failed.length,
  slow: slow.map((row) => ({ name: row.name, durationMs: row.durationMs }))
}, null, 2));

if (failed.length > 0) {
  process.exitCode = 1;
}
