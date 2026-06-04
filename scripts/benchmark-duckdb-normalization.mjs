#!/usr/bin/env node
import { performance } from 'node:perf_hooks';
import { getAdminCookie } from './lib/admin-auth.mjs';

const apiBaseUrl = process.env.API_BASE_URL ?? 'http://localhost:5099';
const args = parseArgs(process.argv.slice(2));
const sourceCode = args.source ?? args.sources ?? null;
const limit = positiveInt(args.limit ?? process.env.DUCKDB_NORMALIZE_LIMIT, 1000);
const reset = args.reset === true || args.reset === 'true' || process.env.DUCKDB_NORMALIZE_RESET === '1';
const cookie = await getAdminCookie(apiBaseUrl);

const started = performance.now();
const response = await fetch(new URL('/api/v1/admin.duckdbEvidence.normalize', apiBaseUrl), {
  method: 'POST',
  headers: { 'content-type': 'application/json', cookie },
  body: JSON.stringify({ sourceCode, limit, reset })
});
const body = await response.json().catch(() => null);
if (!response.ok || body?.ok === false) {
  throw new Error(body?.error?.message ?? `DuckDB normalization failed: HTTP ${response.status}`);
}

const elapsedMs = Math.round(performance.now() - started);
const data = body.data;
console.table(data.sources.map((item) => ({
  source: item.sourceCode,
  records: item.records,
  facts: item.affectedFacts,
  severity: item.severityScores,
  refs: item.references,
  weaknesses: item.weaknesses,
  ms: item.elapsedMs
})));
console.log(JSON.stringify({
  apiBaseUrl,
  elapsedMs,
  path: data.path,
  stats: data.stats
}, null, 2));

function parseArgs(argv) {
  const parsed = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    const [key, inline] = arg.slice(2).split('=', 2);
    if (inline !== undefined) {
      parsed[key] = inline;
    } else if (argv[i + 1] && !argv[i + 1].startsWith('--')) {
      parsed[key] = argv[++i];
    } else {
      parsed[key] = true;
    }
  }
  return parsed;
}

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}
