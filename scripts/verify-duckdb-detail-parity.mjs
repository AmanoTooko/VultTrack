#!/usr/bin/env node
import pg from 'pg';

const { Client } = pg;
const databaseUrl = process.env.DATABASE_URL ?? 'postgres://vultrack:vultrack@127.0.0.1:5432/vultrack';
const apiBase = (process.env.VULTRACK_API_BASE ?? 'http://127.0.0.1:5099').replace(/\/$/, '');
const sampleSize = Math.max(1, Math.min(2000, Number.parseInt(process.env.SAMPLE_SIZE ?? '200', 10)));
const concurrency = Math.max(1, Math.min(32, Number.parseInt(process.env.CONCURRENCY ?? '8', 10)));

const client = new Client({ connectionString: databaseUrl });
await client.connect();

try {
  const result = await client.query(`
    select id
    from vulnerabilities
    where affected_component_count > 0
    order by md5(id::text)
    limit $1
  `, [sampleSize]);
  const ids = result.rows.map(row => row.id);
  const totals = Object.fromEntries(['affectedComponents', 'affectedExpressions', 'severities', 'references']
    .map(name => [name, { pg: 0, duckdb: 0, missingFromDuckDb: 0, extraInDuckDb: 0 }]));
  const examples = Object.fromEntries(Object.keys(totals).map(name => [name, []]));
  let failures = 0;
  let invalidReferenceTags = 0;
  let cursor = 0;

  await Promise.all(Array.from({ length: concurrency }, async () => {
    while (true) {
      const index = cursor++;
      if (index >= ids.length) return;
      try {
        const [pgsql, duckdb] = await Promise.all([
          detail(ids[index], 'pgsql'),
          detail(ids[index], 'duckdb')
        ]);
        compare(ids[index], 'affectedComponents', pgsql, duckdb, row => key(row,
          'ecosystem', 'package_name', 'display_name', 'primary_purl', 'primary_cpe23_uri',
          'normalized_range', 'range_type'));
        compare(ids[index], 'affectedExpressions', pgsql, duckdb, row => key(row,
          'code', 'fact_type', 'ecosystem', 'package_name', 'purl', 'purl_without_version',
          'cpe23_uri', 'version_range_raw', 'range_type', 'vulnerable'));
        compare(ids[index], 'severities', pgsql, duckdb, row => key(row,
          'code', 'scoring_system', 'scoring_version', 'score_type', 'vector_string', 'score',
          'severity_label'));
        compare(ids[index], 'references', pgsql, duckdb, row => key(row, 'code', 'url', 'ref_type'));
        invalidReferenceTags += duckdb.references.filter(row => !Array.isArray(row.tags)).length;
      } catch (error) {
        failures++;
        console.error(`${ids[index]}: ${error.message}`);
      }
    }
  }));

  console.log(JSON.stringify({ sampleSize: ids.length, failures, invalidReferenceTags, totals, examples }, null, 2));
  if (failures > 0 || invalidReferenceTags > 0) process.exitCode = 1;

  function compare(id, name, pgDetail, duckDetail, rowKey) {
    const pgRows = pgDetail[name] ?? [];
    const duckRows = duckDetail[name] ?? [];
    const pgKeys = new Set(pgRows.map(rowKey));
    const duckKeys = new Set(duckRows.map(rowKey));
    totals[name].pg += pgKeys.size;
    totals[name].duckdb += duckKeys.size;
    const missing = [...pgKeys].filter(value => !duckKeys.has(value));
    const extra = [...duckKeys].filter(value => !pgKeys.has(value));
    totals[name].missingFromDuckDb += missing.length;
    totals[name].extraInDuckDb += extra.length;
    if ((missing.length > 0 || extra.length > 0) && examples[name].length < 5) {
      examples[name].push({
        id,
        primaryIdentifier: pgDetail.vulnerability.primaryIdentifier,
        missing: missing.slice(0, 3),
        extra: extra.slice(0, 3)
      });
    }
  }
} finally {
  await client.end();
}

async function detail(id, source) {
  const response = await fetch(`${apiBase}/api/v1/vulnerability.detail?id=${id}&source=${source}&snapshot=false`);
  if (!response.ok) throw new Error(`${source} returned HTTP ${response.status}`);
  const payload = await response.json();
  if (!payload.ok || !payload.data) throw new Error(`${source} returned an invalid payload`);
  return payload.data;
}

function key(row, ...fields) {
  return fields.map(field => JSON.stringify(row[field] ?? null)).join('|');
}
