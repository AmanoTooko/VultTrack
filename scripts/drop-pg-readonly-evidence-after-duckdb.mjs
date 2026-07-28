#!/usr/bin/env node
import pg from 'pg';

const { Client } = pg;
const args = new Set(process.argv.slice(2));
const databaseUrl = process.env.DATABASE_URL ?? 'postgres://vultrack:vultrack@127.0.0.1:5432/vultrack';
const expectedDuckRowsText = process.env.EXPECTED_DUCKDB_AFFECTED_COMPONENTS ?? '0';
const expectedDuckFactsText = process.env.EXPECTED_DUCKDB_AFFECTED_FACTS ?? '0';
const expectedDuckReferencesText = process.env.EXPECTED_DUCKDB_REFERENCES ?? '0';
const expectedDuckSeveritiesText = process.env.EXPECTED_DUCKDB_SEVERITIES ?? '0';
const expectedDuckWeaknessesText = process.env.EXPECTED_DUCKDB_WEAKNESSES ?? '0';
const expectedDuckRows = /^\d+$/.test(expectedDuckRowsText) ? BigInt(expectedDuckRowsText) : 0n;
const expectedDuckFacts = /^\d+$/.test(expectedDuckFactsText) ? BigInt(expectedDuckFactsText) : 0n;
const expectedDuckReferences = /^\d+$/.test(expectedDuckReferencesText) ? BigInt(expectedDuckReferencesText) : 0n;
const expectedDuckSeverities = /^\d+$/.test(expectedDuckSeveritiesText) ? BigInt(expectedDuckSeveritiesText) : 0n;
const expectedDuckWeaknesses = /^\d+$/.test(expectedDuckWeaknessesText) ? BigInt(expectedDuckWeaknessesText) : 0n;

if (!args.has('--yes')) {
  console.error('Refusing to clear PostgreSQL read-only evidence without --yes.');
  process.exit(2);
}

if ([expectedDuckRows, expectedDuckFacts, expectedDuckReferences, expectedDuckSeverities, expectedDuckWeaknesses].some(value => value <= 0n)) {
  console.error('Set all verified EXPECTED_DUCKDB_* evidence counts first.');
  process.exit(2);
}

const client = new Client({ connectionString: databaseUrl });
await client.connect();

try {
  const before = await scalar(`
    select count(*)::bigint
    from vulnerability_affected_components
  `);
  const pgVulns = await scalar(`
    select count(distinct vulnerability_id)::bigint
    from vulnerability_affected_components
  `);
  const pgFacts = await scalar(`
    select count(*)::bigint
    from vulnerability_affected_facts
  `);
  const queue = await scalar(`
    select count(*)::bigint
    from duckdb_affected_component_queue
  `);
  const pgReferences = await scalar('select count(*)::bigint from vulnerability_references');
  const pgSeverities = await scalar('select count(*)::bigint from vulnerability_severity_scores');
  const pgWeaknesses = await scalar('select count(*)::bigint from vulnerability_weaknesses');

  console.log(JSON.stringify({
    event: 'pg_affected_components_preflight',
    pgRows: before.toString(),
    pgVulnerabilities: pgVulns.toString(),
    duckRowsVerifiedByOperator: expectedDuckRows.toString(),
    pgFacts: pgFacts.toString(),
    duckFactsVerifiedByOperator: expectedDuckFacts.toString(),
    pgReferences: pgReferences.toString(),
    duckReferencesVerifiedByOperator: expectedDuckReferences.toString(),
    pgSeverities: pgSeverities.toString(),
    duckSeveritiesVerifiedByOperator: expectedDuckSeverities.toString(),
    pgWeaknesses: pgWeaknesses.toString(),
    duckWeaknessesVerifiedByOperator: expectedDuckWeaknesses.toString(),
    duckDbAffectedQueue: queue.toString()
  }));

  if (expectedDuckRows < before / 2n) {
    throw new Error(`Verified DuckDB row count ${expectedDuckRows} is suspiciously lower than PG rows ${before}`);
  }
  if (expectedDuckFacts < pgFacts / 2n) {
    throw new Error(`Verified DuckDB fact count ${expectedDuckFacts} is suspiciously lower than PG facts ${pgFacts}`);
  }
  if (expectedDuckReferences < pgReferences / 2n) {
    throw new Error(`Verified DuckDB reference count ${expectedDuckReferences} is suspiciously lower than PG rows ${pgReferences}`);
  }
  if (expectedDuckSeverities < pgSeverities / 2n) {
    throw new Error(`Verified DuckDB severity count ${expectedDuckSeverities} is suspiciously lower than PG rows ${pgSeverities}`);
  }
  if (expectedDuckWeaknesses < pgWeaknesses / 2n) {
    throw new Error(`Verified DuckDB weakness count ${expectedDuckWeaknesses} is suspiciously lower than PG rows ${pgWeaknesses}`);
  }

  await client.query(`
    truncate table
      vulnerability_affected_components,
      vulnerability_affected_facts,
      vulnerability_references,
      vulnerability_severity_scores,
      vulnerability_weaknesses
    cascade
  `);
  await client.query('truncate table duckdb_affected_component_queue');
  await client.query('vacuum (analyze) vulnerability_affected_components');
  await client.query('vacuum (analyze) vulnerability_affected_facts');

  const after = await scalar('select count(*)::bigint from vulnerability_affected_components');
  console.log(JSON.stringify({
    event: 'pg_readonly_evidence_cleared',
    before: before.toString(),
    after: after.toString(),
    factsBefore: pgFacts.toString(),
    referencesBefore: pgReferences.toString(),
    severitiesBefore: pgSeverities.toString(),
    weaknessesBefore: pgWeaknesses.toString(),
    queueCleared: queue.toString()
  }));
} finally {
  await client.end();
}

async function scalar(sql) {
  const result = await client.query(sql);
  return BigInt(result.rows[0].count);
}
