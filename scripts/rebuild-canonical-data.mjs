#!/usr/bin/env node
import pg from 'pg';

const { Client } = pg;
const apply = process.argv.includes('--apply');
const confirmed = process.argv.includes('--confirm=REBUILD_CANONICAL_DATA');
const databaseUrl = process.env.DATABASE_URL ?? 'postgres://vultrack:vultrack@127.0.0.1:5432/vultrack';
const tables = [
  'vulnerability_affected_evidence',
  'version_match_cache',
  'sbom_vulnerabilities',
  'vulnerability_affected_components',
  'vulnerability_affected_facts',
  'vulnerability_detail_blocks',
  'vulnerability_source_properties',
  'vulnerability_exploits',
  'vulnerability_references',
  'vulnerability_weaknesses',
  'vulnerability_descriptions',
  'vulnerability_severity_scores',
  'vulnerability_identifier_edges',
  'vulnerability_identifier_index',
  'vulnerability_identifier_groups',
  'vulnerability_records',
  'vulnerabilities'
];
const client = new Client({ connectionString: databaseUrl });
await client.connect();
try {
  const counts = {};
  for (const table of tables) {
    const result = await client.query(`select count(*)::bigint count from ${table}`);
    counts[table] = Number(result.rows[0].count);
  }
  console.log(JSON.stringify({ mode: apply ? 'apply' : 'dry-run', counts }, null, 2));
  if (!apply) {
    console.log('Dry run only. Use --apply --confirm=REBUILD_CANONICAL_DATA after creating a backup.');
    process.exit(0);
  }
  if (!confirmed) throw new Error('Refusing destructive rebuild without --confirm=REBUILD_CANONICAL_DATA');

  await client.query('begin');
  try {
    for (const table of tables) await client.query(`delete from ${table}`);
    await client.query("update sbom_components set vuln_count = 0");
    await client.query("update sbom_uploads set matched_count = 0");
    await client.query("update source_raw_index set normalize_status = 'pending', updated_at = now() where parse_status = 'succeeded'");
    await client.query('commit');
  } catch (error) {
    await client.query('rollback');
    throw error;
  }
  console.log('Canonical and derived data cleared. Parsed raw records were requeued for normalization.');
} finally {
  await client.end();
}
