#!/usr/bin/env node
import pg from 'pg';

const { Client } = pg;
const databaseUrl = process.env.DATABASE_URL ?? 'postgres://vultrack:vultrack@127.0.0.1:5432/vultrack';
const client = new Client({ connectionString: databaseUrl });
await client.connect();
try {
  await client.query(`set statement_timeout = '${Number.parseInt(process.env.AUDIT_TIMEOUT_MS ?? '300000', 10)}'`);
  const totals = await client.query(`
      select
        (select count(*)::bigint from vulnerabilities) vulnerabilities,
        (select count(*)::bigint from vulnerability_identifier_index) identifier_rows,
        (select count(*)::bigint from vulnerability_affected_facts) affected_facts,
        (select count(*)::bigint from vulnerability_affected_components) affected_components
    `);
  const multiCve = await client.query(`
      with cve_index as materialized (
        select distinct canonical_vulnerability_id, normalized_value
        from vulnerability_identifier_index
        where normalized_value ~ '^CVE-[0-9]{4}-[0-9]{4,}$' and canonical_vulnerability_id is not null
      ), suspicious as (
        select canonical_vulnerability_id, count(*)::bigint cve_count
        from cve_index
        group by canonical_vulnerability_id
        having count(*) > 1
      )
      select s.canonical_vulnerability_id, s.cve_count,
             array(
               select distinct i.normalized_value
               from vulnerability_identifier_index i
               where i.canonical_vulnerability_id = s.canonical_vulnerability_id
                 and i.normalized_value ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
               order by i.normalized_value
               limit 20
             ) sample_cves
      from suspicious s
      order by s.cve_count desc
      limit 100
    `);
  const staleProjections = await client.query(`
      select count(*)::bigint stale
      from vulnerability_affected_components c
      where not exists (
        select 1 from vulnerability_affected_facts f
        where f.vulnerability_id = c.vulnerability_id
          and coalesce(f.ecosystem, '') = coalesce(c.ecosystem, '')
          and coalesce(f.package_name, f.purl, '') = coalesce(c.package_name, c.primary_purl, '')
          and coalesce(f.version_range_raw, '') = coalesce(c.normalized_range, '')
      )
    `);
  const cpeCoverage = await client.query(`
      select
        (select count(*)::bigint from cpe_entries) cpe_entries,
        (select count(*)::bigint from vulnerability_affected_facts where cpe23_uri is not null and cpe23_uri <> '') cpe_facts,
        (select count(*)::bigint from vulnerability_affected_components where primary_cpe23_uri is not null and primary_cpe23_uri <> '') cpe_projections
    `);
  const suspiciousSources = await client.query(`
      with cve_index as materialized (
        select distinct canonical_vulnerability_id, normalized_value
        from vulnerability_identifier_index
        where normalized_value ~ '^CVE-[0-9]{4}-[0-9]{4,}$' and canonical_vulnerability_id is not null
      ), suspicious as (
        select canonical_vulnerability_id
        from cve_index
        group by canonical_vulnerability_id
        having count(*) > 1
      )
      select s.code, count(*)::bigint records
      from suspicious x
      join vulnerability_records vr on vr.vulnerability_id = x.canonical_vulnerability_id
      join sources s on s.id = vr.source_id
      group by s.code
      order by records desc, s.code
    `);
  const rawCoverage = await client.query(`
      select s.code,
             count(*) filter (where r.normalize_status in ('pending', 'failed'))::bigint pending,
             count(*) filter (where r.normalize_status = 'succeeded')::bigint normalized
      from source_raw_index r join sources s on s.id = r.source_id
      group by s.code order by s.code
    `);
  console.log(JSON.stringify({
    generatedAt: new Date().toISOString(),
    totals: totals.rows[0],
    suspiciousCanonicalGroups: multiCve.rows,
    suspiciousCanonicalSources: suspiciousSources.rows,
    cpeCoverage: cpeCoverage.rows[0],
    staleProjectionCount: Number(staleProjections.rows[0].stale),
    normalizationBySource: rawCoverage.rows
  }, null, 2));
} finally {
  await client.end();
}
