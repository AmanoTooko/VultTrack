#!/usr/bin/env node
import pg from 'pg';

const { Client } = pg;
if (process.env.ALLOW_CANONICAL_SMOKE_SEED !== '1') {
  throw new Error('Refusing to seed smoke records without ALLOW_CANONICAL_SMOKE_SEED=1');
}

const apiBaseUrl = process.env.API_BASE_URL ?? 'http://127.0.0.1:5199';
const databaseUrl = process.env.DATABASE_URL ?? 'postgres://vultrack:vultrack-benchmark@127.0.0.1:55432/vultrack';
const client = new Client({ connectionString: databaseUrl });
await client.connect();

const sourceId = async (code) => {
  const result = await client.query('select id from sources where code = $1', [code]);
  if (result.rowCount !== 1) throw new Error(`Missing source ${code}`);
  return result.rows[0].id;
};

try {
  const nvdSourceId = await sourceId('nvd-cve');
  const ghsaSourceId = await sourceId('ghsa');
  await client.query(`
      insert into source_raw_index
        (id, source_id, external_key, content_hash, record_hash, parse_status, normalize_status,
         source_published_at, source_modified_at)
      values
        ('10000000-0000-0000-0000-000000000001', $1, 'CVE-2099-0001', 'nvd-cpe-content',
         'nvd-cpe-record', 'succeeded', 'pending', '2099-01-01', '2099-01-02')
    `, [nvdSourceId]);
  await client.query(`
      insert into stg_nvd_cves
        (raw_index_id, cve_id, vuln_status, descriptions, metrics, weaknesses, configurations,
         references_json, published_at, modified_at, payload)
      values
        ('10000000-0000-0000-0000-000000000001', 'CVE-2099-0001', 'Analyzed',
         '[{"lang":"en","value":"Synthetic NVD CPE regression"}]', '{}', '[]',
         '[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*","versionStartIncluding":"1.0.0","versionEndExcluding":"2.0.0"}]}]}]',
         '[]', '2099-01-01', '2099-01-02', '{"id":"CVE-2099-0001"}')
    `);
  for (const [suffix, cve] of [['1', 'CVE-2099-1001'], ['2', 'CVE-2099-1002']]) {
    const rawId = `20000000-0000-0000-0000-00000000000${suffix}`;
    await client.query(`
        insert into source_raw_index
          (id, source_id, external_key, content_hash, record_hash, parse_status, normalize_status)
        values ($1, $2, $3, $4, $4, 'succeeded', 'pending')
      `, [rawId, ghsaSourceId, `GHSA-SHARED-COLLISION-TEST:${cve}`, `ghsa-test-${suffix}`]);
    await client.query(`
        insert into stg_ghsa_advisories
          (raw_index_id, ghsa_id, cve_id, summary, description, ecosystem, package_name,
           vulnerable_ranges, cvss, cwes, references_json, payload)
        values ($1, 'GHSA-SHARED-COLLISION-TEST', $2, 'Synthetic shared alias regression',
                'Synthetic shared alias regression', 'npm', 'demo', '[">= 1.0.0, < 2.0.0"]',
                '{}', '[]', '[]', '{}')
      `, [rawId, cve]);
  }

  const login = await fetch(`${apiBaseUrl}/api/v1/auth.login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'admin' })
  });
  if (!login.ok) throw new Error(`Login failed: ${login.status}`);
  const cookie = login.headers.getSetCookie()[0].split(';', 1)[0];
  const post = async (path, body) => {
    const response = await fetch(`${apiBaseUrl}${path}`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify(body)
    });
    const payload = await response.json();
    if (!response.ok || !payload.ok) throw new Error(`${path} failed: ${JSON.stringify(payload)}`);
    return payload.data;
  };
  await post('/api/v1/nvd.processPending', { limit: 10 });
  await post('/api/v1/raw.normalizeSource', { sourceCode: 'ghsa', limit: 10 });
  const searchResponse = await fetch(`${apiBaseUrl}/api/v1/vulnerability.search`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ query: 'CVE-2099-1002', pageSize: 10 })
  });
  const search = await searchResponse.json();

  const cpe = await client.query(`
      select c.primary_cpe23_uri, c.normalized_range, v.affected_component_count
      from vulnerabilities v
      join vulnerability_affected_components c on c.vulnerability_id = v.id
      where v.primary_identifier = 'CVE-2099-0001'
    `);
  const cveRows = await client.query(`
      select count(*)::int count
      from vulnerabilities
      where primary_identifier in ('CVE-2099-1001', 'CVE-2099-1002')
    `);
  const sharedAlias = await client.query(`
      select count(distinct canonical_vulnerability_id)::int count
      from vulnerability_identifier_index
      where normalized_value = 'GHSA-SHARED-COLLISION-TEST'
    `);

  const result = {
    cpeProjection: cpe.rows[0],
    distinctCveRows: cveRows.rows[0].count,
    sharedAliasCanonicalGroups: sharedAlias.rows[0].count,
    exactSearchPrimaryIdentifier: search.data?.items?.[0]?.primaryIdentifier
  };
  if (result.cpeProjection?.primary_cpe23_uri !== 'cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*') {
    throw new Error(`CPE projection mismatch: ${JSON.stringify(result)}`);
  }
  if (result.cpeProjection?.normalized_range !== '>= 1.0.0, < 2.0.0') {
    throw new Error(`CPE range mismatch: ${JSON.stringify(result)}`);
  }
  if (result.cpeProjection?.affected_component_count !== 1) {
    throw new Error(`Affected component count mismatch: ${JSON.stringify(result)}`);
  }
  if (result.distinctCveRows !== 2 || result.sharedAliasCanonicalGroups !== 2) {
    throw new Error(`Canonical isolation mismatch: ${JSON.stringify(result)}`);
  }
  if (result.exactSearchPrimaryIdentifier !== 'CVE-2099-1002') {
    throw new Error(`Exact CVE search mismatch: ${JSON.stringify(result)}`);
  }
  console.log(JSON.stringify(result, null, 2));
} finally {
  await client.end();
}
