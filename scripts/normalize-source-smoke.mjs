import pg from 'pg';
import { getAdminCookie } from './lib/admin-auth.mjs';

const { Client } = pg;
const apiBaseUrl = process.env.API_BASE_URL ?? 'http://localhost:5099';
const databaseUrl = process.env.DATABASE_URL ?? 'postgres://vultrack:vultrack@localhost:5432/vultrack';
const limit = Number.parseInt(process.env.SOURCE_SMOKE_LIMIT ?? '500', 10) || 500;
const requestedSources = process.argv.slice(2).filter(Boolean);
const adminCookie = await getAdminCookie(apiBaseUrl);

const supportedSources = new Set([
  'nvd-cve',
  'ghsa',
  'npm-advisory',
  'npm-audit',
  'ubuntu-osv',
  'android-osv',
  'android-osv-init',
  'google-osv',
  'google-osv-init',
  'go-advisory',
  'cargo-advisory',
  'maven-osv',
  'maven-osv-init',
  'osv',
  'osv-init',
  'pypi-advisory',
  'cisa-kev',
  'first-epss',
  'exploitdb',
  'metasploit',
  'nuclei-templates',
  'poc-in-github',
  'trickest-cve',
  'alpine-secdb',
  'debian-security-tracker',
  'redhat-csaf',
  'suse-csaf',
  'nvd-cpe',
  'npm-registry',
  'nuget-registry',
  'maven-registry',
  'pypi-registry',
  'crates-registry',
  'rubygems-registry',
  'packagist-registry'
]);

const prioritized = [
  'nvd-cve',
  'ghsa',
  'ubuntu-osv',
  'pypi-advisory',
  'cisa-kev',
  'first-epss',
  'alpine-secdb',
  'debian-security-tracker',
  'nvd-cpe',
  'npm-registry'
];

const client = new Client({ connectionString: databaseUrl });
await client.connect();

try {
  const counts = await loadPendingCounts(client);
  const sources = (requestedSources.length ? requestedSources : prioritized)
    .filter((source) => supportedSources.has(source))
    .filter((source) => Number(counts.get(source) ?? 0) > 0);

  if (!sources.length) {
    console.log(JSON.stringify({ ok: false, message: 'No supported pending sources found' }, null, 2));
    process.exitCode = 1;
  } else {
    console.log(JSON.stringify({
      ok: true,
      apiBaseUrl,
      limit,
      sources: sources.map((source) => ({ source, pending: Number(counts.get(source) ?? 0) }))
    }, null, 2));

    for (const sourceCode of sources) {
      const before = Number(counts.get(sourceCode) ?? 0);
      const response = await fetch(`${apiBaseUrl}/api/v1/raw.normalizeSource`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: adminCookie },
        body: JSON.stringify({ sourceCode, limit })
      });
      const body = await response.json();
      if (!response.ok || body.ok === false) {
        throw new Error(`normalizeSource failed for ${sourceCode}: ${JSON.stringify(body)}`);
      }

      const result = body.data;
      console.log(JSON.stringify({
        sourceCode,
        before,
        processed: result.processed,
        failed: result.failed
      }));
    }
  }
} finally {
  await client.end();
}

async function loadPendingCounts(client) {
  const result = await client.query(`
    select s.code, count(*)::bigint as pending
    from source_raw_index r
    join sources s on s.id = r.source_id
    where r.normalize_status <> 'succeeded'
    group by s.code
  `);
  return new Map(result.rows.map((row) => [row.code, Number(row.pending)]));
}
