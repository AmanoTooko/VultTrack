import { fetchJson } from '../lib/http.mjs';
import { getEnv, getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertNpmAdvisory } from '../lib/staging.mjs';
import { extractIdentifiers, npmPurl } from '../lib/advisory.mjs';

export const sourceCode = 'npm-audit';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const specs = getEnv('NPM_AUDIT_PACKAGES', getEnv('NPM_PACKAGES', 'lodash@4.17.20,express@4.17.1,react@16.0.0'))
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);

  const auditPayload = {};
  for (const spec of specs) {
    const { name, version } = parseSpec(spec);
    if (!auditPayload[name]) auditPayload[name] = [];
    if (version) {
      auditPayload[name].push(version);
    } else {
      const meta = await fetchJson(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
      const latest = meta['dist-tags']?.latest;
      if (latest) auditPayload[name].push(latest);
    }
  }

  const res = await fetch('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'accept': 'application/json',
      'user-agent': 'VulTrack/0.1'
    },
    body: JSON.stringify(auditPayload)
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status} for npm audit bulk: ${text.slice(0, 500)}`);
  }

  const data = await res.json();
  let count = 0;
  for (const [packageName, advisories] of Object.entries(data)) {
    for (const advisory of advisories ?? []) {
      if (count >= max) break;
      const ids = extractIdentifiers(advisory.url, advisory.title, ...(advisory.cves ?? []));
      const ghsa = ids.find((id) => id.startsWith('GHSA-')) ?? `NPM-${advisory.id}`;
      const item = {
        ghsa_id: ghsa,
        identifiers: ids.map((value) => ({ type: value.split('-')[0], value })),
        severity: advisory.severity ?? null,
        summary: advisory.title ?? null,
        description: advisory.title ?? null,
        vulnerabilities: [{
          package: { ecosystem: 'npm', name: packageName },
          vulnerable_version_range: advisory.vulnerable_versions ?? null,
          first_patched_version: advisory.patched_versions ?? null
        }],
        cvss: advisory.cvss ?? {},
        cwes: (advisory.cwe ?? []).map((value) => ({ cwe_id: value })),
        references: advisory.url ? [{ url: advisory.url }] : [],
        published_at: null,
        updated_at: null,
        npm_audit: advisory,
        purl: npmPurl(packageName)
      };
      const rawIndexId = await writeRecord(client, ctx, {
        externalKey: `${packageName}/${ghsa}`,
        externalId: ghsa,
        sourceUrl: advisory.url ?? 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk',
        identifiers: [ghsa, ...ids],
        recordHash: sha256(stableJson(item)),
        payload: item
      });
      await upsertNpmAdvisory(client, rawIndexId, item);
      count++;
    }
    if (count >= max) break;
  }

  return {
    fetchedCount: count,
    parsedCount: count,
    checkpoint: { packages: auditPayload, lastFetched: new Date().toISOString() }
  };
}

function parseSpec(spec) {
  const at = spec.lastIndexOf('@');
  if (at > 0) return { name: spec.slice(0, at), version: spec.slice(at + 1) };
  return { name: spec, version: null };
}
