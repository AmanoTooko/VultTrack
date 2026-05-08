import { getEnv, getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertEcosystemAdvisory } from '../lib/staging.mjs';
import { extractIdentifiers, firstUrl, mavenPurl } from '../lib/advisory.mjs';

export const sourceCode = 'maven-advisory';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const components = getEnv('MAVEN_COMPONENTS', 'org.apache.logging.log4j:log4j-core@2.14.1,org.springframework:spring-core@5.3.17')
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
    .map(parseCoordinate);

  const ossUser = process.env.OSS_INDEX_USERNAME;
  const ossToken = process.env.OSS_INDEX_TOKEN ?? process.env.OSS_INDEX_PASSWORD;
  const provider = ossUser && ossToken ? 'sonatype-oss-index' : 'osv-maven-query';
  const reports = ossUser && ossToken
    ? await fetchOssIndex(components, ossUser, ossToken)
    : await fetchOsvBatch(components);

  let count = 0;
  for (const report of reports) {
    for (const vulnerability of report.vulnerabilities ?? []) {
      if (count >= max) break;
      const ids = extractIdentifiers(vulnerability.id, vulnerability.title, vulnerability.description, ...(vulnerability.aliases ?? []), ...(vulnerability.cves ?? []));
      const advisoryId = ids[0] ?? vulnerability.id ?? `${report.coordinates}:${sha256(stableJson(vulnerability)).slice(0, 12)}`;
      const payload = { provider, component: report.component, coordinates: report.coordinates, vulnerability };
      const rawIndexId = await writeRecord(client, ctx, {
        externalKey: `${report.coordinates}/${advisoryId}`,
        externalId: advisoryId,
        sourceUrl: firstUrl(vulnerability.references?.[0]) ?? vulnerability.reference ?? `https://osv.dev/vulnerability/${advisoryId}`,
        identifiers: ids,
        recordHash: sha256(stableJson(payload)),
        payload
      });
      await upsertEcosystemAdvisory(client, rawIndexId, {
        provider,
        ecosystem: 'maven',
        advisoryId,
        identifiers: ids,
        packageName: `${report.component.groupId}:${report.component.artifactId}`,
        purl: mavenPurl(report.component.groupId, report.component.artifactId, report.component.version),
        vulnerableRanges: vulnerability.vulnerableRanges ?? [],
        severityLabel: vulnerability.severityLabel ?? null,
        cvss: vulnerability.cvss ?? {},
        references: normalizeReferences(vulnerability),
        publishedAt: vulnerability.published ?? null,
        modifiedAt: vulnerability.modified ?? null,
        payload
      });
      count++;
    }
    if (count >= max) break;
  }

  return {
    fetchedCount: count,
    parsedCount: count,
    checkpoint: { provider, components: components.map((x) => x.raw), lastFetched: new Date().toISOString() }
  };
}

async function fetchOssIndex(components, username, token) {
  const coordinates = components.map((x) => mavenPurl(x.groupId, x.artifactId, x.version));
  const res = await fetch('https://ossindex.sonatype.org/api/v3/component-report', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'accept': 'application/json',
      'authorization': `Basic ${Buffer.from(`${username}:${token}`).toString('base64')}`,
      'user-agent': 'VulTrack/0.1'
    },
    body: JSON.stringify({ coordinates })
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status} for Sonatype OSS Index: ${text.slice(0, 500)}`);
  }
  const data = await res.json();
  return data.map((item, index) => ({
    component: components[index],
    coordinates: item.coordinates ?? coordinates[index],
    vulnerabilities: (item.vulnerabilities ?? []).map((v) => ({
      id: v.id,
      title: v.title,
      description: v.description,
      cvss: { score: v.cvssScore, vectorString: v.cvssVector },
      references: v.reference ? [{ url: v.reference }] : []
    }))
  }));
}

async function fetchOsvBatch(components) {
  const queries = components.map((x) => ({
    version: x.version,
    package: { ecosystem: 'Maven', name: `${x.groupId}:${x.artifactId}` }
  }));
  const res = await fetch('https://api.osv.dev/v1/querybatch', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'user-agent': 'VulTrack/0.1' },
    body: JSON.stringify({ queries })
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} for OSV Maven querybatch`);
  const batch = await res.json();
  const reports = [];
  for (let i = 0; i < components.length; i++) {
    const component = components[i];
    const summaries = batch.results?.[i]?.vulns ?? [];
    const vulnerabilities = [];
    for (const summary of summaries) {
      const detail = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(summary.id)}`, {
        headers: { 'user-agent': 'VulTrack/0.1' }
      });
      vulnerabilities.push(detail.ok ? await detail.json() : summary);
    }
    reports.push({ component, coordinates: mavenPurl(component.groupId, component.artifactId, component.version), vulnerabilities });
  }
  return reports;
}

function parseCoordinate(raw) {
  const [name, version = null] = raw.split('@');
  const [groupId, artifactId] = name.split(':');
  if (!groupId || !artifactId) throw new Error(`Invalid Maven coordinate: ${raw}`);
  return { raw, groupId, artifactId, version };
}

function normalizeReferences(vulnerability) {
  return (vulnerability.references ?? [])
    .map((ref) => typeof ref === 'string' ? { url: ref } : ref)
    .filter((ref) => ref?.url);
}
