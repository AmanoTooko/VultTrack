import { fetchJson } from '../lib/http.mjs';
import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertEcosystemAdvisory } from '../lib/staging.mjs';
import { advisoryIdFromUrl, extractIdentifiers, nugetSeverityLabel } from '../lib/advisory.mjs';

export const sourceCode = 'nuget-advisory';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const serviceIndex = await fetchJson('https://api.nuget.org/v3/index.json');
  const resource = (serviceIndex.resources ?? []).find((x) => String(x['@type'] ?? '').startsWith('VulnerabilityInfo/'));
  if (!resource?.['@id']) throw new Error('NuGet VulnerabilityInfo resource not found');

  const vulnerabilityIndex = await fetchJson(resource['@id']);
  const indexHash = sha256(stableJson(vulnerabilityIndex));
  const checkpoint = ctx.source.checkpoint_json ?? {};
  if (checkpoint.indexHash === indexHash && !process.env.FETCHER_FORCE) {
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { indexHash, skipped: true } };
  }

  let count = 0;
  let latestUpdated = checkpoint.latestUpdated ?? null;
  for (const page of vulnerabilityIndex) {
    if (count >= max) break;
    if (page['@updated'] && (!latestUpdated || page['@updated'] > latestUpdated)) latestUpdated = page['@updated'];
    const data = await fetchJson(page['@id']);
    for (const [packageName, advisories] of Object.entries(data)) {
      for (const advisory of advisories ?? []) {
        if (count >= max) break;
        const ids = extractIdentifiers(advisory.url);
        const advisoryId = advisoryIdFromUrl(advisory.url, `NUGET-${sha256(stableJson({ packageName, advisory })).slice(0, 12)}`);
        const payload = { packageName, advisory, sourcePage: page };
        const rawIndexId = await writeRecord(client, ctx, {
          externalKey: `${packageName}/${advisoryId}/${advisory.versions}`,
          externalId: advisoryId,
          sourceUrl: advisory.url,
          identifiers: ids,
          recordHash: sha256(stableJson(payload)),
          payload
        });
        await upsertEcosystemAdvisory(client, rawIndexId, {
          provider: 'nuget-vulnerability-info',
          ecosystem: 'nuget',
          advisoryId,
          identifiers: ids,
          packageName,
          purl: `pkg:nuget/${encodeURIComponent(packageName)}`,
          vulnerableRanges: [advisory.versions].filter(Boolean),
          severityLabel: nugetSeverityLabel(advisory.severity),
          references: advisory.url ? [{ url: advisory.url }] : [],
          modifiedAt: page['@updated'] ?? null,
          payload
        });
        count++;
      }
      if (count >= max) break;
    }
  }

  return {
    fetchedCount: count,
    parsedCount: count,
    checkpoint: { indexHash, latestUpdated, lastFetched: new Date().toISOString() }
  };
}
