import { fetchJson } from '../lib/http.mjs';
import { getEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertRegistryPackage } from '../lib/staging.mjs';

export const sourceCode = 'nuget-registry';

export async function run(client, ctx) {
  const packages = getEnv('NUGET_PACKAGES', '').split(',').map((x) => x.trim()).filter(Boolean);
  let count = 0;
  for (const name of packages) {
    const lower = name.toLowerCase();
    const versions = await fetchJson(`https://api.nuget.org/v3-flatcontainer/${encodeURIComponent(lower)}/index.json`);
    const latest = versions.versions?.at(-1) ?? null;
    const registration = await fetchJson(`https://api.nuget.org/v3/registration5-semver1/${encodeURIComponent(lower)}/index.json`);
    const catalogEntry = findCatalogEntry(registration, latest);
    const payload = {
      name,
      version: latest,
      purl: latest ? `pkg:nuget/${encodeURIComponent(name)}@${encodeURIComponent(latest)}` : `pkg:nuget/${encodeURIComponent(name)}`,
      repositoryUrl: catalogEntry?.repository ?? null,
      homepageUrl: catalogEntry?.projectUrl ?? null,
      metadata: { description: catalogEntry?.description, authors: catalogEntry?.authors },
      payload: { versions, registration }
    };
    const rawIndexId = await writeRecord(client, ctx, {
      externalKey: lower,
      externalId: name,
      sourceUrl: `https://www.nuget.org/packages/${encodeURIComponent(name)}`,
      identifiers: [payload.purl],
      recordHash: sha256(stableJson(payload)),
      payload
    });
    await upsertRegistryPackage(client, rawIndexId, 'nuget', 'nuget', payload);
    count++;
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { count, lastFetched: new Date().toISOString() } };
}

function findCatalogEntry(registration, version) {
  for (const page of registration.items ?? []) {
    for (const item of page.items ?? []) {
      if (!version || item.catalogEntry?.version?.toLowerCase() === version.toLowerCase()) {
        return item.catalogEntry;
      }
    }
  }
  return registration.items?.[0]?.items?.[0]?.catalogEntry ?? null;
}
