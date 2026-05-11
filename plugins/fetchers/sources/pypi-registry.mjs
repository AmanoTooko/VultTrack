import { fetchJson } from '../lib/http.mjs';
import { getEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertRegistryPackage } from '../lib/staging.mjs';

export const sourceCode = 'pypi-registry';

export async function run(client, ctx) {
  const packages = getEnv('PYPI_PACKAGES', '').split(',').map((x) => x.trim()).filter(Boolean);
  let count = 0;
  for (const name of packages) {
    const item = await fetchJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
    const latest = item.info?.version ?? null;
    const payload = {
      name: item.info?.name ?? name,
      version: latest,
      purl: latest ? `pkg:pypi/${encodeURIComponent(name.toLowerCase())}@${encodeURIComponent(latest)}` : `pkg:pypi/${encodeURIComponent(name.toLowerCase())}`,
      repositoryUrl: item.info?.project_urls?.Source ?? item.info?.project_urls?.Repository ?? null,
      homepageUrl: item.info?.home_page || item.info?.project_url || null,
      metadata: { summary: item.info?.summary, projectUrls: item.info?.project_urls },
      payload: item
    };
    const rawIndexId = await writeRecord(client, ctx, {
      externalKey: name.toLowerCase(),
      externalId: name,
      sourceUrl: item.info?.project_url ?? `https://pypi.org/project/${encodeURIComponent(name)}/`,
      identifiers: [payload.purl],
      recordHash: sha256(stableJson(payload)),
      payload
    });
    await upsertRegistryPackage(client, rawIndexId, 'pypi', 'pypi', payload);
    count++;
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { count, lastFetched: new Date().toISOString() } };
}
