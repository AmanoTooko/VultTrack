import { fetchJson } from '../lib/http.mjs';
import { getEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertRegistryPackage } from '../lib/staging.mjs';

export const sourceCode = 'packagist-registry';

export async function run(client, ctx) {
  const packages = getEnv('PACKAGIST_PACKAGES', '').split(',').map((x) => x.trim()).filter(Boolean);
  let count = 0;
  for (const name of packages) {
    const item = await fetchJson(`https://repo.packagist.org/p2/${encodeURIComponent(name)}.json`);
    const versions = item.packages?.[name] ?? [];
    const latest = versions[0] ?? {};
    const [namespace, packageName] = name.split('/');
    const payload = {
      namespace,
      name: packageName ?? name,
      version: latest.version ?? null,
      purl: latest.version ? `pkg:composer/${encodeURIComponent(name)}@${encodeURIComponent(latest.version)}` : `pkg:composer/${encodeURIComponent(name)}`,
      repositoryUrl: latest.source?.url ?? null,
      homepageUrl: latest.homepage ?? null,
      metadata: { description: latest.description, license: latest.license },
      payload: item
    };
    const rawIndexId = await writeRecord(client, ctx, {
      externalKey: name,
      externalId: name,
      sourceUrl: `https://packagist.org/packages/${name}`,
      identifiers: [payload.purl],
      recordHash: sha256(stableJson(payload)),
      payload
    });
    await upsertRegistryPackage(client, rawIndexId, 'packagist', 'composer', payload);
    count++;
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { count, lastFetched: new Date().toISOString() } };
}
