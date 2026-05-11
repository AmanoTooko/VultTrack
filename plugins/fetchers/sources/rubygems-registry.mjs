import { fetchJson } from '../lib/http.mjs';
import { getEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertRegistryPackage } from '../lib/staging.mjs';

export const sourceCode = 'rubygems-registry';

export async function run(client, ctx) {
  const packages = getEnv('RUBYGEMS_PACKAGES', '').split(',').map((x) => x.trim()).filter(Boolean);
  let count = 0;
  for (const name of packages) {
    const item = await fetchJson(`https://rubygems.org/api/v1/gems/${encodeURIComponent(name)}.json`);
    const payload = {
      name: item.name ?? name,
      version: item.version ?? null,
      purl: item.version ? `pkg:gem/${encodeURIComponent(name)}@${encodeURIComponent(item.version)}` : `pkg:gem/${encodeURIComponent(name)}`,
      repositoryUrl: item.source_code_uri ?? null,
      homepageUrl: item.homepage_uri ?? item.project_uri ?? null,
      metadata: { info: item.info, licenses: item.licenses, bugTrackerUri: item.bug_tracker_uri },
      payload: item
    };
    const rawIndexId = await writeRecord(client, ctx, {
      externalKey: name,
      externalId: name,
      sourceUrl: item.project_uri ?? `https://rubygems.org/gems/${encodeURIComponent(name)}`,
      identifiers: [payload.purl],
      recordHash: sha256(stableJson(payload)),
      payload
    });
    await upsertRegistryPackage(client, rawIndexId, 'rubygems', 'gem', payload);
    count++;
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { count, lastFetched: new Date().toISOString() } };
}
