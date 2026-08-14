import { fetchJson } from '../lib/http.mjs';
import { getEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';

export const sourceCode = 'crates-registry';

export async function run(client, ctx) {
  const packages = getEnv('CRATES_PACKAGES', '').split(',').map((x) => x.trim()).filter(Boolean);
  let count = 0;
  for (const name of packages) {
    const item = await fetchJson(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}`);
    const crate = item.crate ?? {};
    const version = crate.max_stable_version ?? crate.newest_version ?? null;
    const payload = {
      name,
      version,
      purl: version ? `pkg:cargo/${encodeURIComponent(name)}@${encodeURIComponent(version)}` : `pkg:cargo/${encodeURIComponent(name)}`,
      repositoryUrl: crate.repository ?? null,
      homepageUrl: crate.homepage ?? null,
      metadata: { description: crate.description, license: crate.license, downloads: crate.downloads },
      payload: item
    };
    await writeRecord(client, ctx, {
      externalKey: name,
      externalId: name,
      sourceUrl: `https://crates.io/crates/${encodeURIComponent(name)}`,
      identifiers: [payload.purl],
      recordHash: sha256(stableJson(payload)),
      payload
    });
    count++;
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { count, lastFetched: new Date().toISOString() } };
}
