import { fetchJson } from '../lib/http.mjs';
import { getEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertRegistryPackage } from '../lib/staging.mjs';

export const sourceCode = 'npm-registry';

export async function run(client, ctx) {
  const packages = getEnv('NPM_PACKAGES', 'lodash,express,react').split(',').map((x) => x.trim()).filter(Boolean);
  let count = 0;
  for (const name of packages) {
    const item = await fetchJson(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
    const latest = item['dist-tags']?.latest;
    const latestMeta = latest ? item.versions?.[latest] : null;
    const repository = normalizeRepo(latestMeta?.repository ?? item.repository);
    const payload = {
      name,
      version: latest,
      purl: latest ? `pkg:npm/${encodeURIComponent(name)}@${latest}` : `pkg:npm/${encodeURIComponent(name)}`,
      repositoryUrl: repository,
      homepageUrl: latestMeta?.homepage ?? item.homepage ?? null,
      metadata: { description: item.description, distTags: item['dist-tags'] },
      payload: item
    };
    const rawIndexId = await writeRecord(client, ctx, {
      externalKey: name,
      externalId: name,
      sourceUrl: `https://www.npmjs.com/package/${name}`,
      identifiers: [`pkg:npm/${name}`],
      recordHash: sha256(stableJson(payload)),
      payload
    });
    await upsertRegistryPackage(client, rawIndexId, 'npm', 'npm', payload);
    count++;
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { count } };
}

function normalizeRepo(repo) {
  if (!repo) return null;
  const url = typeof repo === 'string' ? repo : repo.url;
  return url?.replace(/^git\+/, '').replace(/\.git$/, '') ?? null;
}
