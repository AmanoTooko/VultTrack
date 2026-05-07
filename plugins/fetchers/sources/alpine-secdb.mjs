import { fetchJson } from '../lib/http.mjs';
import { getEnv, getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertAlpine } from '../lib/staging.mjs';

export const sourceCode = 'alpine-secdb';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const releases = getEnv('ALPINE_RELEASES', 'v3.22,v3.21,v3.20,v3.19,v3.18,edge').split(',');
  const repos = getEnv('ALPINE_REPOS', 'main,community').split(',');
  let count = 0;
  for (const release of releases) {
    for (const repo of repos) {
      if (count >= max) break;
      const url = `https://secdb.alpinelinux.org/${release}/${repo}.json`;
      let data;
      try {
        data = await fetchJson(url);
      } catch {
        continue;
      }
      for (const pkg of data.packages ?? []) {
        if (count >= max) break;
        const secfixes = pkg.pkg?.secfixes ?? pkg.secfixes ?? {};
        const identifiers = [...new Set(Object.values(secfixes).flatMap((x) => Array.isArray(x) ? x : []))].filter(Boolean);
        const name = pkg.pkg?.name ?? pkg.name;
        const payload = { release, repo, pkg };
        const rawIndexId = await writeRecord(client, ctx, {
          externalKey: `${release}/${repo}/${name}`,
          externalId: name,
          sourceUrl: url,
          identifiers,
          recordHash: sha256(stableJson(payload)),
          payload
        });
        await upsertAlpine(client, rawIndexId, `${release}/${repo}`, pkg, identifiers, payload);
        count++;
      }
    }
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { count } };
}
