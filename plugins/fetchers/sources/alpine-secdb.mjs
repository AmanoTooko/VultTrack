import { getEnv, getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';

export const sourceCode = 'alpine-secdb';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const releases = getEnv('ALPINE_RELEASES', 'v3.22,v3.21,v3.20,v3.19,v3.18,edge').split(',');
  const repos = getEnv('ALPINE_REPOS', 'main,community').split(',');
  let count = 0;
  const hashes = {};

  for (const release of releases) {
    for (const repo of repos) {
      if (count >= max) break;
      const url = `https://secdb.alpinelinux.org/${release}/${repo}.json`;
      try {
        const resp = await fetch(url, { headers: { 'user-agent': 'VulTrack/0.1', 'accept': 'application/json' } });
        if (!resp.ok) continue;
        const text = await resp.text();
        const h = sha256(Buffer.from(text));
        hashes[`${release}/${repo}`] = h;
        // Skip if this release/repo unchanged
        if (checkpoint.hashes?.[`${release}/${repo}`] === h) {
          continue;
        }
        const data = JSON.parse(text);
        for (const pkg of data.packages ?? []) {
          if (count >= max) break;
          const secfixes = pkg.pkg?.secfixes ?? pkg.secfixes ?? {};
          const identifiers = [...new Set(Object.values(secfixes).flatMap((x) => Array.isArray(x) ? x : []))].filter(Boolean);
          const name = pkg.pkg?.name ?? pkg.name;
          const payload = { release, repo, pkg };
          await writeRecord(client, ctx, {
            externalKey: `${release}/${repo}/${name}`,
            externalId: name,
            sourceUrl: url,
            identifiers,
            recordHash: sha256(stableJson(payload)),
            payload
          });
          count++;
        }
      } catch { continue; }
    }
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { hashes, lastFetched: new Date().toISOString() } };
}
