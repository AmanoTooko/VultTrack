import { fetchJson } from '../lib/http.mjs';
import { getEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { mavenPurl } from '../lib/advisory.mjs';

export const sourceCode = 'maven-registry';

export async function run(client, ctx) {
  const coordinates = getEnv('MAVEN_COMPONENTS', '')
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
    .map(parseCoordinate);

  let count = 0;
  for (const coord of coordinates) {
    const q = `g:"${coord.groupId}" AND a:"${coord.artifactId}"`;
    const data = await fetchJson(`https://search.maven.org/solrsearch/select?q=${encodeURIComponent(q)}&rows=1&wt=json`);
    const doc = data.response?.docs?.[0] ?? {};
    const version = coord.version ?? doc.latestVersion ?? null;
    const payload = {
      namespace: coord.groupId,
      name: coord.artifactId,
      version,
      purl: mavenPurl(coord.groupId, coord.artifactId, version),
      repositoryUrl: null,
      homepageUrl: null,
      metadata: doc,
      payload: data
    };
    await writeRecord(client, ctx, {
      externalKey: `${coord.groupId}:${coord.artifactId}`,
      externalId: `${coord.groupId}:${coord.artifactId}`,
      sourceUrl: `https://search.maven.org/artifact/${coord.groupId}/${coord.artifactId}/${version ?? ''}/jar`,
      identifiers: [payload.purl],
      recordHash: sha256(stableJson(payload)),
      payload
    });
    count++;
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { count, lastFetched: new Date().toISOString() } };
}

function parseCoordinate(raw) {
  const [name, version = null] = raw.split('@');
  const [groupId, artifactId] = name.split(':');
  if (!groupId || !artifactId) throw new Error(`Invalid Maven coordinate: ${raw}`);
  return { groupId, artifactId, version };
}
