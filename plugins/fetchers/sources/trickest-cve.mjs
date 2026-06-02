import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeArtifact, writeRecord } from '../lib/db.mjs';
import { upsertExploitPoc } from '../lib/staging.mjs';
import { classifyExploitType, githubHeaders, maturityFor } from '../lib/exploit-utils.mjs';

export const sourceCode = 'trickest-cve';
export const runMode = 'manual';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const years = yearsDescending();
  let count = 0;
  for (const year of years) {
    const entries = await listYear(year).catch(() => []);
    for (const entry of entries.filter((x) => trickestCveFromFilename(x.name))) {
      if (count >= max) break;
      const body = await fetchText(entry.download_url);
      const cve = trickestCveFromFilename(entry.name);
      const identifiers = [cve];
      const rel = `${year}/${entry.name}`;
      const title = body.match(/^###\s+\[?([^\]\n]+)\]?/m)?.[1]?.trim() ?? cve;
      const githubLinks = [...body.matchAll(/https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+/g)].map((m) => m[0]);
      const artifact = await writeArtifact(client, ctx, {
        externalKey: cve,
        filename: rel,
        body,
        contentType: 'text/markdown',
        schemaHint: 'trickest-cve-markdown'
      });
      const item = {
        provider: 'trickest-cve',
        sourceKey: cve,
        identifiers,
        title,
        sourceUrl: entry.html_url,
        artifactUrl: entry.download_url,
        artifactObjectId: artifact.objectId,
        artifactSha256: artifact.sha256,
        artifactType: 'poc_index',
        exploitType: classifyExploitType(title, body.slice(0, 4000)),
        maturity: maturityFor('trickest-cve', false),
        verificationStatus: 'unreviewed',
        language: 'markdown',
        platform: null,
        author: 'trickest',
        modifiedAt: new Date().toISOString(),
        tags: ['github-poc-index'],
        payload: { path: rel, githubLinks: [...new Set(githubLinks)].slice(0, 200) }
      };
      const rawIndexId = await writeRecord(client, ctx, {
        externalKey: item.sourceKey,
        externalId: item.sourceKey,
        sourceUrl: item.sourceUrl,
        modifiedAt: item.modifiedAt,
        identifiers,
        recordHash: sha256(stableJson({ sourceKey: item.sourceKey, artifactSha256: item.artifactSha256 })),
        payload: item
      });
      await upsertExploitPoc(client, rawIndexId, item);
      count++;
    }
    if (count >= max) break;
  }

  return { fetchedCount: count, parsedCount: count, checkpoint: { lastFetched: new Date().toISOString() } };
}

export function trickestCveFromFilename(filename) {
  return String(filename).match(/^(CVE-\d{4}-\d+)\.md$/i)?.[1]?.toUpperCase() ?? null;
}

function yearsDescending() {
  const current = new Date().getUTCFullYear();
  const years = [];
  for (let year = current; year >= 1999; year--) years.push(String(year));
  return years;
}

async function listYear(year) {
  const resp = await fetch(`https://api.github.com/repos/trickest/cve/contents/${year}?ref=main`, { headers: githubHeaders() });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} for trickest/cve ${year}`);
  return await resp.json();
}

async function fetchText(url) {
  const resp = await fetch(url, { headers: { 'user-agent': 'VulTrack/0.1' } });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} for ${url}`);
  return await resp.text();
}
