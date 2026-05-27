import fs from 'node:fs/promises';
import path from 'node:path';
import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeArtifact, writeRecord } from '../lib/db.mjs';
import { upsertExploitPoc } from '../lib/staging.mjs';
import { classifyExploitType, ensureGitMirror, githubHeaders, identifiersFromText, maturityFor, walkFiles } from '../lib/exploit-utils.mjs';

export const sourceCode = 'poc-in-github';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const mirror = await ensureGitMirror(sourceCode, 'https://github.com/nomi-sec/PoC-in-GitHub.git', 'master');
  const files = await walkFiles(
    mirror.dir,
    (file) => /\/20\d{2}\/CVE-\d{4}-\d+\.json$/i.test(file),
    max * 4
  );

  let count = 0;
  for (const file of files) {
    if (count >= max) break;
    const body = await fs.readFile(file, 'utf8');
    let repos;
    try {
      repos = JSON.parse(body);
    } catch {
      continue;
    }
    const cve = path.basename(file, '.json').toUpperCase();
    for (const repo of Array.isArray(repos) ? repos : []) {
      if (count >= max) break;
      const identifiers = identifiersFromText(cve, repo.name, repo.full_name, repo.description);
      if (!identifiers.length || !repo.full_name) continue;
      const artifact = await archiveGithubRepoMetadata(client, ctx, cve, repo);
      const item = {
        provider: 'poc-in-github',
        sourceKey: `${cve}:${repo.full_name}`,
        identifiers,
        title: repo.description || repo.full_name,
        sourceUrl: repo.html_url,
        artifactUrl: repo.html_url,
        artifactObjectId: artifact.objectId,
        artifactSha256: artifact.sha256,
        artifactType: 'github_repository',
        exploitType: classifyExploitType(repo.name, repo.description),
        maturity: maturityFor('poc-in-github', false),
        verificationStatus: 'unreviewed',
        language: null,
        platform: null,
        author: repo.owner?.login ?? null,
        publishedAt: repo.created_at ?? null,
        modifiedAt: repo.pushed_at ?? repo.updated_at ?? null,
        tags: ['github-poc', repo.fork ? 'fork' : 'source'].filter(Boolean),
        payload: repo
      };
      const rawIndexId = await writeRecord(client, ctx, {
        externalKey: item.sourceKey,
        externalId: item.sourceKey,
        sourceUrl: item.sourceUrl,
        publishedAt: item.publishedAt,
        modifiedAt: item.modifiedAt,
        identifiers,
        recordHash: sha256(stableJson({ repo, artifactSha256: item.artifactSha256, revision: mirror.revision })),
        payload: item
      });
      await upsertExploitPoc(client, rawIndexId, item);
      count++;
    }
  }

  return { fetchedCount: count, parsedCount: count, checkpoint: { gitRevision: mirror.revision, lastFetched: new Date().toISOString() } };
}

async function archiveGithubRepoMetadata(client, ctx, cve, repo) {
  if (process.env.FETCHER_ARCHIVE_GITHUB_REPOS === '1') {
    const archive = await tryDownloadArchive(repo.full_name);
    if (archive) {
      return await writeArtifact(client, ctx, {
        externalKey: `${cve}-${repo.full_name}`,
        filename: `${repo.full_name}.zip`,
        body: archive,
        contentType: 'application/zip',
        schemaHint: 'github-repository-archive',
        compressedExtension: '.zip.gz'
      });
    }
  }

  return await writeArtifact(client, ctx, {
    externalKey: `${cve}-${repo.full_name}`,
    filename: `${repo.full_name}.json`,
    body: JSON.stringify(repo, null, 2),
    contentType: 'application/json',
    schemaHint: 'github-poc-metadata'
  });
}

async function tryDownloadArchive(fullName) {
  const maxBytes = getIntEnv('FETCHER_GITHUB_ARCHIVE_MAX_BYTES', 10 * 1024 * 1024);
  const repoResp = await fetch(`https://api.github.com/repos/${fullName}`, { headers: githubHeaders() });
  if (!repoResp.ok) return null;
  const repoInfo = await repoResp.json();
  const branch = repoInfo.default_branch || 'main';
  const archiveResp = await fetch(`https://github.com/${fullName}/archive/refs/heads/${encodeURIComponent(branch)}.zip`, {
    headers: { 'user-agent': 'VulTrack/0.1' }
  });
  if (!archiveResp.ok) return null;
  const len = Number(archiveResp.headers.get('content-length') || 0);
  if (len && len > maxBytes) return null;
  const buf = Buffer.from(await archiveResp.arrayBuffer());
  return buf.length <= maxBytes ? buf : null;
}
