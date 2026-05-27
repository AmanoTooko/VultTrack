import fs from 'node:fs/promises';
import path from 'node:path';
import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeArtifact, writeRecord } from '../lib/db.mjs';
import { upsertExploitPoc } from '../lib/staging.mjs';
import { classifyExploitType, ensureGitMirror, identifiersFromText, languageFromPath, maturityFor, walkFiles } from '../lib/exploit-utils.mjs';

export const sourceCode = 'metasploit';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const mirror = await ensureGitMirror(sourceCode, 'https://github.com/rapid7/metasploit-framework.git', 'master');
  const files = await walkFiles(
    path.join(mirror.dir, 'modules'),
    (file) => file.endsWith('.rb') && /\/modules\/(exploits|auxiliary)\//.test(file),
    max * 4
  );

  let count = 0;
  for (const file of files) {
    if (count >= max) break;
    const body = await fs.readFile(file, 'utf8');
    const identifiers = identifiersFromText(body);
    if (!identifiers.length) continue;
    const rel = path.relative(mirror.dir, file);
    const title = extractRubyMeta(body, 'Name') ?? rel;
    const rank = body.match(/\bRank\s*=\s*([A-Za-z]+)Ranking/)?.[1] ?? null;
    const artifact = await writeArtifact(client, ctx, {
      externalKey: rel,
      filename: rel,
      body,
      contentType: 'text/x-ruby',
      schemaHint: 'metasploit-module'
    });
    const item = {
      provider: 'metasploit',
      sourceKey: rel,
      identifiers,
      title,
      sourceUrl: `https://github.com/rapid7/metasploit-framework/blob/master/${rel}`,
      artifactUrl: `https://raw.githubusercontent.com/rapid7/metasploit-framework/master/${rel}`,
      artifactObjectId: artifact.objectId,
      artifactSha256: artifact.sha256,
      artifactType: 'metasploit_module',
      exploitType: classifyExploitType(rel, title, body.slice(0, 4000)),
      maturity: maturityFor('metasploit', true),
      verificationStatus: 'framework_module',
      language: languageFromPath(file),
      platform: platformFromPath(rel),
      author: extractRubyAuthor(body),
      modifiedAt: new Date().toISOString(),
      tags: ['metasploit', rank].filter(Boolean),
      payload: { path: rel, rank, gitRevision: mirror.revision, name: title }
    };
    const rawIndexId = await writeRecord(client, ctx, {
      externalKey: item.sourceKey,
      externalId: item.sourceKey,
      sourceUrl: item.sourceUrl,
      modifiedAt: item.modifiedAt,
      identifiers,
      recordHash: sha256(stableJson({ sourceKey: item.sourceKey, artifactSha256: item.artifactSha256, revision: mirror.revision })),
      payload: item
    });
    await upsertExploitPoc(client, rawIndexId, item);
    count++;
  }

  return { fetchedCount: count, parsedCount: count, checkpoint: { gitRevision: mirror.revision, lastFetched: new Date().toISOString() } };
}

function extractRubyMeta(body, key) {
  const re = new RegExp(`['"]${key}['"]\\s*=>\\s*['"]([^'"]+)['"]`, 'i');
  return body.match(re)?.[1] ?? null;
}

function extractRubyAuthor(body) {
  const block = body.match(/['"]Author['"]\s*=>\s*(\[[\s\S]*?\]|['"][^'"]+['"])/i)?.[1];
  if (!block) return null;
  return [...block.matchAll(/['"]([^'"]+)['"]/g)].map((m) => m[1]).join(', ') || null;
}

function platformFromPath(rel) {
  const parts = rel.split('/');
  return parts.length > 2 ? parts[2] : null;
}
