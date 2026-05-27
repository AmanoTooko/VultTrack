import fs from 'node:fs/promises';
import path from 'node:path';
import YAML from 'yaml';
import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeArtifact, writeRecord } from '../lib/db.mjs';
import { upsertExploitPoc } from '../lib/staging.mjs';
import { classifyExploitType, ensureGitMirror, identifiersFromText, maturityFor, walkFiles } from '../lib/exploit-utils.mjs';

export const sourceCode = 'nuclei-templates';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const mirror = await ensureGitMirror(sourceCode, 'https://github.com/projectdiscovery/nuclei-templates.git', 'main');
  const files = await walkFiles(
    mirror.dir,
    (file) => /\.(ya?ml)$/i.test(file) && !file.includes('/.github/')
  );

  let count = 0;
  for (const file of files) {
    if (count >= max) break;
    const body = await fs.readFile(file, 'utf8');
    if (!/\bcve\b/i.test(body)) continue;
    let doc;
    try {
      doc = YAML.parse(body);
    } catch {
      continue;
    }
    const identifiers = identifiersFromText(
      doc?.id,
      doc?.info?.classification?.['cve-id'],
      doc?.info?.tags,
      body.slice(0, 3000)
    );
    if (!identifiers.length) continue;
    const tags = String(doc?.info?.tags ?? '').split(',').map((x) => x.trim()).filter(Boolean);
    const rel = path.relative(mirror.dir, file);
    const verified = Boolean(doc?.info?.metadata?.verified);
    const artifact = await writeArtifact(client, ctx, {
      externalKey: rel,
      filename: rel,
      body,
      contentType: 'application/yaml',
      schemaHint: 'nuclei-template'
    });
    const item = {
      provider: 'nuclei-templates',
      sourceKey: doc?.id || rel,
      identifiers,
      title: doc?.info?.name ?? doc?.id ?? rel,
      sourceUrl: `https://github.com/projectdiscovery/nuclei-templates/blob/main/${rel}`,
      artifactUrl: `https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/${rel}`,
      artifactObjectId: artifact.objectId,
      artifactSha256: artifact.sha256,
      artifactType: 'nuclei_template',
      exploitType: classifyExploitType(doc?.info?.name, doc?.info?.description, tags.join(' ')),
      maturity: maturityFor('nuclei-templates', verified),
      verificationStatus: verified ? 'source_verified' : 'template_reviewed',
      requiresAuth: tags.includes('authenticated') || /authenticated|requires auth/i.test(body),
      requiresUserInteraction: false,
      language: 'yaml',
      platform: doc?.info?.metadata?.product ?? null,
      author: Array.isArray(doc?.info?.author) ? doc.info.author.join(', ') : (doc?.info?.author ?? null),
      modifiedAt: new Date().toISOString(),
      tags,
      payload: { id: doc?.id, info: doc?.info, path: rel, gitRevision: mirror.revision }
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
