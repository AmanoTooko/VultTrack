import fs from 'node:fs/promises';
import path from 'node:path';
import YAML from 'yaml';
import { getIntEnv } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { classifyExploitType, ensureGitMirror, identifiersFromText, maturityFor, sanitizeUnicode, walkFiles } from '../lib/exploit-utils.mjs';

export const sourceCode = 'nuclei-templates';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const mirror = await ensureGitMirror(sourceCode, 'https://github.com/projectdiscovery/nuclei-templates.git', 'main');
  const completedRevision = checkpoint.completedGitRevision ??
    (checkpoint.snapshotComplete === false ? null : checkpoint.gitRevision);
  if (completedRevision === mirror.revision && !process.env.FETCHER_FORCE) {
    return {
      fetchedCount: 0,
      parsedCount: 0,
      checkpoint: {
        ...checkpoint,
        completedGitRevision: completedRevision,
        gitRevision: completedRevision,
        snapshotComplete: true,
        skipped: true,
        lastChecked: new Date().toISOString()
      }
    };
  }
  const files = await walkFiles(
    mirror.dir,
    (file) => /\.(ya?ml)$/i.test(file) && !file.includes('/.github/')
  );

  const templates = [];
  for (const file of files) {
    const body = await fs.readFile(file, 'utf8');
    if (!/\bcve\b/i.test(body)) continue;
    let doc;
    try {
      doc = YAML.parse(body);
    } catch {
      continue;
    }
    const identifiers = nucleiIdentifiers(doc);
    if (!identifiers.length) continue;
    const tags = String(doc?.info?.tags ?? '').split(',').map((x) => x.trim()).filter(Boolean);
    const rel = path.relative(mirror.dir, file);
    const verified = Boolean(doc?.info?.metadata?.verified);
    templates.push({ body, doc, identifiers, tags, rel, verified });
  }

  const plan = nucleiSnapshotPlan(checkpoint, mirror.revision, templates.length, max);
  if (!plan.snapshotComplete) {
    console.error(`[${sourceCode}] refusing incomplete revision ${mirror.revision}: ${templates.length} eligible templates (${plan.checkpoint.rejectedReason})`);
    return { fetchedCount: 0, parsedCount: templates.length, checkpoint: plan.checkpoint };
  }

  const fetchedAt = new Date().toISOString();
  for (const template of templates) {
    const artifact = { objectId: null, sha256: sha256(Buffer.from(template.body, 'utf8')) };
    const item = sanitizeUnicode({
      provider: 'nuclei-templates',
      sourceKey: template.doc?.id || template.rel,
      identifiers: template.identifiers,
      title: template.doc?.info?.name ?? template.doc?.id ?? template.rel,
      sourceUrl: `https://github.com/projectdiscovery/nuclei-templates/blob/main/${template.rel}`,
      artifactUrl: `https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/${template.rel}`,
      artifactObjectId: artifact.objectId,
      artifactSha256: artifact.sha256,
      artifactType: 'nuclei_template',
      exploitType: classifyExploitType(template.doc?.info?.name, template.doc?.info?.description, template.tags.join(' ')),
      maturity: maturityFor('nuclei-templates', template.verified),
      verificationStatus: template.verified ? 'source_verified' : 'template_reviewed',
      requiresAuth: template.tags.includes('authenticated') || /authenticated|requires auth/i.test(template.body),
      requiresUserInteraction: false,
      language: 'yaml',
      platform: template.doc?.info?.metadata?.product ?? null,
      author: Array.isArray(template.doc?.info?.author) ? template.doc.info.author.join(', ') : (template.doc?.info?.author ?? null),
      modifiedAt: fetchedAt,
      tags: template.tags,
      payload: { id: template.doc?.id, info: template.doc?.info, path: template.rel, gitRevision: mirror.revision }
    });
    await writeRecord(client, ctx, {
      externalKey: template.rel,
      externalId: item.sourceKey,
      sourceUrl: item.sourceUrl,
      modifiedAt: item.modifiedAt,
      identifiers: template.identifiers,
      snapshotId: mirror.revision,
      snapshotComplete: true,
      recordHash: sha256(stableJson({ sourceKey: item.sourceKey, artifactSha256: item.artifactSha256, revision: mirror.revision })),
      payload: item
    });
  }

  return { fetchedCount: templates.length, parsedCount: templates.length, checkpoint: plan.checkpoint };
}

export function nucleiSnapshotPlan(previousCheckpoint, revision, recordCount, maxRecords) {
  const observedAt = new Date().toISOString();
  const rejectedReason = recordCount <= 0
    ? 'empty_snapshot'
    : (recordCount > maxRecords ? 'max_records_exceeded' : null);
  if (rejectedReason) {
    return {
      snapshotComplete: false,
      checkpoint: {
        ...previousCheckpoint,
        snapshotComplete: false,
        observedGitRevision: revision,
        rejectedRecordCount: recordCount,
        rejectedReason,
        skipped: false,
        lastRejectedAt: observedAt
      }
    };
  }
  return {
    snapshotComplete: true,
    checkpoint: {
      ...previousCheckpoint,
      gitRevision: revision,
      completedGitRevision: revision,
      observedGitRevision: revision,
      snapshotComplete: true,
      skipped: false,
      lastFetched: observedAt,
      recordCount
    }
  };
}

export function nucleiIdentifiers(doc) {
  return identifiersFromText(doc?.id, doc?.info?.classification?.['cve-id']);
}
