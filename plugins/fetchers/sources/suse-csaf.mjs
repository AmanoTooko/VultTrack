import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fetchJson, fetchText } from '../lib/http.mjs';
import { getIntEnv, getRootPath } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
import { upsertEcosystemAdvisory } from '../lib/staging.mjs';
import { extractIdentifiers } from '../lib/advisory.mjs';

export const sourceCode = 'suse-csaf';

const BASE_URL = 'https://ftp.suse.com/pub/projects/security/csaf';
const ARCHIVE_URL = 'https://ftp.suse.com/pub/projects/security/csaf.tar.bz2';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const fetchConcurrency = Math.max(1, getIntEnv('CSAF_FETCH_CONCURRENCY', 8));
  const checkpoint = ctx.source.checkpoint_json ?? {};
  if (max === Number.MAX_SAFE_INTEGER) {
    return runArchiveImport(client, ctx, checkpoint);
  }

  const indexText = await fetchText(`${BASE_URL}/index.txt`);
  const indexHash = sha256(Buffer.from(indexText));
  if (checkpoint.indexHash === indexHash && !process.env.FETCHER_FORCE) {
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { indexHash, skipped: true } };
  }

  const entries = indexText.split(/\r?\n/).map((x) => x.trim()).filter((x) => x.endsWith('.json'));
  let count = 0;
  for (let offset = 0; offset < entries.length && count < max; offset += fetchConcurrency) {
    const batch = entries.slice(offset, offset + fetchConcurrency);
    const items = await Promise.all(batch.map(async (entry) => ({
      entry,
      item: await fetchJson(`${BASE_URL}/${entry}`).catch(() => null)
    })));
    for (const { entry, item } of items) {
      if (count >= max) break;
      if (!item) continue;
      const url = `${BASE_URL}/${entry}`;
      await writeSuseItem(client, ctx, item, url, entry.replace(/\.json$/, ''));
      count++;
    }
  }

  return { fetchedCount: count, parsedCount: count, checkpoint: { indexHash, lastFetched: new Date().toISOString() } };
}

async function runArchiveImport(client, ctx, checkpoint) {
  const mirrorDir = getRootPath('data/mirrors');
  await fs.mkdir(mirrorDir, { recursive: true });
  const archive = path.join(mirrorDir, 'suse-csaf.tar.bz2');
  const timeoutMs = getIntEnv('FETCHER_TIMEOUT_MS', 600000);
  const download = spawnSync('curl', ['-fL', '--retry', '3', '--retry-delay', '2', '-o', archive, ARCHIVE_URL], {
    encoding: 'utf8',
    timeout: timeoutMs
  });
  if (download.status !== 0) throw new Error(`Failed to download SUSE CSAF archive: ${download.stderr}`);

  const archiveHash = sha256(await fs.readFile(archive));
  if (checkpoint.archiveHash === archiveHash && !process.env.FETCHER_FORCE) {
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { archiveHash, skipped: true } };
  }

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-suse-csaf-'));
  try {
    const result = spawnSync('tar', ['-xjf', archive, '-C', tmpDir], { stdio: 'pipe' });
    if (result.status !== 0) throw new Error(`Failed to extract SUSE CSAF archive: ${result.stderr.toString()}`);
    const files = [];
    await walk(tmpDir, files);
    let count = 0;
    for (const file of files) {
      const item = JSON.parse(await fs.readFile(file, 'utf8'));
      const entry = path.basename(file, '.json');
      await writeSuseItem(client, ctx, item, `${BASE_URL}/${path.basename(file)}`, entry);
      count++;
    }
    return { fetchedCount: count, parsedCount: count, checkpoint: { archiveHash, lastFetched: new Date().toISOString() } };
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
}

async function walk(dir, files) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) await walk(full, files);
    else if (entry.isFile() && entry.name.endsWith('.json')) files.push(full);
  }
}

function parseCpeToProductName(cpe) {
  if (!cpe || typeof cpe !== 'string') return null;
  const parts = cpe.split(':');
  if (parts.length < 5) return null;
  const vendor = parts[3] || '';
  const product = parts[4] || '';
  if (!product) return null;
  return vendor && vendor !== '*' ? `${vendor}/${product}` : product;
}

function extractCvssFromScores(scores) {
  if (!Array.isArray(scores)) return null;
  for (const entry of scores) {
    const cvss = entry?.cvss_v3 ?? entry?.cvss_v3_1 ?? entry?.cvss_v3_0 ?? entry?.cvss_v2;
    if (cvss) return cvss;
  }
  return null;
}

function extractAffectedProducts(vulnerabilities) {
  const products = [];
  for (const vuln of vulnerabilities ?? []) {
    const cve = vuln.cve ?? null;
    const affected = vuln.product_status?.known_affected ?? [];
    const cvss = extractCvssFromScores(vuln.scores);
    for (const cpe of affected) {
      const name = parseCpeToProductName(cpe);
      if (!name) continue;
      products.push({
        cve,
        packageName: name,
        ecosystem: 'rpm',
        cpe,
        severity: cvss?.baseSeverity ?? null,
        baseScore: cvss?.baseScore ?? null
      });
    }
  }
  return products;
}

async function writeSuseItem(client, ctx, item, url, fallbackId) {
  const doc = item.document ?? {};
  const tracking = doc.tracking ?? {};
  const advisoryId = tracking.id ?? fallbackId;
  const identifiers = [...new Set([advisoryId, ...extractIdentifiers(JSON.stringify(item.vulnerabilities ?? []), doc.title)])];
  const affectedProducts = extractAffectedProducts(item.vulnerabilities);
  const firstProduct = affectedProducts[0] ?? null;
  const severityLabel = firstProduct?.severity
    ?? item.vulnerabilities?.[0]?.scores?.[0]?.cvss_v3?.baseSeverity
    ?? null;

  const rawIndexId = await writeRecord(client, ctx, {
    externalKey: advisoryId,
    externalId: advisoryId,
    sourceUrl: url,
    publishedAt: tracking.initial_release_date ?? null,
    modifiedAt: tracking.current_release_date ?? null,
    identifiers,
    recordHash: sha256(stableJson(item)),
    payload: item
  });
  await upsertEcosystemAdvisory(client, rawIndexId, {
    provider: 'suse-csaf',
    ecosystem: 'rpm',
    advisoryId,
    identifiers,
    packageName: firstProduct?.packageName ?? null,
    purl: null,
    vulnerableRanges: [],
    severityLabel,
    references: [{ url }],
    publishedAt: tracking.initial_release_date ?? null,
    modifiedAt: tracking.current_release_date ?? null,
    payload: item,
    affectedProducts
  });
}
