import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fetchBuffer } from '../lib/http.mjs';
import { getRootPath } from '../lib/env.mjs';
import { sha256 } from '../lib/hash.mjs';

export const sourceCode = 'first-epss';
const EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';
const SNAPSHOT_VERSION = 1;

export async function run(client, ctx) {
  return runEpssSnapshot(client, ctx, { fetchGzip: fetchBuffer });
}

// DuckDB-primary deployments deliberately keep FIRST's original gzip CSV as
// the batch input. The C# side validates and merges it in one DuckDB
// transaction, then advances the checkpoint. Do not turn this into JSON rows.
export async function runEpssSnapshot(_client, ctx, { fetchGzip = fetchBuffer } = {}) {
  const gz = await fetchGzip(EPSS_URL);
  if (!Buffer.isBuffer(gz) || gz.length === 0) throw new Error('FIRST EPSS returned an empty gzip payload');

  const contentHash = sha256(gz);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  if (checkpoint.contentHash === contentHash && process.env.FETCHER_FORCE !== '1') {
    console.error('FIRST EPSS data unchanged, skipping.');
    return { fetchedCount: 0, changedCount: 0, parsedCount: 0 };
  }

  const incoming = incomingPath();
  await fs.mkdir(incoming, { recursive: true });
  if (await hasPendingSnapshot(incoming, contentHash)) {
    console.error('FIRST EPSS snapshot is already pending DuckDB commit, skipping duplicate download.');
    return { fetchedCount: 0, changedCount: 0, parsedCount: 0 };
  }

  const observedAt = new Date().toISOString();
  const runId = String(ctx.run?.id ?? crypto.randomUUID());
  const base = `${sourceCode}-${safeFilePart(runId)}`;
  const csvPartial = path.join(incoming, `${base}.epss.csv.gz.partial`);
  const csvReady = path.join(incoming, `${base}.epss.csv.gz.ready`);
  const manifestPartial = path.join(incoming, `${base}.epss.json.partial`);
  const manifestReady = path.join(incoming, `${base}.epss.json.ready`);
  const manifest = {
    schemaVersion: SNAPSHOT_VERSION,
    sourceCode,
    runId,
    observedAt,
    contentHash,
    bytes: gz.length,
    sourceUrl: EPSS_URL
  };

  try {
    await fs.writeFile(csvPartial, gz, { flag: 'wx' });
    await fs.writeFile(manifestPartial, `${JSON.stringify(manifest)}\n`, { flag: 'wx' });
    // The manifest is published last: its presence is the consumer's atomic
    // signal that the matching gzip has been fully written.
    await fs.rename(csvPartial, csvReady);
    await fs.rename(manifestPartial, manifestReady);
  } catch (error) {
    await Promise.all([csvPartial, csvReady, manifestPartial, manifestReady]
      .map((file) => fs.rm(file, { force: true }).catch(() => {})));
    throw error;
  }

  // No checkpoint here. The normalizer advances it only after DuckDB commits.
  return { fetchedCount: 1, changedCount: 1, parsedCount: 0 };
}

async function hasPendingSnapshot(incoming, contentHash) {
  const files = await fs.readdir(incoming).catch((error) => {
    if (error.code === 'ENOENT') return [];
    throw error;
  });
  for (const file of files) {
    if (!file.startsWith(`${sourceCode}-`) || !file.endsWith('.epss.json.ready')) continue;
    try {
      const manifest = JSON.parse(await fs.readFile(path.join(incoming, file), 'utf8'));
      if (manifest?.contentHash === contentHash) return true;
    } catch {
      // Leave malformed manifests for the C# importer to report and retain.
    }
  }
  return false;
}

function incomingPath() {
  return getRootPath(process.env.VULTRACK_SPOOL_PATH ?? 'data/spool', 'incoming');
}

function safeFilePart(value) {
  return String(value).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 100);
}
