#!/usr/bin/env node
import fs from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import yauzl from 'yauzl';
import { sha256, stableJson } from '../plugins/fetchers/lib/hash.mjs';

const DEFAULT_ZIP = 'data/mirrors/osv-all.zip';
const DEFAULT_OUTPUT = 'data/osv-prefix-spool';

export async function feedOsvBulkPrefix(zipPath, outputDirectory, options) {
  const prefix = normalizePrefix(options?.prefix);
  const segmentSize = positiveInteger(options?.segmentSize, 5000);
  const archiveHash = await fileSha256(zipPath);
  const runId = `prefix-${safePart(prefix)}-${archiveHash.slice(0, 16)}`;
  const incoming = path.join(outputDirectory, 'incoming');
  await fs.mkdir(incoming, { recursive: true });

  const writer = createSegmentWriter(incoming, runId, segmentSize);
  const scan = await scanOsvPrefix(zipPath, prefix, async (item) => writer.add(item));
  const spool = await writer.finish();
  const manifest = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    archive: { path: path.resolve(zipPath), sha256: archiveHash },
    prefix,
    sourceCode: 'osv-init',
    sourceMode: 'append',
    scannedEntries: scan.scannedEntries,
    candidateEntries: scan.candidateEntries,
    selectedRecords: spool.records,
    segmentSize,
    segments: spool.files
  };
  const manifestPath = path.join(outputDirectory, 'manifest.json');
  await fs.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx' });
  return { manifestPath, manifest };
}

export async function feedOsvBulkIds(zipPath, outputDirectory, options) {
  const ids = normalizeIds(options?.ids);
  const segmentSize = positiveInteger(options?.segmentSize, 5000);
  const archiveHash = await fileSha256(zipPath);
  const runId = `ids-${archiveHash.slice(0, 16)}`;
  const incoming = path.join(outputDirectory, 'incoming');
  await fs.mkdir(incoming, { recursive: true });

  const writer = createSegmentWriter(incoming, runId, segmentSize);
  const remaining = new Set(ids);
  const scan = await scanOsvIds(zipPath, remaining, async (item) => {
    await writer.add(item);
    remaining.delete(normalizeId(item.id));
  });
  const spool = await writer.finish();
  const missingIds = [...remaining].sort();
  const manifest = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    archive: { path: path.resolve(zipPath), sha256: archiveHash },
    sourceCode: 'osv-init',
    sourceMode: 'append',
    requestedIds: ids.length,
    selectedRecords: spool.records,
    missingIds,
    scannedEntries: scan.scannedEntries,
    segmentSize,
    segments: spool.files
  };
  const manifestPath = path.join(outputDirectory, 'manifest.json');
  await fs.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx' });
  if (missingIds.length > 0)
    throw new Error(`OSV archive is missing ${missingIds.length} requested IDs; see ${manifestPath}`);
  return { manifestPath, manifest };
}

export async function writeOsvPrefixRecords(records, outputDirectory, options) {
  const prefix = normalizePrefix(options?.prefix);
  const segmentSize = positiveInteger(options?.segmentSize, 5000);
  const runId = options?.runId ?? `prefix-${safePart(prefix)}-fixture`;
  const incoming = path.join(outputDirectory, 'incoming');
  await fs.mkdir(incoming, { recursive: true });
  const writer = createSegmentWriter(incoming, runId, segmentSize);
  for (const item of records) {
    if (matchesPrefix(item?.id, prefix)) await writer.add(item);
  }
  return writer.finish();
}

export async function writeOsvIdRecords(records, outputDirectory, options) {
  const ids = normalizeIds(options?.ids);
  const requested = new Set(ids);
  const segmentSize = positiveInteger(options?.segmentSize, 5000);
  const runId = options?.runId ?? 'ids-fixture';
  const incoming = path.join(outputDirectory, 'incoming');
  await fs.mkdir(incoming, { recursive: true });
  const writer = createSegmentWriter(incoming, runId, segmentSize);
  for (const item of records) {
    const id = normalizeId(item?.id);
    if (!requested.has(id)) continue;
    await writer.add(item);
    requested.delete(id);
  }
  const result = await writer.finish();
  return { ...result, missingIds: [...requested].sort() };
}

async function scanOsvPrefix(zipPath, prefix, onItem) {
  const zip = await openZip(zipPath);
  let scannedEntries = 0;
  let candidateEntries = 0;
  try {
    await new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error) => {
        if (settled) return;
        settled = true;
        if (error) reject(error);
        else resolve();
      };
      zip.once('error', finish);
      zip.once('end', () => finish());
      zip.on('entry', async (entry) => {
        try {
          if (/\/$/.test(entry.fileName) || !entry.fileName.endsWith('.json')) {
            zip.readEntry();
            return;
          }
          scannedEntries++;
          if (!matchesPrefix(path.posix.basename(entry.fileName, '.json'), prefix)) {
            zip.readEntry();
            return;
          }
          candidateEntries++;
          const item = JSON.parse((await readZipEntry(zip, entry)).toString('utf8'));
          if (!matchesPrefix(item?.id, prefix))
            throw new Error(`OSV archive entry ${entry.fileName} does not match requested prefix ${prefix}`);
          await onItem(item);
          zip.readEntry();
        } catch (error) {
          zip.close();
          finish(error);
        }
      });
      zip.readEntry();
    });
  } finally {
    zip.close();
  }
  return { scannedEntries, candidateEntries };
}

async function scanOsvIds(zipPath, remaining, onItem) {
  const zip = await openZip(zipPath);
  let scannedEntries = 0;
  try {
    await new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error) => {
        if (settled) return;
        settled = true;
        if (error) reject(error);
        else resolve();
      };
      zip.once('error', finish);
      zip.once('end', () => finish());
      zip.on('entry', async (entry) => {
        try {
          if (/\/$/.test(entry.fileName) || !entry.fileName.endsWith('.json')) {
            zip.readEntry();
            return;
          }
          scannedEntries++;
          const entryId = normalizeId(path.posix.basename(entry.fileName, '.json'));
          if (!remaining.has(entryId)) {
            zip.readEntry();
            return;
          }
          const item = JSON.parse((await readZipEntry(zip, entry)).toString('utf8'));
          if (normalizeId(item?.id) !== entryId)
            throw new Error(`OSV archive entry ${entry.fileName} has mismatched payload ID ${item?.id}`);
          await onItem(item);
          if (remaining.size === 0) {
            zip.close();
            finish();
            return;
          }
          zip.readEntry();
        } catch (error) {
          zip.close();
          finish(error);
        }
      });
      zip.readEntry();
    });
  } finally {
    zip.close();
  }
  return { scannedEntries };
}

function createSegmentWriter(incoming, runId, segmentSize) {
  let records = 0;
  let segment = [];
  const files = [];

  const flush = async () => {
    if (segment.length === 0) return;
    const sequence = files.length;
    const base = `osv-init-${safePart(runId)}-s${String(sequence).padStart(4, '0')}.ndjson`;
    const partialPath = path.join(incoming, `${base}.partial`);
    const readyPath = path.join(incoming, `${base}.ready`);
    await fs.writeFile(partialPath, `${segment.join('\n')}\n`, { flag: 'wx' });
    await fs.rename(partialPath, readyPath);
    files.push({ file: path.basename(readyPath), records: segment.length });
    segment = [];
  };

  return {
    async add(item) {
      segment.push(stableJson(osvAppendEnvelope(item, runId)));
      records++;
      if (segment.length >= segmentSize) await flush();
    },
    async finish() {
      await flush();
      return { records, files };
    }
  };
}

function osvAppendEnvelope(item, runId) {
  return {
    schemaVersion: 1,
    sourceCode: 'osv-init',
    sourceMode: 'append',
    forceNormalize: true,
    runId,
    externalKey: item.id,
    externalId: item.id,
    sourceUrl: `https://osv.dev/vulnerability/${item.id}`,
    publishedAt: item.published ?? null,
    modifiedAt: item.modified ?? null,
    snapshotId: null,
    snapshotComplete: null,
    recordHash: sha256(stableJson(item)),
    identifiers: [item.id, ...(item.aliases ?? [])].filter(Boolean),
    payload: item
  };
}

function normalizePrefix(value) {
  const prefix = String(value ?? '').trim().toUpperCase();
  if (!/^[A-Z][A-Z0-9_.:-]*-$/.test(prefix))
    throw new Error('--prefix must be an uppercase vulnerability identifier prefix ending in -');
  return prefix;
}

function matchesPrefix(value, prefix) {
  return String(value ?? '').toUpperCase().startsWith(prefix);
}

function normalizeIds(values) {
  const ids = [...new Set((values ?? []).map(normalizeId).filter(Boolean))].sort();
  if (ids.length === 0) throw new Error('at least one OSV ID is required');
  return ids;
}

function normalizeId(value) {
  return String(value ?? '').trim().toUpperCase();
}

function positiveInteger(value, fallback) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error('segment size must be a positive integer');
  return parsed;
}

function safePart(value) {
  return String(value).replace(/[^a-zA-Z0-9_.-]+/g, '-').replace(/^-+|-+$/g, '').toLowerCase();
}

function openZip(zipPath) {
  return new Promise((resolve, reject) => {
    yauzl.open(zipPath, { lazyEntries: true, autoClose: false }, (error, zip) => {
      if (error) reject(error);
      else resolve(zip);
    });
  });
}

function readZipEntry(zip, entry) {
  return new Promise((resolve, reject) => {
    zip.openReadStream(entry, (error, stream) => {
      if (error) {
        reject(error);
        return;
      }
      const chunks = [];
      stream.on('data', (chunk) => chunks.push(chunk));
      stream.once('error', reject);
      stream.once('end', () => resolve(Buffer.concat(chunks)));
    });
  });
}

async function fileSha256(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

function argument(name, fallback = null) {
  const prefix = `${name}=`;
  const value = process.argv.slice(2).find((item) => item.startsWith(prefix));
  return value ? value.slice(prefix.length) : fallback;
}

async function main() {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const zipPath = path.resolve(root, argument('--zip', DEFAULT_ZIP));
  const outputDirectory = path.resolve(root, argument('--output', DEFAULT_OUTPUT));
  const prefix = argument('--prefix');
  const idsFile = argument('--ids-file');
  const segmentSize = Number(argument('--segment-size', '5000'));
  if (Boolean(prefix) === Boolean(idsFile))
    throw new Error('provide exactly one of --prefix or --ids-file');
  const result = idsFile
    ? await feedOsvBulkIds(zipPath, outputDirectory, {
      ids: (await fs.readFile(path.resolve(idsFile), 'utf8')).split(/\r?\n/),
      segmentSize
    })
    : await feedOsvBulkPrefix(zipPath, outputDirectory, { prefix, segmentSize });
  console.log(JSON.stringify({ ok: true, manifest: result.manifestPath, ...result.manifest }));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
