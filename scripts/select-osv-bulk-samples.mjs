#!/usr/bin/env node
import fs from 'node:fs/promises';
import { createReadStream, createWriteStream, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import yauzl from 'yauzl';
import { sha256, stableJson } from '../plugins/fetchers/lib/hash.mjs';

const DEFAULT_URL = 'https://storage.googleapis.com/osv-vulnerabilities/all.zip';
const DEFAULT_ZIP = 'data/mirrors/osv-all.zip';
const DEFAULT_OUTPUT = 'data/osv-bulk-samples';
const EXACT_CVE = /^CVE-\d{4}-\d{4,}$/i;
const EMBEDDED_CVE = /^[A-Z][A-Z0-9_.-]*-(CVE-\d{4}-\d{4,})$/i;

export async function selectOsvBulkSamples(zipPath, options = {}) {
  const state = createSelectionState();
  await forEachOsvRecord(
    zipPath,
    (item, entryName) => addSelectionRecord(state, item, entryName),
    options.concurrency ?? 8);
  return finishSelection(state);
}

export function selectOsvRecords(records) {
  const state = createSelectionState();
  for (const [index, item] of records.entries()) addSelectionRecord(state, item, `fixture-${index}.json`);
  return finishSelection(state);
}

function createSelectionState() {
  return {
    selected: new Map(),
    aliasHistogram: new Map(),
    upstreamHistogram: new Map(),
    totalRecords: 0,
    maximumAliasCves: null,
    maximumUpstreamCves: null
  };
}

function addSelectionRecord(state, item, entryName) {
  state.totalRecords++;
  const profile = profileOsvRecord(item, entryName);
  increment(state.aliasHistogram, profile.aliasCveCount);
  increment(state.upstreamHistogram, profile.upstreamCveCount);

  selectFirst(state.selected, `alias-cve-${profile.aliasCveCount}`, item, profile, profile.aliasCveCount <= 2);
  selectFirst(state.selected, `upstream-cve-${profile.upstreamCveCount}`, item, profile, profile.upstreamCveCount <= 2);
  selectFirst(state.selected, 'cve-less-ghsa', item, profile, profile.cveLessGhsa);
  selectFirst(state.selected, 'embedded-cve-id', item, profile, profile.embeddedCveId);
  selectFirst(state.selected, 'complete-evidence', item, profile, profile.hasCompleteEvidence);

  if (!state.maximumAliasCves || profile.aliasCveCount > state.maximumAliasCves.profile.aliasCveCount)
    state.maximumAliasCves = { item, profile };
  if (!state.maximumUpstreamCves || profile.upstreamCveCount > state.maximumUpstreamCves.profile.upstreamCveCount)
    state.maximumUpstreamCves = { item, profile };
}

function finishSelection(state) {
  const {
    selected,
    aliasHistogram,
    upstreamHistogram,
    totalRecords,
    maximumAliasCves,
    maximumUpstreamCves
  } = state;
  if (maximumAliasCves) selected.set('alias-cve-maximum', maximumAliasCves);
  if (maximumUpstreamCves) selected.set('upstream-cve-maximum', maximumUpstreamCves);

  const records = deduplicateSelections(selected);
  return {
    totalRecords,
    aliasCveHistogram: histogramObject(aliasHistogram),
    upstreamCveHistogram: histogramObject(upstreamHistogram),
    selections: Object.fromEntries([...selected].map(([category, value]) => [category, value.profile.id])),
    records
  };
}

export function profileOsvRecord(item, entryName = null) {
  const id = String(item?.id ?? '').toUpperCase();
  const aliases = normalizedValues(item?.aliases);
  const upstream = normalizedValues(item?.upstream);
  const aliasCves = aliases.filter((value) => EXACT_CVE.test(value));
  const upstreamCves = upstream.filter((value) => EXACT_CVE.test(value));
  return {
    id,
    entryName,
    aliasCves,
    upstreamCves,
    aliasCveCount: new Set(aliasCves).size,
    upstreamCveCount: new Set(upstreamCves).size,
    cveLessGhsa: id.startsWith('GHSA-') && aliasCves.length === 0,
    embeddedCveId: !EXACT_CVE.test(id) && EMBEDDED_CVE.test(id),
    hasSeverity: Array.isArray(item?.severity) && item.severity.length > 0,
    hasReferences: Array.isArray(item?.references) && item.references.length > 0,
    hasAffected: Array.isArray(item?.affected) && item.affected.length > 0,
    hasCompleteEvidence: Array.isArray(item?.severity) && item.severity.length > 0
      && Array.isArray(item?.references) && item.references.length > 0
      && Array.isArray(item?.affected) && item.affected.length > 0
  };
}

export async function writeOsvBulkSamples(zipPath, outputDirectory, options = {}) {
  const archiveHash = await fileSha256(zipPath);
  const selection = await selectOsvBulkSamples(zipPath, options);
  const runId = `boundary-${archiveHash.slice(0, 16)}`;
  const incoming = path.join(outputDirectory, 'incoming');
  const spoolName = `osv-init-${runId}-s0000.ndjson.ready`;
  const spoolPath = path.join(incoming, spoolName);
  await fs.mkdir(incoming, { recursive: true });

  const lines = selection.records.map(({ item }) => stableJson(osvSpoolEnvelope(item, runId)));
  await fs.writeFile(spoolPath, `${lines.join('\n')}\n`, 'utf8');
  const manifest = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    archive: { path: path.resolve(zipPath), sha256: archiveHash },
    spool: { file: spoolName, records: lines.length },
    totalRecords: selection.totalRecords,
    aliasCveHistogram: selection.aliasCveHistogram,
    upstreamCveHistogram: selection.upstreamCveHistogram,
    selections: selection.selections,
    records: selection.records.map(({ profile, categories }) => ({ ...profile, categories }))
  };
  const manifestPath = path.join(outputDirectory, 'manifest.json');
  await fs.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return { manifestPath, spoolPath, manifest };
}

async function forEachOsvRecord(zipPath, callback, configuredConcurrency) {
  const zip = await openZip(zipPath);
  const concurrency = Math.max(1, Math.min(32, Number(configuredConcurrency) || 8));
  try {
    await new Promise((resolve, reject) => {
      let settled = false;
      let ended = false;
      let pendingRead = false;
      let active = 0;
      const finish = (error) => {
        if (settled) return;
        settled = true;
        if (error) reject(error);
        else resolve();
      };
      const requestNext = () => {
        if (settled || ended || pendingRead || active >= concurrency) return;
        pendingRead = true;
        zip.readEntry();
      };
      zip.once('error', finish);
      zip.once('end', () => {
        pendingRead = false;
        ended = true;
        if (active === 0) finish();
      });
      zip.on('entry', (entry) => {
        pendingRead = false;
        if (/\/$/.test(entry.fileName) || !entry.fileName.endsWith('.json')) {
          requestNext();
          return;
        }
        active++;
        requestNext();
        readZipEntry(zip, entry)
          .then((bytes) => callback(JSON.parse(bytes.toString('utf8')), entry.fileName))
          .then(() => {
            active--;
            if (ended && active === 0) finish();
            else requestNext();
          })
          .catch((error) => {
            zip.close();
            finish(error);
          });
      });
      requestNext();
    });
  } finally {
    zip.close();
  }
}

function deduplicateSelections(selected) {
  const byId = new Map();
  for (const [category, value] of selected) {
    if (!byId.has(value.profile.id)) byId.set(value.profile.id, { ...value, categories: [] });
    byId.get(value.profile.id).categories.push(category);
  }
  return [...byId.values()]
    .map((value) => ({ ...value, categories: value.categories.sort() }))
    .sort((left, right) => left.profile.id.localeCompare(right.profile.id));
}

function selectFirst(selected, category, item, profile, condition) {
  if (condition && !selected.has(category)) selected.set(category, { item, profile });
}

function normalizedValues(values) {
  if (!Array.isArray(values)) return [];
  return values
    .filter((value) => typeof value === 'string' && value.trim())
    .map((value) => value.trim().toUpperCase());
}

function increment(histogram, count) {
  histogram.set(count, (histogram.get(count) ?? 0) + 1);
}

function histogramObject(histogram) {
  return Object.fromEntries([...histogram].sort(([left], [right]) => left - right));
}

function osvSpoolEnvelope(item, runId) {
  return {
    schemaVersion: 1,
    sourceCode: 'osv-init',
    sourceMode: null,
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

async function ensureArchive(zipPath, url, refresh) {
  if (existsSync(zipPath) && !refresh) return;
  await fs.mkdir(path.dirname(zipPath), { recursive: true });
  const response = await fetch(url, { headers: { 'user-agent': 'VulTrack/0.1' } });
  if (!response.ok || !response.body) throw new Error(`Failed to download OSV all.zip: HTTP ${response.status}`);
  const temporary = `${zipPath}.${process.pid}.tmp`;
  try {
    await pipeline(Readable.fromWeb(response.body), createWriteStream(temporary));
    await fs.rename(temporary, zipPath);
  } catch (error) {
    await fs.rm(temporary, { force: true });
    throw error;
  }
}

function argument(name, fallback) {
  const prefix = `${name}=`;
  const value = process.argv.slice(2).find((item) => item.startsWith(prefix));
  return value ? value.slice(prefix.length) : fallback;
}

async function main() {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const zipPath = path.resolve(root, argument('--zip', DEFAULT_ZIP));
  const outputDirectory = path.resolve(root, argument('--output', DEFAULT_OUTPUT));
  const url = argument('--url', DEFAULT_URL);
  const concurrency = Number(argument('--concurrency', '8'));
  await ensureArchive(zipPath, url, process.argv.includes('--refresh'));
  const result = await writeOsvBulkSamples(zipPath, outputDirectory, { concurrency });
  console.log(JSON.stringify({
    ok: true,
    manifest: result.manifestPath,
    spool: result.spoolPath,
    records: result.manifest.spool.records,
    scanned: result.manifest.totalRecords
  }));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
