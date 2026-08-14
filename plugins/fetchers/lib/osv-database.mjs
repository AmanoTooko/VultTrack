import fs from 'node:fs/promises';
import { createReadStream, createWriteStream, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import yauzl from 'yauzl';
import { getBoolEnv, getIntEnv, getRootPath } from './env.mjs';
import { fetchJson, fetchResponse } from './http.mjs';
import { sha256, stableJson } from './hash.mjs';
import { commitSpoolSegment, writeRecord } from './db.mjs';

const BASE_URL = 'https://storage.googleapis.com/osv-vulnerabilities';

export async function runOsvAllZipInit(client, ctx, options = {}) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  // This is deliberately captured before the archive is fetched. The daily
  // source will replay anything OSV changes while a long baseline is running.
  const incrementalSince = checkpoint.incrementalSince ?? new Date().toISOString();
  const zipUrl = options.ecosystem ? `${BASE_URL}/${encodeURIComponent(options.ecosystem)}/all.zip` : `${BASE_URL}/all.zip`;
  const zipName = options.ecosystem ? `osv-${options.ecosystem.toLowerCase()}-all.zip` : 'osv-all.zip';
  const tmpDir = getRootPath('data/mirrors');
  await fs.mkdir(tmpDir, { recursive: true });
  const zipPath = `${tmpDir}/${zipName}`;

  if (!existsSync(zipPath) || process.env.FETCHER_REFRESH_MIRROR) {
    const resp = await fetch(zipUrl, { headers: { 'user-agent': 'VulTrack/0.1' } });
    if (!resp.ok || !resp.body) throw new Error(`Failed to download OSV all.zip: HTTP ${resp.status}`);
    await pipeline(Readable.fromWeb(resp.body), createWriteStream(zipPath));
  }

  const contentHash = await fileSha256(zipPath);
  if (checkpoint.contentHash === contentHash && checkpoint.initComplete !== false && !process.env.FETCHER_FORCE) {
    return {
      fetchedCount: 0,
      parsedCount: 0,
      checkpoint: { ...checkpoint, contentHash, incrementalSince, skipped: true, lastFetched: new Date().toISOString() }
    };
  }

  const canResume = checkpoint.contentHash === contentHash && checkpoint.initComplete === false;
  const startOffset = canResume ? Math.max(0, Number(checkpoint.offset) || 0) : 0;
  const streamed = await streamOsvZip(zipPath, {
    startOffset,
    max,
    prefixes: options.prefixes,
    onItem: async (item, nextOffset, estimatedEntries) => {
      const accepted = !options.filter || options.filter(item);
      if (accepted) await writeOsvItem(client, ctx, item);
      if (client.__spool && nextOffset % 5000 === 0) {
        const segmentCheckpoint = {
          contentHash,
          initComplete: false,
          incrementalSince,
          offset: nextOffset,
          totalEntries: estimatedEntries,
          lastFetched: new Date().toISOString()
        };
        await commitSpoolSegment(client, ctx.source.id, segmentCheckpoint);
        ctx.source.checkpoint_json = segmentCheckpoint;
        console.error(`[${ctx.source.code}] committed ${nextOffset}/${estimatedEntries}`);
      }
      return accepted;
    }
  });
  const { count, nextOffset, complete, totalEntries } = streamed;
  const nextCheckpoint = {
    contentHash,
    initComplete: complete,
    incrementalSince,
    offset: nextOffset,
    totalEntries,
    lastFetched: new Date().toISOString()
  };
  if (client.__spool) await commitSpoolSegment(client, ctx.source.id, nextCheckpoint);
  // DuckDB ingestion happens after the fetcher exits. Keep the compressed
  // source until the importer has committed every spool segment.
  if (complete && !client.__spool && !getBoolEnv('OSV_KEEP_MIRROR', false))
    await fs.rm(zipPath, { force: true });
  return { fetchedCount: count, parsedCount: count, checkpoint: nextCheckpoint };
}

async function streamOsvZip(zipPath, options) {
  const zip = await openZip(zipPath);
  const estimatedEntries = zip.entryCount;
  let eligibleOffset = 0;
  let nextOffset = options.startOffset;
  let count = 0;
  let complete = false;

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
      zip.once('end', () => {
        complete = true;
        finish();
      });
      zip.on('entry', async (entry) => {
        try {
          if (/\/$/.test(entry.fileName)
              || !entry.fileName.endsWith('.json')
              || (options.prefixes && !options.prefixes.some((prefix) => entry.fileName.startsWith(prefix)))) {
            zip.readEntry();
            return;
          }
          if (eligibleOffset < options.startOffset) {
            eligibleOffset++;
            zip.readEntry();
            return;
          }
          if (count >= options.max) {
            zip.close();
            finish();
            return;
          }

          const item = JSON.parse((await readZipEntry(zip, entry)).toString('utf8'));
          eligibleOffset++;
          nextOffset = eligibleOffset;
          if (await options.onItem(item, nextOffset, estimatedEntries)) count++;
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
  return {
    count,
    nextOffset,
    complete,
    totalEntries: complete ? eligibleOffset : estimatedEntries
  };
}

function openZip(path) {
  return new Promise((resolve, reject) => {
    yauzl.open(path, { lazyEntries: true, autoClose: false }, (error, zip) => {
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

export async function runOsvModifiedIdIncremental(client, ctx, options = {}) {
  const max = osvFetchLimit();
  const explicitIds = options.ids ?? [];
  if (explicitIds.length) {
    return runOsvIds(client, ctx, explicitIds.slice(0, max), options);
  }
  if (getBoolEnv('FETCHER_SMOKE') && options.smokeIds?.length) {
    return runOsvIds(client, ctx, options.smokeIds.slice(0, max), options);
  }

  const checkpoint = ctx.source.checkpoint_json ?? {};
  const bootstrapWatermark = options.bootstrapWatermark ?? process.env.OSV_BOOTSTRAP_WATERMARK;
  const cursor = readOsvCursor(checkpoint, bootstrapWatermark);
  const csvUrl = options.ecosystem
    ? `${BASE_URL}/${encodeURIComponent(options.ecosystem)}/modified_id.csv`
    : `${BASE_URL}/modified_id.csv`;
  let index = await fetchModifiedIndex(csvUrl, checkpoint, options);
  const indexEtag = header(index.headers, 'etag');
  const indexLastModified = header(index.headers, 'last-modified');

  if (index.status === 304) {
    return emptyIncrementalResult(checkpoint, {
      indexEtag: checkpoint.indexEtag,
      indexLastModified: checkpoint.indexLastModified,
      skipped: 'not-modified'
    });
  }
  if (!index.ok || !index.body) throw new Error(`Failed to download OSV modified index: HTTP ${index.status}`);

  // A normal source must never invent a multi-day catch-up window. The init
  // source supplies this cursor; legacy deployments need an explicit one-time
  // bootstrap value rather than silently emitting a near-full spool.
  if (!cursor) {
    await abortIndexBody(index.body);
    return emptyIncrementalResult(checkpoint, {
      indexEtag,
      indexLastModified,
      bootstrapRequired: true,
      skipped: 'missing-baseline-cursor'
    });
  }

  let indexSnapshotPath = index.snapshotPath ?? null;
  if ((!options.fetchIndex || options.persistIndexSnapshot) && client.__spool && !indexSnapshotPath) {
    indexSnapshotPath = await materializeModifiedIndex(
      index.body,
      options.ecosystem,
      indexEtag ?? indexLastModified ?? new Date().toISOString(),
      options.indexSnapshotDirectory);
    index = { ...index, body: createReadStream(indexSnapshotPath), snapshotPath: indexSnapshotPath };
  }

  const pending = readPending(checkpoint.pending);
  const activeCursor = pending?.baseCursor ?? cursor;
  const pendingMatchesIndex = pending && sameIndexVersion(pending, { indexEtag, indexLastModified });
  const resume = pendingMatchesIndex ? pending.resume : null;
  const snapshotMode = Boolean(indexSnapshotPath);
  const snapshotOffset = snapshotMode && pendingMatchesIndex
    && pending?.indexSnapshotPath === indexSnapshotPath
    ? pending.offset
    : 0;
  const candidates = [];
  const newestIds = new Set(snapshotMode && pendingMatchesIndex ? pending.newestIds : []);
  let newestModifiedAt = snapshotMode && pendingMatchesIndex ? pending.newestModifiedAt : null;
  let previousModifiedAt = null;
  const handledEntries = [];
  let entryOffset = 0;
  let processedOffset = snapshotOffset;
  let hitLimit = false;

  for await (const line of csvLines(index.body)) {
    const entry = parseModifiedIdLine(line);
    if (!entry) continue;
    entryOffset++;
    if (!isValidTimestamp(entry.modifiedAt)) throw new Error(`Invalid OSV modified timestamp: ${entry.modifiedAt}`);
    if (!snapshotMode && previousModifiedAt && compareRfc3339(entry.modifiedAt, previousModifiedAt) > 0)
      throw new Error('OSV modified_id.csv is not reverse chronological');
    previousModifiedAt = entry.modifiedAt;
    if (snapshotMode && entryOffset <= snapshotOffset) continue;

    if (!newestModifiedAt || compareRfc3339(entry.modifiedAt, newestModifiedAt) > 0) {
      newestModifiedAt = entry.modifiedAt;
      newestIds.clear();
      newestIds.add(entry.rawId);
    } else if (compareRfc3339(entry.modifiedAt, newestModifiedAt) === 0) {
      newestIds.add(entry.rawId);
    }

    const relation = compareToCursor(entry.modifiedAt, entry.rawId, activeCursor);
    if (!snapshotMode && relation < 0) break;
    if (relation <= 0 || (!snapshotMode && isAtOrAboveResume(entry, resume))) {
      if (snapshotMode) processedOffset = entryOffset;
      continue;
    }
    if (options.idFilter && !options.idFilter(entry.rawId)) {
      handledEntries.push(entry);
      if (snapshotMode) processedOffset = entryOffset;
      continue;
    }
    candidates.push(entry);
    handledEntries.push(entry);
    if (snapshotMode) processedOffset = entryOffset;
    if (candidates.length >= max) {
      hitLimit = true;
      break;
    }
  }

  const fetchConcurrency = Math.max(1, getIntEnv('OSV_FETCH_CONCURRENCY', 8));
  const fetchItem = options.fetchItem ?? fetchOsvItem;
  let count = 0;
  for (let offset = 0; offset < candidates.length; offset += fetchConcurrency) {
    const batch = candidates.slice(offset, offset + fetchConcurrency);
    const items = await Promise.all(batch.map(async (itemRef) => ({
      itemRef,
      item: await fetchItem(itemRef.rawId, options.ecosystem)
    })));
    for (const { item } of items) {
      if (options.filter && !options.filter(item)) {
        continue;
      }
      await writeOsvItem(client, ctx, item);
      count++;
    }
  }

  const common = {
    indexEtag,
    indexLastModified,
    lastFetched: new Date().toISOString(),
    bootstrapRequired: false
  };
  if (hitLimit) {
    return {
      fetchedCount: count,
      parsedCount: count,
      checkpoint: {
        ...common,
        cursor,
        pending: {
          baseCursor: activeCursor,
          indexEtag,
          indexLastModified,
          ...(snapshotMode ? {
            indexSnapshotPath,
            offset: processedOffset,
            newestModifiedAt,
            newestIds: [...newestIds].sort()
          } : {
            resume: advanceResume(resume, handledEntries)
          })
        }
      }
    };
  }

  if (indexSnapshotPath) await fs.rm(indexSnapshotPath, { force: true });
  return {
    fetchedCount: count,
    parsedCount: count,
    checkpoint: {
      ...common,
      cursor: nextOsvCursor(activeCursor, newestModifiedAt, newestIds),
      lastModifiedWatermark: nextOsvCursor(activeCursor, newestModifiedAt, newestIds).modifiedAt
    }
  };
}

function readOsvCursor(checkpoint, bootstrapWatermark) {
  const current = checkpoint.cursor;
  if (isValidTimestamp(current?.modifiedAt)) {
    return { modifiedAt: current.modifiedAt, ids: Array.isArray(current.ids) ? current.ids : [] };
  }
  if (isValidTimestamp(checkpoint.lastModifiedWatermark)) {
    return { modifiedAt: checkpoint.lastModifiedWatermark, ids: [] };
  }
  if (isValidTimestamp(bootstrapWatermark)) return { modifiedAt: bootstrapWatermark, ids: [] };
  return null;
}

function isValidTimestamp(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value);
}

function compareToCursor(modifiedAt, rawId, cursor) {
  const timestampComparison = compareRfc3339(modifiedAt, cursor.modifiedAt);
  if (timestampComparison !== 0) return timestampComparison;
  return cursor.ids.includes(rawId) ? 0 : 1;
}

function nextOsvCursor(current, newestModifiedAt, newestIds) {
  if (!newestModifiedAt || compareRfc3339(newestModifiedAt, current.modifiedAt) < 0) return current;
  if (compareRfc3339(newestModifiedAt, current.modifiedAt) === 0) {
    return { modifiedAt: current.modifiedAt, ids: [...new Set([...current.ids, ...newestIds])].sort() };
  }
  return { modifiedAt: newestModifiedAt, ids: [...newestIds].sort() };
}

function compareRfc3339(left, right) {
  const [leftBase, leftFraction = ''] = left.slice(0, -1).split('.', 2);
  const [rightBase, rightFraction = ''] = right.slice(0, -1).split('.', 2);
  if (leftBase !== rightBase) return leftBase < rightBase ? -1 : 1;
  const width = Math.max(leftFraction.length, rightFraction.length);
  for (let index = 0; index < width; index++) {
    const leftDigit = leftFraction.charCodeAt(index) || 48;
    const rightDigit = rightFraction.charCodeAt(index) || 48;
    if (leftDigit !== rightDigit) return leftDigit < rightDigit ? -1 : 1;
  }
  return 0;
}

function readPending(value) {
  if (!isValidTimestamp(value?.baseCursor?.modifiedAt)) return null;
  const hasSnapshot = typeof value.indexSnapshotPath === 'string'
    && Number.isInteger(value.offset)
    && value.offset >= 0;
  const hasResume = isValidTimestamp(value?.resume?.modifiedAt);
  if (!hasSnapshot && !hasResume) return null;
  return {
    baseCursor: {
      modifiedAt: value.baseCursor.modifiedAt,
      ids: Array.isArray(value.baseCursor.ids) ? value.baseCursor.ids : []
    },
    indexEtag: value.indexEtag ?? null,
    indexLastModified: value.indexLastModified ?? null,
    indexSnapshotPath: typeof value.indexSnapshotPath === 'string' ? value.indexSnapshotPath : null,
    offset: hasSnapshot ? value.offset : 0,
    newestModifiedAt: isValidTimestamp(value.newestModifiedAt) ? value.newestModifiedAt : null,
    newestIds: Array.isArray(value.newestIds) ? value.newestIds : [],
    resume: hasResume ? {
      modifiedAt: value.resume.modifiedAt,
      ids: Array.isArray(value.resume.ids) ? value.resume.ids : []
    } : null
  };
}

function sameIndexVersion(pending, index) {
  if (pending.indexEtag && index.indexEtag) return pending.indexEtag === index.indexEtag;
  if (pending.indexLastModified && index.indexLastModified) return pending.indexLastModified === index.indexLastModified;
  return false;
}

function isAtOrAboveResume(entry, resume) {
  if (!resume) return false;
  const comparison = compareRfc3339(entry.modifiedAt, resume.modifiedAt);
  return comparison > 0 || (comparison === 0 && resume.ids.includes(entry.rawId));
}

function advanceResume(previous, entries) {
  const entry = entries.at(-1);
  if (!entry) return previous;
  const boundaryIds = entries
    .filter((candidate) => compareRfc3339(candidate.modifiedAt, entry.modifiedAt) === 0)
    .map((candidate) => candidate.rawId);
  if (!previous || compareRfc3339(entry.modifiedAt, previous.modifiedAt) < 0) {
    return { modifiedAt: entry.modifiedAt, ids: [...new Set(boundaryIds)].sort() };
  }
  if (compareRfc3339(entry.modifiedAt, previous.modifiedAt) === 0) {
    return { modifiedAt: previous.modifiedAt, ids: [...new Set([...previous.ids, ...boundaryIds])].sort() };
  }
  return previous;
}

function parseModifiedIdLine(line) {
  const separator = line.indexOf(',');
  if (separator <= 0) return null;
  const modifiedAt = line.slice(0, separator).trim();
  const rawId = line.slice(separator + 1).trim();
  return modifiedAt && rawId ? { modifiedAt, rawId } : null;
}

async function* csvLines(body) {
  const input = typeof body.getReader === 'function' ? Readable.fromWeb(body) : body;
  const timeoutMs = Math.max(1000, getIntEnv('OSV_INDEX_STREAM_TIMEOUT_MS', getIntEnv('FETCHER_TIMEOUT_MS', 120000)));
  const timeout = setTimeout(() => input.destroy?.(new Error(`OSV modified index stream timed out after ${timeoutMs}ms`)), timeoutMs);
  let remainder = '';
  let complete = false;
  try {
    for await (const chunk of input) {
      const text = remainder + Buffer.from(chunk).toString('utf8');
      const lines = text.split(/\r?\n/);
      remainder = lines.pop() ?? '';
      yield* lines;
    }
    complete = true;
    if (remainder) yield remainder;
  } finally {
    clearTimeout(timeout);
    if (!complete) input.destroy?.();
  }
}

async function abortIndexBody(body) {
  if (typeof body.cancel === 'function') {
    await body.cancel().catch(() => {});
    return;
  }
  body.destroy?.();
}

async function fetchModifiedIndex(url, checkpoint, options) {
  const pending = readPending(checkpoint.pending);
  if (pending?.indexSnapshotPath && existsSync(pending.indexSnapshotPath)) {
    return {
      status: 200,
      ok: true,
      body: createReadStream(pending.indexSnapshotPath),
      snapshotPath: pending.indexSnapshotPath,
      headers: {
        get(name) {
          const normalized = String(name).toLowerCase();
          if (normalized === 'etag') return pending.indexEtag;
          if (normalized === 'last-modified') return pending.indexLastModified;
          return null;
        }
      }
    };
  }

  const headers = {};
  const mustRescan = checkpoint.bootstrapRequired === true || pending !== null;
  if (!process.env.FETCHER_FORCE && !mustRescan && checkpoint.indexEtag) headers['if-none-match'] = checkpoint.indexEtag;
  else if (!process.env.FETCHER_FORCE && !mustRescan && checkpoint.indexLastModified) headers['if-modified-since'] = checkpoint.indexLastModified;
  return options.fetchIndex ? options.fetchIndex(url, { headers }) : fetchResponse(url, { headers });
}

async function materializeModifiedIndex(body, ecosystem, version, configuredDirectory) {
  const directory = configuredDirectory ?? getRootPath('data/mirrors/osv-index');
  await fs.mkdir(directory, { recursive: true });
  const name = `${ecosystem ? String(ecosystem).toLowerCase() : 'all'}-${sha256(String(version)).slice(0, 16)}.csv`;
  const target = path.join(directory, name);
  const temporary = `${target}.${process.pid}.tmp`;
  const input = typeof body.getReader === 'function' ? Readable.fromWeb(body) : body;
  try {
    await pipeline(input, createWriteStream(temporary));
    await fs.rename(temporary, target);
    return target;
  } catch (error) {
    await fs.rm(temporary, { force: true });
    throw error;
  }
}

function osvFetchLimit() {
  const explicit = getIntEnv('FETCHER_MAX_RECORDS');
  const configured = getIntEnv('OSV_FETCH_MAX_RECORDS', 1000);
  return Math.max(1, explicit ?? configured ?? 1000);
}

function emptyIncrementalResult(checkpoint, patch) {
  return {
    fetchedCount: 0,
    parsedCount: 0,
    checkpoint: { ...checkpoint, ...patch, lastFetched: new Date().toISOString() }
  };
}

function header(headers, name) {
  return headers?.get?.(name) ?? headers?.[name] ?? headers?.[name.toLowerCase()] ?? null;
}

async function runOsvIds(client, ctx, ids, options) {
  let count = 0;
  for (const id of ids) {
    const item = await fetchOsvItem(id, options.ecosystem);
    if (options.filter && !options.filter(item)) continue;
    await writeOsvItem(client, ctx, item);
    count++;
  }
  return { fetchedCount: count, parsedCount: count, checkpoint: { ids, lastFetched: new Date().toISOString() } };
}

async function fetchOsvItem(rawId, ecosystem) {
  const path = ecosystem ? `${encodeURIComponent(ecosystem)}/${encodeURIComponent(rawId)}.json` : `${rawId}.json`;
  return fetchJson(`${BASE_URL}/${path}`);
}

async function writeOsvItem(client, ctx, item) {
  const ids = [item.id, ...(item.aliases ?? [])].filter(Boolean);
  await writeRecord(client, ctx, {
    externalKey: item.id,
    externalId: item.id,
    sourceUrl: `https://osv.dev/vulnerability/${item.id}`,
    publishedAt: item.published,
    modifiedAt: item.modified,
    identifiers: ids,
    recordHash: sha256(stableJson(item)),
    payload: item
  });
}
