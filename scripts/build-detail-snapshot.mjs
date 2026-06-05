import { promises as fs } from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { gzip as gzipCallback, gunzip as gunzipCallback } from 'node:zlib';
import pg from 'pg';

const gzip = promisify(gzipCallback);
const gunzip = promisify(gunzipCallback);
const { Client } = pg;

const args = parseArgs(process.argv.slice(2));
const apiBaseUrl = process.env.API_BASE_URL ?? 'http://localhost:5099';
const databaseUrl = process.env.DATABASE_URL ?? 'postgres://vultrack:vultrack@localhost:5432/vultrack';
const outputDir = path.resolve(process.env.VULTRACK_DETAIL_SNAPSHOT_DIR ?? args.output ?? 'data/vulnerability-details');
const concurrency = clamp(positiveInt(process.env.DETAIL_SNAPSHOT_CONCURRENCY ?? args.concurrency, 8), 1, 64);
const gzipLevel = clamp(positiveInt(process.env.DETAIL_SNAPSHOT_GZIP_LEVEL ?? args.gzipLevel, 6), 1, 9);
const fetchRetries = clamp(positiveInt(process.env.DETAIL_SNAPSHOT_FETCH_RETRIES ?? args.fetchRetries, 3), 0, 10);
const globalLimit = args.limit == null ? null : positiveInt(args.limit, 0);
const since = args.since ?? null;
const explicitIds = (args.id ?? []).map((id) => normalizeUuid(id)).filter(Boolean);
const requestedShard = args.shard ? normalizeShard(args.shard) : null;

const client = new Client({ connectionString: databaseUrl });
await client.connect();

let remaining = globalLimit;
let totalSelected = 0;
let totalWritten = 0;
const updatedShards = [];

try {
  await fs.mkdir(path.join(outputDir, 'shards'), { recursive: true });

  const rowsByShard = await loadRowsByShard();
  const shards = [...rowsByShard.keys()].sort();
  for (const shard of shards) {
    if (remaining === 0) break;
    const rows = remaining === null ? rowsByShard.get(shard) : rowsByShard.get(shard).slice(0, remaining);
    if (rows.length === 0) continue;

    totalSelected += rows.length;
    const shardFile = path.join(outputDir, 'shards', `${shard}.json.gz`);
    const shardDoc = await readShard(shardFile);
    const startedAt = Date.now();
    const results = await mapLimit(rows, concurrency, async (row) => {
      const detail = await fetchDetail(row.id);
      return { row, detail };
    });

    for (const { row, detail } of results) {
      shardDoc[row.id] = detail;
      totalWritten++;
    }

    await writeShard(shardFile, shardDoc);
    updatedShards.push({
      shard,
      selected: rows.length,
      totalInShard: Object.keys(shardDoc).length,
      file: path.relative(outputDir, shardFile)
    });

    if (remaining !== null) remaining = Math.max(0, remaining - rows.length);
    const elapsedMs = Date.now() - startedAt;
    console.log(JSON.stringify({
      event: 'detail_snapshot_shard_written',
      shard,
      selected: rows.length,
      totalWritten,
      elapsedMs,
      rowsPerSecond: elapsedMs > 0 ? rows.length / (elapsedMs / 1000) : rows.length
    }));
  }

  await writeManifest({
    generatedAt: new Date().toISOString(),
    shardScheme: 'uuid-prefix-2',
    compression: 'gzip',
    gzipLevel,
    apiBaseUrl,
    since,
    selected: totalSelected,
    written: totalWritten,
    updatedShards
  });

  console.log(JSON.stringify({
    ok: true,
    outputDir,
    selected: totalSelected,
    written: totalWritten,
    shards: updatedShards.length
  }, null, 2));
} finally {
  await client.end();
}

async function loadRowsByShard() {
  const rows = explicitIds.length
    ? await loadExplicitRows()
    : requestedShard
      ? await loadRowsForShard(requestedShard, remaining)
      : await loadRows(remaining);

  const rowsByShard = new Map();
  for (const row of rows) {
    const shard = shardForId(row.id);
    if (!rowsByShard.has(shard)) rowsByShard.set(shard, []);
    rowsByShard.get(shard).push(row);
  }
  return rowsByShard;
}

async function loadRows(limit) {
  const params = [];
  let where = 'true';
  if (since) {
    params.push(since);
    where += ` and updated_at >= $${params.length}::timestamptz`;
  }
  if (limit !== null) {
    params.push(limit);
  }

  const result = await client.query(`
    select id::text as id, primary_identifier, updated_at
    from vulnerabilities
    where ${where}
    order by updated_at desc nulls last, id
    ${limit !== null ? `limit $${params.length}` : ''}
  `, params);
  return result.rows;
}

async function loadRowsForShard(shard, limit) {
  const params = [shard];
  let where = "left(replace(id::text, '-', ''), 2) = $1";
  if (since) {
    params.push(since);
    where += ` and updated_at >= $${params.length}::timestamptz`;
  }
  if (limit !== null) {
    params.push(limit);
  }

  const result = await client.query(`
    select id::text as id, primary_identifier, updated_at
    from vulnerabilities
    where ${where}
    order by updated_at desc nulls last, id
    ${limit !== null ? `limit $${params.length}` : ''}
  `, params);
  return result.rows;
}

async function loadExplicitRows() {
  if (explicitIds.length === 0) return [];
  const result = await client.query(`
    select id::text as id, primary_identifier, updated_at
    from vulnerabilities
    where id = any($1::uuid[])
    order by updated_at desc nulls last, id
  `, [explicitIds]);
  return result.rows;
}

async function fetchDetail(id) {
  const url = new URL('/api/v1/vulnerability.detail', apiBaseUrl);
  url.searchParams.set('id', id);
  url.searchParams.set('source', 'duckdb');
  url.searchParams.set('snapshot', 'false');
  let lastError;
  for (let attempt = 0; attempt <= fetchRetries; attempt++) {
    try {
      const response = await fetch(url);
      const body = await response.json().catch(() => null);
      if (!response.ok || body?.ok === false) {
        throw new Error(`detail fetch failed for ${id}: HTTP ${response.status} ${JSON.stringify(body)}`);
      }
      return body.data;
    } catch (error) {
      lastError = error;
      if (attempt < fetchRetries)
        await delay(Math.min(5000, 250 * 2 ** attempt));
    }
  }
  throw lastError;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function readShard(file) {
  try {
    const compressed = await fs.readFile(file);
    const raw = await gunzip(compressed);
    const parsed = JSON.parse(raw.toString('utf8'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch (error) {
    if (error.code === 'ENOENT') return {};
    throw error;
  }
}

async function writeShard(file, value) {
  const tmp = `${file}.tmp-${process.pid}`;
  const json = JSON.stringify(sortObjectKeys(value));
  const compressed = await gzip(Buffer.from(json), { level: gzipLevel });
  await fs.writeFile(tmp, compressed);
  await fs.rename(tmp, file);
}

async function writeManifest(manifest) {
  const file = path.join(outputDir, 'manifest.json');
  const tmp = `${file}.tmp-${process.pid}`;
  await fs.writeFile(tmp, `${JSON.stringify(manifest, null, 2)}\n`);
  await fs.rename(tmp, file);
}

function sortObjectKeys(value) {
  return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)));
}

async function mapLimit(items, limit, mapper) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await mapper(items[index], index);
    }
  });
  await Promise.all(workers);
  return results;
}

function shardForId(id) {
  return id.replaceAll('-', '').slice(0, 2).toLowerCase();
}

function normalizeShard(value) {
  const shard = String(value ?? '').trim().toLowerCase();
  if (!/^[0-9a-f]{2}$/.test(shard)) throw new Error(`Invalid shard: ${value}`);
  return shard;
}

function normalizeUuid(value) {
  const id = String(value ?? '').trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id)) {
    throw new Error(`Invalid UUID: ${value}`);
  }
  return id;
}

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function parseArgs(argv) {
  const parsed = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    const [rawKey, inlineValue] = arg.slice(2).split('=', 2);
    const key = rawKey.replace(/-([a-z])/g, (_, ch) => ch.toUpperCase());
    const value = inlineValue ?? argv[++i];
    if (key === 'id') {
      parsed.id ??= [];
      parsed.id.push(value);
    } else {
      parsed[key] = value;
    }
  }
  return parsed;
}
