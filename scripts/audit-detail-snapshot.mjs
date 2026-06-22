import { promises as fs } from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { gunzip as gunzipCallback } from 'node:zlib';
import pg from 'pg';

const gunzip = promisify(gunzipCallback);
const { Client } = pg;

const args = parseArgs(process.argv.slice(2));
const databaseUrl = process.env.DATABASE_URL ?? args.databaseUrl ?? 'postgres://vultrack:vultrack@localhost:5432/vultrack';
const snapshotDir = path.resolve(process.env.VULTRACK_DETAIL_SNAPSHOT_DIR ?? args.dir ?? 'data/vulnerability-details');
const sampleMissing = positiveInt(args.sampleMissing, 20);

const client = new Client({ connectionString: databaseUrl });
await client.connect();

try {
  const pgTotal = await scalar('select count(*)::bigint from vulnerabilities');
  const audit = await readSnapshots();
  const matched = await countMatchedVulnerabilities([...audit.ids]);
  const missing = pgTotal - matched;
  const samples = missing > 0 ? await sampleMissingRows(audit.ids, sampleMissing) : [];

  console.log(JSON.stringify({
    ok: true,
    snapshotDir,
    pgVulnerabilities: pgTotal,
    snapshotEntries: audit.entries,
    snapshotUniqueIds: audit.ids.size,
    snapshotMatchedPg: matched,
    snapshotExtraIds: Math.max(0, audit.ids.size - matched),
    missingPgVulnerabilities: missing,
    coverage: pgTotal === 0 ? 1 : matched / pgTotal,
    files: audit.files,
    gzipBytes: audit.gzipBytes,
    rawJsonBytes: audit.rawJsonBytes,
    invalidKeys: audit.invalidKeys,
    shardStats: summarizeShards(audit.shards),
    sampleMissing: samples
  }, null, 2));
} finally {
  await client.end();
}

async function scalar(sql, params = []) {
  const result = await client.query(sql, params);
  return Number(result.rows[0]?.count ?? result.rows[0]?.value ?? 0);
}

async function readSnapshots() {
  const shardsDir = path.join(snapshotDir, 'shards');
  const ids = new Set();
  const shards = [];
  let entries = 0;
  let files = 0;
  let gzipBytes = 0;
  let rawJsonBytes = 0;
  let invalidKeys = 0;

  let names = [];
  try {
    names = await fs.readdir(shardsDir);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  for (const name of names.sort()) {
    if (!/^[0-9a-f]{2}\.json\.gz$/i.test(name)) continue;
    const file = path.join(shardsDir, name);
    const stat = await fs.stat(file);
    const compressed = await fs.readFile(file);
    const raw = await gunzip(compressed);
    const parsed = JSON.parse(raw.toString('utf8'));
    const keys = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? Object.keys(parsed).filter((key) => !key.startsWith('_'))
      : [];

    let valid = 0;
    for (const key of keys) {
      const uuid = normalizeUuid(key);
      if (uuid) {
        ids.add(uuid);
        valid++;
      } else {
        invalidKeys++;
      }
    }

    entries += keys.length;
    files++;
    gzipBytes += stat.size;
    rawJsonBytes += raw.length;
    shards.push({ shard: name.slice(0, 2).toLowerCase(), entries: keys.length, valid, gzipBytes: stat.size, rawJsonBytes: raw.length });
  }

  return { ids, entries, files, gzipBytes, rawJsonBytes, invalidKeys, shards };
}

async function countMatchedVulnerabilities(ids) {
  let matched = 0;
  for (const chunk of chunks(ids, 10000)) {
    matched += await scalar('select count(*)::bigint from vulnerabilities where id = any($1::uuid[])', [chunk]);
  }
  return matched;
}

async function sampleMissingRows(snapshotIds, limit) {
  const rows = [];
  let cursorUpdatedAt = null;
  let cursorId = null;
  while (rows.length < limit) {
    const result = await client.query(`
      select id::text, primary_identifier, updated_at
      from vulnerabilities
      where $1::timestamptz is null
         or (updated_at, id) < ($1::timestamptz, $2::uuid)
      order by updated_at desc, id desc
      limit 1000
    `, [cursorUpdatedAt, cursorId]);
    if (result.rows.length === 0) break;
    for (const row of result.rows) {
      if (!snapshotIds.has(row.id.toLowerCase())) {
        rows.push(row);
        if (rows.length >= limit) break;
      }
    }
    const last = result.rows.at(-1);
    cursorUpdatedAt = last.updated_at;
    cursorId = last.id;
  }
  return rows;
}

function summarizeShards(shards) {
  if (shards.length === 0) {
    return { minEntries: 0, maxEntries: 0, averageEntries: 0, largest: [] };
  }
  const entries = shards.map((shard) => shard.entries);
  return {
    minEntries: Math.min(...entries),
    maxEntries: Math.max(...entries),
    averageEntries: entries.reduce((sum, value) => sum + value, 0) / entries.length,
    largest: [...shards].sort((a, b) => b.gzipBytes - a.gzipBytes).slice(0, 8)
  };
}

function normalizeUuid(value) {
  const text = String(value ?? '').trim().toLowerCase();
  if (/^[0-9a-f]{32}$/.test(text)) {
    return `${text.slice(0, 8)}-${text.slice(8, 12)}-${text.slice(12, 16)}-${text.slice(16, 20)}-${text.slice(20)}`;
  }
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(text) ? text : null;
}

function chunks(items, size) {
  const result = [];
  for (let i = 0; i < items.length; i += size) result.push(items.slice(i, i + size));
  return result;
}

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function parseArgs(argv) {
  const parsed = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    const [rawKey, inlineValue] = arg.slice(2).split('=', 2);
    const key = rawKey.replace(/-([a-z])/g, (_, ch) => ch.toUpperCase());
    parsed[key] = inlineValue ?? argv[++i];
  }
  return parsed;
}
