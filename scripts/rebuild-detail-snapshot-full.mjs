import { promises as fs } from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { gunzip as gunzipCallback } from 'node:zlib';
import pg from 'pg';

const gunzip = promisify(gunzipCallback);
const { Client } = pg;

const args = parseArgs(process.argv.slice(2));
const databaseUrl = process.env.DATABASE_URL ?? args.databaseUrl ?? 'postgres://vultrack:vultrack@localhost:5432/vultrack';
const apiBaseUrl = process.env.API_BASE_URL ?? args.api ?? 'http://localhost:5099';
const outputDir = path.resolve(process.env.VULTRACK_DETAIL_SNAPSHOT_DIR ?? args.output ?? 'data/vulnerability-details');
const parallelShards = clamp(positiveInt(process.env.DETAIL_SNAPSHOT_PARALLEL_SHARDS ?? args.parallelShards, 4), 1, 32);
const perShardConcurrency = clamp(positiveInt(process.env.DETAIL_SNAPSHOT_CONCURRENCY ?? args.concurrency, 8), 1, 64);
const gzipLevel = clamp(positiveInt(process.env.DETAIL_SNAPSHOT_GZIP_LEVEL ?? args.gzipLevel, 4), 1, 9);
const force = truthy(args.force) || truthy(process.env.DETAIL_SNAPSHOT_FORCE);
const onlyShard = args.shard ? normalizeShard(args.shard) : null;
const adminUsername = args.username ?? process.env.VULTRACK_ADMIN_USERNAME ?? process.env.ADMIN_USERNAME ?? 'admin';
const adminPassword = args.password ?? process.env.VULTRACK_ADMIN_PASSWORD ?? process.env.ADMIN_PASSWORD ?? 'admin';

const client = new Client({ connectionString: databaseUrl });
await client.connect();

try {
  const authCookie = await login();
  await fs.mkdir(path.join(outputDir, 'shards'), { recursive: true });
  const expected = await loadExpectedShardCounts();
  const current = await loadCurrentShardCounts();
  const selected = [...expected.entries()]
    .filter(([shard, expectedCount]) => (!onlyShard || shard === onlyShard) && expectedCount > 0)
    .filter(([shard, expectedCount]) => force || (current.get(shard) ?? 0) < expectedCount)
    .sort(([a], [b]) => a.localeCompare(b));

  const expectedTotal = sum([...expected.values()]);
  const currentTotal = sum([...current.values()]);
  console.log(JSON.stringify({
    event: 'detail_snapshot_full_start',
    outputDir,
    apiBaseUrl,
    expectedTotal,
    currentTotal,
    missingEstimate: Math.max(0, expectedTotal - currentTotal),
    selectedShards: selected.length,
    parallelShards,
    perShardConcurrency,
    gzipLevel,
    force
  }));

  const startedAt = Date.now();
  let written = 0;
  let completed = 0;
  await mapLimit(selected, parallelShards, async ([shard, expectedCount]) => {
    const before = current.get(shard) ?? 0;
    const result = await rebuildShard(shard, authCookie);
    completed++;
    written += result.written;
    const elapsedSeconds = (Date.now() - startedAt) / 1000;
    console.log(JSON.stringify({
      event: 'detail_snapshot_full_progress',
      shard,
      before,
      expected: expectedCount,
      written: result.written,
      completedShards: completed,
      selectedShards: selected.length,
      totalWritten: written,
      elapsedSeconds,
      averageRowsPerSecond: elapsedSeconds > 0 ? written / elapsedSeconds : written
    }));
  });

  await writeManifest({
    generatedAt: new Date().toISOString(),
    shardScheme: 'uuid-prefix-2',
    compression: 'gzip',
    gzipLevel,
    mode: 'full-sharded',
    apiBaseUrl,
    expectedTotal,
    selectedShards: selected.length,
    written
  });

  console.log(JSON.stringify({
    ok: true,
    outputDir,
    expectedTotal,
    written,
    selectedShards: selected.length,
    elapsedSeconds: (Date.now() - startedAt) / 1000
  }, null, 2));
} finally {
  await client.end();
}

async function loadExpectedShardCounts() {
  const result = await client.query(`
    select left(replace(id::text, '-', ''), 2) as shard, count(*)::int as count
    from vulnerabilities
    group by 1
    order by 1
  `);
  return new Map(result.rows.map((row) => [row.shard, Number(row.count)]));
}

async function loadCurrentShardCounts() {
  const shardsDir = path.join(outputDir, 'shards');
  const counts = new Map();
  let names = [];
  try {
    names = await fs.readdir(shardsDir);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  await mapLimit(names.filter((name) => /^[0-9a-f]{2}\.json\.gz$/i.test(name)), 16, async (name) => {
    const file = path.join(shardsDir, name);
    const raw = await gunzip(await fs.readFile(file));
    const parsed = JSON.parse(raw.toString('utf8'));
    const count = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? Object.keys(parsed).filter((key) => !key.startsWith('_')).length
      : 0;
    counts.set(name.slice(0, 2).toLowerCase(), count);
  });
  return counts;
}

async function login() {
  const response = await fetch(new URL('/api/v1/auth.login', apiBaseUrl), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: adminUsername, password: adminPassword })
  });
  const body = await response.json().catch(() => null);
  if (!response.ok || body?.ok === false)
    throw new Error(`snapshot admin login failed: HTTP ${response.status} ${JSON.stringify(body)}`);
  const cookie = response.headers.get('set-cookie')?.split(';')[0];
  if (!cookie) throw new Error('snapshot admin login did not return an auth cookie');
  return cookie;
}

async function rebuildShard(shard, cookie) {
  const response = await fetch(new URL('/api/v1/admin.detailSnapshot.rebuild', apiBaseUrl), {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({
      shard,
      limit: 100000,
      concurrency: perShardConcurrency,
      gzipLevel
    })
  });
  const body = await response.json().catch(() => null);
  if (!response.ok || body?.ok === false)
    throw new Error(`snapshot shard ${shard} failed: HTTP ${response.status} ${JSON.stringify(body)}`);
  return { shard, written: Number(body.data?.written ?? 0), result: body.data };
}

async function writeManifest(manifest) {
  const file = path.join(outputDir, 'manifest.json');
  const tmp = `${file}.tmp-${process.pid}`;
  await fs.writeFile(tmp, `${JSON.stringify(manifest, null, 2)}\n`);
  await fs.rename(tmp, file);
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

function normalizeShard(value) {
  const shard = String(value ?? '').trim().toLowerCase();
  if (!/^[0-9a-f]{2}$/.test(shard)) throw new Error(`Invalid shard: ${value}`);
  return shard;
}

function sum(values) {
  return values.reduce((total, value) => total + Number(value), 0);
}

function truthy(value) {
  return ['1', 'true', 'yes', 'on'].includes(String(value ?? '').toLowerCase());
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
    parsed[key] = inlineValue ?? argv[++i] ?? 'true';
  }
  return parsed;
}
