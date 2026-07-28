import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { Readable } from 'node:stream';
import zlib from 'node:zlib';

test('all fetchers export matching sourceCode and run()', async () => {
  const files = (await fs.readdir('plugins/fetchers/sources')).filter((file) => file.endsWith('.mjs')).sort();
  assert.ok(files.length >= 10);
  for (const file of files) {
    const source = path.basename(file, '.mjs');
    const mod = await import(`../../plugins/fetchers/sources/${source}.mjs`);
    assert.equal(typeof mod.run, 'function', `${source} exports run`);
    assert.equal(mod.sourceCode, source);
  }
});

test('debian tracker package index is grouped into CVE records', async () => {
  const { groupByCve } = await import('../../plugins/fetchers/sources/debian-security-tracker.mjs');
  const records = groupByCve({
    apt: {
      'CVE-2011-3374': { releases: { bookworm: { status: 'open' } } },
      description: 'ignored'
    },
    zlib: {
      'CVE-2023-45853': { releases: { bookworm: { status: 'open' } } },
      'TEMP-123': { releases: { sid: { status: 'open' } } }
    }
  });

  assert.deepEqual([...records.keys()], ['CVE-2011-3374', 'CVE-2023-45853', 'TEMP-123']);
  assert.deepEqual(records.get('CVE-2011-3374'), {
    apt: { releases: { bookworm: { status: 'open' } } }
  });
});

test('exploit metadata sanitizer replaces only invalid Unicode surrogates', async () => {
  const { sanitizeUnicode } = await import('../../plugins/fetchers/lib/exploit-utils.mjs');
  assert.deepEqual(sanitizeUnicode({
    valid: 'before \uD83D\uDE00 after',
    invalid: ['high \uD800', 'low \uDC00']
  }), {
    valid: 'before \uD83D\uDE00 after',
    invalid: ['high \uFFFD', 'low \uFFFD']
  });
});

test('init checkpoints resume only matching incomplete imports and persist progress', async () => {
  const { resumeInitOffset, saveInitProgress } = await import('../../plugins/fetchers/lib/db.mjs');
  assert.equal(resumeInitOffset({ initComplete: false, initMode: 'full', offset: '500' }, { initMode: 'full' }), 500);
  assert.equal(resumeInitOffset({ initComplete: true, initMode: 'full', offset: 500 }, { initMode: 'full' }), 0);
  assert.equal(resumeInitOffset({ initComplete: false, initMode: 'full', offset: 500 }, { initMode: 'incremental' }), 0);
  assert.equal(resumeInitOffset({ initComplete: false, initMode: 'full', offset: -1 }, { initMode: 'full' }), 0);

  const queries = [];
  const ctx = { source: { id: 'source-id', checkpoint_json: {} } };
  const next = await saveInitProgress({
    query: async (sql, values) => queries.push({ sql, values })
  }, ctx, { initMode: 'full', offset: 500 });

  assert.deepEqual(next, { initMode: 'full', offset: 500, initComplete: false });
  assert.equal(JSON.parse(queries[0].values[1]).offset, 500);
  assert.strictEqual(ctx.source.checkpoint_json, next);
});

test('DuckDB scheduler defaults to blocking automatic baseline imports on every due-run path', async () => {
  const scheduler = await fs.readFile('src/VulTrack.App/DuckDbFirstScheduler.cs', 'utf8');
  const program = await fs.readFile('src/VulTrack.App/Program.cs', 'utf8');
  const envExample = await fs.readFile('.env.example', 'utf8');
  assert.match(scheduler, /EnvBool\("DUCKDB_ALLOW_AUTOMATIC_INIT", false\)/);
  assert.match(scheduler, /"nvd-cve" or "nvd-cve-init" => "nvd-cve-init"/);
  assert.match(scheduler, /"osv" or "osv-init" => "osv-init"/);
  assert.match(scheduler, /checkpoint\?\["initComplete"\].*== false\)\s*return RequireAutomaticInit/s);
  assert.match(scheduler, /sourceCode\.EndsWith\("-init"[\s\S]*return RequireAutomaticInit/);
  assert.match(scheduler, /HasSourceRecordsAsync\(sourceCode, ct\)\) return sourceCode;\s*return RequireAutomaticInit/s);
  assert.match(program, /admin\.scheduler\.runDue[\s\S]*duckScheduler\.RunCycleAsync\(ct\)/);
  assert.match(envExample, /^DUCKDB_ALLOW_AUTOMATIC_INIT=false$/m);
  for (const composeFile of ['docker-compose.yml', 'docker-compose.duckdb.yml', 'docker-compose.prod.yml']) {
    const compose = await fs.readFile(composeFile, 'utf8');
    assert.doesNotMatch(compose, /^\s+DUCKDB_ALLOW_AUTOMATIC_INIT:/m);
  }
});

test('Compose env files are not overridden by interpolated runtime defaults', async () => {
  const runtimeKeys = [
    'VULTRACK_DUCKDB_MEMORY_LIMIT',
    'VULTRACK_DUCKDB_THREADS',
    'VULTRACK_SCHEDULER_ENABLED',
    'DUCKDB_FETCH_SOURCES',
    'DUCKDB_FETCH_INTERVAL_SECONDS',
    'DUCKDB_FETCH_INITIAL_DELAY_SECONDS',
    'DUCKDB_ALLOW_AUTOMATIC_INIT',
    'VULTRACK_AI_ENABLED'
  ];
  for (const composeFile of ['docker-compose.yml', 'docker-compose.duckdb.yml', 'docker-compose.prod.yml']) {
    const compose = await fs.readFile(composeFile, 'utf8');
    for (const key of runtimeKeys) {
      assert.doesNotMatch(compose, new RegExp(`^\\s+${key}:`, 'm'), `${composeFile} does not override ${key}`);
    }
  }

  const production = await fs.readFile('docker-compose.prod.yml', 'utf8');
  assert.match(production, /path: \.env\.production\s+required: false/);
  assert.match(production, /"\$\{VULTRACK_HTTP_PORT:-3000\}:80"/);
});

test('FIRST EPSS is excluded from default DuckDB scheduler sources until delta state is accepted', async () => {
  const scheduler = await fs.readFile('src/VulTrack.App/DuckDbFirstScheduler.cs', 'utf8');
  const program = await fs.readFile('src/VulTrack.App/Program.cs', 'utf8');
  const envExample = await fs.readFile('.env.example', 'utf8');
  assert.match(scheduler, /\?\? "nvd-cve,osv,cisa-kev,exploitdb,nuclei-templates"/);
  assert.match(program, /\?\? "nvd-cve,osv,cisa-kev,exploitdb,nuclei-templates"/);
  assert.match(envExample, /^DUCKDB_FETCH_SOURCES=nvd-cve,osv,cisa-kev,exploitdb,nuclei-templates$/m);
});

test('OSV incremental streams only records newer than its baseline cursor', async () => {
  const result = await runOsvIncremental({
    checkpoint: { bootstrapRequired: true, indexEtag: 'old-index' },
    bootstrapWatermark: '2026-01-01T00:00:00Z',
    csv: [
      '2026-01-03T00:00:00Z,PyPI/OSV-NEW-A',
      '2026-01-03T00:00:00Z,PyPI/OSV-NEW-B',
      '2025-12-31T23:59:59Z,PyPI/OSV-OLD'
    ].join('\n'),
    etag: 'index-v1'
  });

  assert.equal(result.result.fetchedCount, 2);
  assert.deepEqual(result.fetchedIds, ['PyPI/OSV-NEW-A', 'PyPI/OSV-NEW-B']);
  assert.deepEqual(result.spoolIds, ['OSV-NEW-A', 'OSV-NEW-B']);
  assert.deepEqual(result.result.checkpoint.cursor, {
    modifiedAt: '2026-01-03T00:00:00Z',
    ids: ['PyPI/OSV-NEW-A', 'PyPI/OSV-NEW-B']
  });
  assert.deepEqual(result.fetchHeaders, {});
  assert.equal(result.result.checkpoint.indexEtag, 'index-v1');
});

test('OSV incremental retains same-timestamp cursor ties and honors a 304 response', async () => {
  const first = await runOsvIncremental({
    checkpoint: {
      cursor: { modifiedAt: '2026-01-03T00:00:00Z', ids: ['PyPI/OSV-EXISTING'] },
      indexEtag: 'index-v1'
    },
    csv: [
      '2026-01-03T00:00:00Z,PyPI/OSV-EXISTING',
      '2026-01-03T00:00:00Z,PyPI/OSV-LATE-TIE',
      '2026-01-02T00:00:00Z,PyPI/OSV-OLD'
    ].join('\n'),
    etag: 'index-v2'
  });
  assert.deepEqual(first.fetchedIds, ['PyPI/OSV-LATE-TIE']);
  assert.deepEqual(first.result.checkpoint.cursor.ids, ['PyPI/OSV-EXISTING', 'PyPI/OSV-LATE-TIE']);

  const second = await runOsvIncremental({
    checkpoint: first.result.checkpoint,
    status: 304,
    etag: 'index-v2'
  });
  assert.equal(second.result.fetchedCount, 0);
  assert.equal(second.result.checkpoint.skipped, 'not-modified');
  assert.deepEqual(second.fetchHeaders, { 'if-none-match': 'index-v2' });
  assert.deepEqual(second.fetchedIds, []);
  assert.deepEqual(second.spoolIds, []);
});

test('OSV incremental refuses to create a broad catch-up without a baseline cursor', async () => {
  const result = await runOsvIncremental({
    checkpoint: {},
    csv: '2026-01-03T00:00:00Z,PyPI/OSV-NEW-A\n',
    etag: 'index-v1'
  });
  assert.equal(result.result.fetchedCount, 0);
  assert.equal(result.result.checkpoint.bootstrapRequired, true);
  assert.equal(result.result.checkpoint.skipped, 'missing-baseline-cursor');
  assert.deepEqual(result.fetchHeaders, {});
  assert.deepEqual(result.fetchedIds, []);
  assert.deepEqual(result.spoolIds, []);
});

test('OSV pending batches never send conditional headers and resume from their exact boundary', async () => {
  const csv = [
    '2026-01-03T00:00:00.000000002Z,PyPI/OSV-NEW-A',
    '2026-01-03T00:00:00.000000001Z,PyPI/OSV-NEW-B',
    '2026-01-01T00:00:00Z,PyPI/OSV-OLD'
  ].join('\n');
  const first = await runOsvIncremental({
    checkpoint: {},
    bootstrapWatermark: '2026-01-01T00:00:00Z',
    csv,
    etag: 'index-v1',
    maxRecords: 1
  });
  assert.deepEqual(first.fetchedIds, ['PyPI/OSV-NEW-A']);
  assert.equal(first.result.checkpoint.pending.indexEtag, 'index-v1');
  assert.deepEqual(first.result.checkpoint.pending.resume, {
    modifiedAt: '2026-01-03T00:00:00.000000002Z',
    ids: ['PyPI/OSV-NEW-A']
  });

  const unexpected304 = await runOsvIncremental({
    checkpoint: first.result.checkpoint,
    status: 304,
    etag: 'index-v1',
    maxRecords: 1
  });
  assert.deepEqual(unexpected304.fetchHeaders, {});
  assert.deepEqual(unexpected304.result.checkpoint.pending, first.result.checkpoint.pending);

  const second = await runOsvIncremental({
    checkpoint: first.result.checkpoint,
    csv,
    etag: 'index-v1',
    maxRecords: 1
  });
  assert.deepEqual(second.fetchHeaders, {});
  assert.deepEqual(second.fetchedIds, ['PyPI/OSV-NEW-B']);
  assert.equal(second.result.checkpoint.pending.resume.modifiedAt, '2026-01-03T00:00:00.000000001Z');
});

test('OSV restarts pending work from the base cursor when the index version changes', async () => {
  const checkpoint = {
    cursor: { modifiedAt: '2026-01-01T00:00:00Z', ids: [] },
    pending: {
      baseCursor: { modifiedAt: '2026-01-01T00:00:00Z', ids: [] },
      indexEtag: 'index-v1',
      indexLastModified: null,
      resume: { modifiedAt: '2026-01-03T00:00:00.000000001Z', ids: ['PyPI/OSV-UPDATED'] }
    }
  };
  const result = await runOsvIncremental({
    checkpoint,
    csv: [
      '2026-01-03T00:00:00.000000002Z,PyPI/OSV-UPDATED',
      '2026-01-03T00:00:00.000000001Z,PyPI/OSV-OTHER',
      '2026-01-01T00:00:00Z,PyPI/OSV-OLD'
    ].join('\n'),
    etag: 'index-v2',
    maxRecords: 1
  });
  assert.deepEqual(result.fetchHeaders, {});
  assert.deepEqual(result.fetchedIds, ['PyPI/OSV-UPDATED']);
  assert.equal(result.result.checkpoint.pending.indexEtag, 'index-v2');
  assert.deepEqual(result.result.checkpoint.pending.resume, {
    modifiedAt: '2026-01-03T00:00:00.000000002Z',
    ids: ['PyPI/OSV-UPDATED']
  });
});

test('OSV compares RFC3339 fractional seconds without millisecond rounding', async () => {
  const result = await runOsvIncremental({
    checkpoint: {
      cursor: { modifiedAt: '2026-01-03T00:00:00.123456789Z', ids: ['PyPI/OSV-EXISTING'] }
    },
    csv: [
      '2026-01-03T00:00:00.1234567891Z,PyPI/OSV-NANOSECOND-NEW',
      '2026-01-03T00:00:00.123456789Z,PyPI/OSV-EXISTING',
      '2026-01-03T00:00:00.123456788999999999Z,PyPI/OSV-OLD'
    ].join('\n'),
    etag: 'index-v1'
  });
  assert.deepEqual(result.fetchedIds, ['PyPI/OSV-NANOSECOND-NEW']);
});

test('OSV stops and destroys an index stream once its cursor is reached', async () => {
  let sent = false;
  const body = new Readable({
    read() {
      if (!sent) {
        sent = true;
        this.push('2026-01-01T00:00:00Z,PyPI/OSV-OLD\n');
      }
    }
  });
  const result = await runOsvIncremental({
    checkpoint: { cursor: { modifiedAt: '2026-01-02T00:00:00Z', ids: [] } },
    body,
    etag: 'index-v1'
  });
  assert.equal(result.result.fetchedCount, 0);
  assert.equal(body.destroyed, true);
});

test('FIRST EPSS writes only changed rows after an atomic compact-state baseline', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-epss-delta-'));
  const baseline = epssCsv([
    'CVE-2026-0001,0.01,0.10',
    'CVE-2026-0002,0.02,0.20',
    'CVE-2026-0003,0.03,0.30'
  ]);
  try {
    const first = await runEpssDelta({ root, csv: baseline, allowBaseline: true });
    assert.equal(first.result.fetchedCount, 3);
    assert.equal(first.result.changedCount, 3);
    assert.deepEqual(first.spoolIds, ['CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003']);
    assert.equal(first.stateExists, true);

    const second = await runEpssDelta({
      root,
      checkpoint: first.result.checkpoint,
      csv: epssCsv([
        'CVE-2026-0001,0.01,0.10',
        'CVE-2026-0002,0.025,0.20',
        'CVE-2026-0003,0.03,0.30'
      ])
    });
    assert.equal(second.result.fetchedCount, 3);
    assert.equal(second.result.changedCount, 1);
    assert.deepEqual(second.spoolIds, ['CVE-2026-0002']);
    assert.equal(second.stateExists, true);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('FIRST EPSS sidecar never advances before its matching spool is ready', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-epss-atomic-'));
  const previous = captureEpssEnv();
  process.env.VULTRACK_STORAGE_BACKEND = 'duckdb';
  process.env.VULTRACK_SPOOL_PATH = root;
  process.env.EPSS_DELTA_ALLOW_BASELINE = '1';
  try {
    const { withClient, rollbackWriteBatch } = await import('../../plugins/fetchers/lib/db.mjs');
    const { runEpssDelta } = await import('../../plugins/fetchers/sources/first-epss.mjs');
    await withClient(async (client) => {
      const result = await runEpssDelta(client, {
        source: { id: 'first-epss', code: 'first-epss', checkpoint_json: {} },
        run: { id: 'atomic-test' }
      }, { fetchGzip: async () => zlib.gzipSync(epssCsv(['CVE-2026-0001,0.01,0.10'])) });
      assert.equal(result.changedCount, 1);
      await assert.rejects(fs.access(path.join(root, 'state', 'first-epss.delta.v1.tsv.gz')));
      const incoming = await fs.readdir(path.join(root, 'incoming'));
      assert.equal(incoming.some((file) => file.endsWith('.partial')), true);
      await rollbackWriteBatch(client);
    });
    const stateFiles = await fs.readdir(path.join(root, 'state')).catch(() => []);
    const incomingFiles = await fs.readdir(path.join(root, 'incoming')).catch(() => []);
    assert.equal(stateFiles.some((file) => file.includes('first-epss.delta')), false);
    assert.equal(incomingFiles.some((file) => file.endsWith('.partial')), false);
  } finally {
    restoreEpssEnv(previous);
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('FIRST EPSS fails closed without a delta baseline or when a daily bulk delta exceeds its cap', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-epss-cap-'));
  const csv = epssCsv([
    'CVE-2026-0001,0.01,0.10',
    'CVE-2026-0002,0.02,0.20',
    'CVE-2026-0003,0.03,0.30'
  ]);
  try {
    const missing = await runEpssDelta({ root, csv });
    assert.equal(missing.result.changedCount, 0);
    assert.equal(missing.result.checkpoint.skipped, 'delta-state-required');
    assert.deepEqual(missing.spoolIds, []);

    const baseline = await runEpssDelta({ root, csv, allowBaseline: true });
    await assert.rejects(
      () => runEpssDelta({
        root,
        checkpoint: baseline.result.checkpoint,
        maxChangedRows: 2,
        csv: epssCsv([
          'CVE-2026-0001,0.11,0.11',
          'CVE-2026-0002,0.12,0.12',
          'CVE-2026-0003,0.13,0.13'
        ])
      }),
      /EPSS_DELTA_MAX_CHANGED_ROWS=2/
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

function epssCsv(rows) {
  return ['#model_version: test', 'cve,epss,percentile', ...rows].join('\n');
}

async function runEpssDelta({ root, checkpoint = {}, csv, allowBaseline = false, maxChangedRows }) {
  const previous = captureEpssEnv();
  process.env.VULTRACK_STORAGE_BACKEND = 'duckdb';
  process.env.VULTRACK_SPOOL_PATH = root;
  process.env.EPSS_DELTA_ALLOW_BASELINE = allowBaseline ? '1' : '0';
  process.env.EPSS_DELTA_ALLOW_BULK = '0';
  if (maxChangedRows === undefined) delete process.env.EPSS_DELTA_MAX_CHANGED_ROWS;
  else process.env.EPSS_DELTA_MAX_CHANGED_ROWS = String(maxChangedRows);
  try {
    const { withClient, flushWriteBatch } = await import('../../plugins/fetchers/lib/db.mjs');
    const { runEpssDelta: run } = await import('../../plugins/fetchers/sources/first-epss.mjs');
    const incoming = path.join(root, 'incoming');
    const existingReady = new Set((await fs.readdir(incoming).catch(() => [])).filter((file) => file.endsWith('.ready')));
    const result = await withClient(async (client) => {
      const current = await run(client, {
        source: { id: 'first-epss', code: 'first-epss', checkpoint_json: checkpoint },
        run: { id: `epss-${Math.random().toString(16).slice(2)}` }
      }, { fetchGzip: async () => zlib.gzipSync(csv) });
      await flushWriteBatch(client);
      return current;
    });
    const spoolIds = [];
    for (const file of (await fs.readdir(incoming).catch(() => [])).filter((file) => file.endsWith('.ready') && !existingReady.has(file))) {
      const lines = (await fs.readFile(path.join(incoming, file), 'utf8')).trim().split('\n').filter(Boolean);
      spoolIds.push(...lines.map((line) => JSON.parse(line).externalKey));
    }
    return {
      result,
      spoolIds,
      stateExists: await fs.access(path.join(root, 'state', 'first-epss.delta.v1.tsv.gz')).then(() => true, () => false)
    };
  } finally {
    restoreEpssEnv(previous);
  }
}

function captureEpssEnv() {
  return Object.fromEntries([
    'VULTRACK_STORAGE_BACKEND',
    'VULTRACK_SPOOL_PATH',
    'EPSS_DELTA_ALLOW_BASELINE',
    'EPSS_DELTA_ALLOW_BULK',
    'EPSS_DELTA_MAX_CHANGED_ROWS'
  ].map((key) => [key, process.env[key]]));
}

function restoreEpssEnv(previous) {
  for (const [key, value] of Object.entries(previous)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

async function runOsvIncremental({ checkpoint, bootstrapWatermark, csv = '', etag, status = 200, maxRecords, body }) {
  const previousBackend = process.env.VULTRACK_STORAGE_BACKEND;
  const previousPath = process.env.VULTRACK_SPOOL_PATH;
  const previousMax = process.env.OSV_FETCH_MAX_RECORDS;
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-osv-incremental-'));
  process.env.VULTRACK_STORAGE_BACKEND = 'duckdb';
  process.env.VULTRACK_SPOOL_PATH = root;
  if (maxRecords === undefined) delete process.env.OSV_FETCH_MAX_RECORDS;
  else process.env.OSV_FETCH_MAX_RECORDS = String(maxRecords);
  const fetchedIds = [];
  let fetchHeaders = null;
  try {
    const { withClient, flushWriteBatch } = await import('../../plugins/fetchers/lib/db.mjs');
    const { runOsvModifiedIdIncremental } = await import('../../plugins/fetchers/lib/osv-database.mjs');
    const result = await withClient(async (client) => {
      const ctx = {
        source: { id: 'osv', code: 'osv', checkpoint_json: checkpoint, has_records: true },
        run: { id: 'run-test' }
      };
      const current = await runOsvModifiedIdIncremental(client, ctx, {
        bootstrapWatermark,
        fetchIndex: async (_url, request) => {
          fetchHeaders = request.headers;
          return {
            status,
            ok: status >= 200 && status < 300,
            headers: new Map(etag ? [['etag', etag]] : []),
            body: status === 304 ? null : (body ?? Readable.from([csv]))
          };
        },
        fetchItem: async (rawId) => {
          fetchedIds.push(rawId);
          return { id: rawId.split('/').at(-1), modified: '2026-01-03T00:00:00Z' };
        }
      });
      await flushWriteBatch(client);
      return current;
    });
    const incoming = path.join(root, 'incoming');
    const files = await fs.readdir(incoming).catch(() => []);
    const spoolIds = [];
    for (const file of files) {
      const lines = (await fs.readFile(path.join(incoming, file), 'utf8')).trim().split('\n').filter(Boolean);
      spoolIds.push(...lines.map((line) => JSON.parse(line).externalKey));
    }
    return { result, fetchedIds, fetchHeaders, spoolIds };
  } finally {
    if (previousBackend === undefined) delete process.env.VULTRACK_STORAGE_BACKEND;
    else process.env.VULTRACK_STORAGE_BACKEND = previousBackend;
    if (previousPath === undefined) delete process.env.VULTRACK_SPOOL_PATH;
    else process.env.VULTRACK_SPOOL_PATH = previousPath;
    if (previousMax === undefined) delete process.env.OSV_FETCH_MAX_RECORDS;
    else process.env.OSV_FETCH_MAX_RECORDS = previousMax;
    await fs.rm(root, { recursive: true, force: true });
  }
}

test('DuckDB fetch backend writes one atomic spool batch without PostgreSQL', async () => {
  const previousBackend = process.env.VULTRACK_STORAGE_BACKEND;
  const previousPath = process.env.VULTRACK_SPOOL_PATH;
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-spool-'));
  process.env.VULTRACK_STORAGE_BACKEND = 'duckdb';
  process.env.VULTRACK_SPOOL_PATH = root;
  try {
    const { withClient, getSource, startRun, writeRecord, flushWriteBatch, finishRun } =
      await import('../../plugins/fetchers/lib/db.mjs');
    await withClient(async (client) => {
      const source = await getSource(client, 'osv-init');
      const run = await startRun(client, source.id, 'test');
      const ctx = { source, run };
      await writeRecord(client, ctx, {
        externalKey: 'OSV-TEST-1',
        identifiers: ['CVE-2026-1'],
        payload: { id: 'OSV-TEST-1', aliases: ['CVE-2026-1'] }
      });
      await flushWriteBatch(client);
      await finishRun(client, run.id, {
        status: 'succeeded',
        fetchedCount: 1,
        parsedCount: 1,
        checkpoint: { done: true }
      });
    });

    const files = await fs.readdir(path.join(root, 'incoming'));
    assert.equal(files.length, 1);
    assert.match(files[0], /^osv-init-.*\.ndjson\.ready$/);
    const line = JSON.parse((await fs.readFile(path.join(root, 'incoming', files[0]), 'utf8')).trim());
    assert.equal(line.sourceCode, 'osv-init');
    assert.equal(line.externalKey, 'OSV-TEST-1');
    assert.deepEqual(line.payload.aliases, ['CVE-2026-1']);
    const state = JSON.parse(await fs.readFile(path.join(root, 'state', 'osv-init.json'), 'utf8'));
    assert.equal(state.lastRun.status, 'succeeded');
    assert.equal(state.checkpoint.done, true);
  } finally {
    if (previousBackend === undefined) delete process.env.VULTRACK_STORAGE_BACKEND;
    else process.env.VULTRACK_STORAGE_BACKEND = previousBackend;
    if (previousPath === undefined) delete process.env.VULTRACK_SPOOL_PATH;
    else process.env.VULTRACK_SPOOL_PATH = previousPath;
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('DuckDB fetch backend commits resumable spool segments atomically', async () => {
  const previousBackend = process.env.VULTRACK_STORAGE_BACKEND;
  const previousPath = process.env.VULTRACK_SPOOL_PATH;
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-spool-segments-'));
  process.env.VULTRACK_STORAGE_BACKEND = 'duckdb';
  process.env.VULTRACK_SPOOL_PATH = root;
  try {
    const { withClient, getSource, startRun, writeRecord, commitSpoolSegment, flushWriteBatch, finishRun } =
      await import('../../plugins/fetchers/lib/db.mjs');
    await withClient(async (client) => {
      const source = await getSource(client, 'nvd-cve-init');
      const run = await startRun(client, source.id, 'test');
      const ctx = { source, run };
      await writeRecord(client, ctx, { externalKey: 'CVE-2002-0001', identifiers: ['CVE-2002-0001'], payload: { id: 'CVE-2002-0001' } });
      await commitSpoolSegment(client, source.id, { initComplete: false, year: 2003 });
      await writeRecord(client, ctx, { externalKey: 'CVE-2003-0001', identifiers: ['CVE-2003-0001'], payload: { id: 'CVE-2003-0001' } });
      await commitSpoolSegment(client, source.id, { initComplete: false, year: 2004 });
      await flushWriteBatch(client);
      await finishRun(client, run.id, { status: 'succeeded', fetchedCount: 2, parsedCount: 2, checkpoint: { initComplete: false, year: 2004 } });
    });

    const files = (await fs.readdir(path.join(root, 'incoming'))).sort();
    assert.equal(files.length, 2);
    assert.ok(files.some(file => /^nvd-cve-init-.*-s0000\.ndjson\.ready$/.test(file)));
    assert.ok(files.some(file => /^nvd-cve-init-.*-s0001\.ndjson\.ready$/.test(file)));
    const segments = await Promise.all(files.map(async file => JSON.parse((await fs.readFile(path.join(root, 'incoming', file), 'utf8')).trim())));
    assert.equal(segments.filter(segment => segment.sourceMode === null).length, 1);
    assert.equal(segments.filter(segment => segment.sourceMode === 'append').length, 1);
    const state = JSON.parse(await fs.readFile(path.join(root, 'state', 'nvd-cve-init.json'), 'utf8'));
    assert.equal(state.checkpoint.year, 2004);
    assert.equal(state.hasRecords, true);
  } finally {
    if (previousBackend === undefined) delete process.env.VULTRACK_STORAGE_BACKEND;
    else process.env.VULTRACK_STORAGE_BACKEND = previousBackend;
    if (previousPath === undefined) delete process.env.VULTRACK_SPOOL_PATH;
    else process.env.VULTRACK_SPOOL_PATH = previousPath;
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('raw store none keeps only the raw index and skips unchanged staging writes', async () => {
  const previous = process.env.RAW_OBJECT_STORE;
  process.env.RAW_OBJECT_STORE = 'none';
  try {
    const { writeRecord } = await import('../../plugins/fetchers/lib/db.mjs');
    const { upsertNvdCve } = await import('../../plugins/fetchers/lib/staging.mjs');
    const queries = [];
    const client = {
      query: async (sql, values) => {
        queries.push({ sql, values });
        if (sql === 'begin') return { rowCount: 0, rows: [] };
        if (sql.includes('select id') && sql.includes('source_raw_index')) return { rowCount: 0, rows: [] };
        if (sql.includes('insert into source_raw_index')) return { rowCount: 1, rows: [{ id: 'raw-id' }] };
        throw new Error(`Unexpected query: ${sql}`);
      }
    };
    const ctx = { source: { id: 'source-id', code: 'nvd-cve' }, run: { id: 'run-id' } };
    const id = await writeRecord(client, ctx, { externalKey: 'CVE-2026-1', payload: { id: 'CVE-2026-1' } });
    assert.equal(id, 'raw-id');
    assert.equal(queries.some((x) => x.sql.includes('source_objects')), false);
    assert.equal(queries.find((x) => x.sql.includes('insert into source_raw_index')).values[2], null);

    let stagingQueried = false;
    await upsertNvdCve({ query: async () => { stagingQueried = true; } }, null, {});
    assert.equal(stagingQueried, false);
  } finally {
    if (previous === undefined) delete process.env.RAW_OBJECT_STORE;
    else process.env.RAW_OBJECT_STORE = previous;
  }
});

test('unchanged normalized records bypass raw storage and staging', async () => {
  const previous = process.env.RAW_OBJECT_STORE;
  process.env.RAW_OBJECT_STORE = 'none';
  try {
    const { writeRecord } = await import('../../plugins/fetchers/lib/db.mjs');
    const queries = [];
    const client = {
      query: async (sql, values) => {
        queries.push({ sql, values });
        if (sql === 'begin') return { rowCount: 0, rows: [] };
        if (sql.includes('select id') && sql.includes('source_raw_index')) {
          return { rowCount: 1, rows: [{ id: 'existing-raw-id' }] };
        }
        if (sql.includes('update source_raw_index')) return { rowCount: 1, rows: [] };
        throw new Error(`Unexpected query: ${sql}`);
      }
    };
    const ctx = { source: { id: 'source-id', code: 'nvd-cve' }, run: { id: 'run-id' } };
    const id = await writeRecord(client, ctx, { externalKey: 'CVE-2026-1', payload: { id: 'CVE-2026-1' } });
    assert.equal(id, null);
    assert.equal(queries.length, 3);
    assert.equal(queries.some((x) => x.sql.includes('insert into source_objects')), false);
  } finally {
    if (previous === undefined) delete process.env.RAW_OBJECT_STORE;
    else process.env.RAW_OBJECT_STORE = previous;
  }
});

test('CVE List v5 requires full import without a completed checkpoint or raw source records', async () => {
  const { shouldRunFullImport } = await import('../../plugins/fetchers/sources/cve-list-v5.mjs');
  assert.equal(shouldRunFullImport({}, true), true);
  assert.equal(shouldRunFullImport({ initComplete: false }, true), true);
  assert.equal(shouldRunFullImport({ initComplete: true }, true), true);
  assert.equal(shouldRunFullImport({ initComplete: true }, false), true);
  assert.equal(shouldRunFullImport({ initComplete: true, commit: 'abc123' }, true), false);
});

test('PoC fetchers keep authoritative CVE primary identifiers only', async () => {
  const { nucleiIdentifiers } = await import('../../plugins/fetchers/sources/nuclei-templates.mjs');
  const { trickestCveFromFilename } = await import('../../plugins/fetchers/sources/trickest-cve.mjs');
  const { pocGithubCveFromPath } = await import('../../plugins/fetchers/sources/poc-in-github.mjs');

  assert.deepEqual(nucleiIdentifiers({
    id: 'CVE-2021-44228',
    info: {
      classification: { 'cve-id': 'CVE-2021-44228' },
      tags: 'cve,CVE-2021-45046',
      reference: ['https://example.test/CVE-2022-0070']
    }
  }), ['CVE-2021-44228']);
  assert.equal(trickestCveFromFilename('CVE-2021-44228.md'), 'CVE-2021-44228');
  assert.equal(trickestCveFromFilename('notes-CVE-2021-45046.md'), null);
  assert.equal(pocGithubCveFromPath('/mirror/2021/CVE-2021-44228.json'), 'CVE-2021-44228');
  assert.equal(pocGithubCveFromPath('/mirror/2021/log4j-notes.json'), null);
});

test('Nuclei fetcher refuses truncated revisions without advancing the completed checkpoint', async () => {
  const { nucleiSnapshotPlan } = await import('../../plugins/fetchers/sources/nuclei-templates.mjs');
  const rejected = nucleiSnapshotPlan({
    gitRevision: 'revision-a',
    completedGitRevision: 'revision-a',
    snapshotComplete: true
  }, 'revision-b', 4348, 100);
  assert.equal(rejected.snapshotComplete, false);
  assert.equal(rejected.checkpoint.snapshotComplete, false);
  assert.equal(rejected.checkpoint.completedGitRevision, 'revision-a');
  assert.equal(rejected.checkpoint.gitRevision, 'revision-a');
  assert.equal(rejected.checkpoint.observedGitRevision, 'revision-b');
  assert.equal(rejected.checkpoint.skipped, false);

  const complete = nucleiSnapshotPlan({}, 'revision-b', 4348, 5000);
  assert.equal(complete.snapshotComplete, true);
  assert.equal(complete.checkpoint.snapshotComplete, true);
  assert.equal(complete.checkpoint.completedGitRevision, 'revision-b');
});

test('Nuclei DuckDB projection applies a complete revision before finalizing the spool', async () => {
  const spool = await fs.readFile('src/VulTrack.App/DuckDbEvidenceNormalizer.Spool.cs', 'utf8');
  const store = await fs.readFile('src/VulTrack.App/DuckDbEvidenceStore.cs', 'utf8');
  const legacyNormalizer = await fs.readFile('src/VulTrack.App/DuckDbEvidenceNormalizer.cs', 'utf8');
  const fetcher = await fs.readFile('plugins/fetchers/sources/nuclei-templates.mjs', 'utf8');

  assert.match(fetcher, /const templates = \[\]/);
  assert.doesNotMatch(fetcher, /commitSpoolSegment/);
  assert.match(fetcher, /snapshotComplete: true/);
  assert.match(spool, /Nuclei spool record is not a complete revision snapshot/);
  assert.match(spool, /EnsureCurrentNucleiSnapshot\(nucleiSnapshotId\)/);
  assert.match(spool, /ApplyNucleiSnapshotAsync\(exploitBatch, nucleiSnapshotId!, ct\)/);
  assert.ok(
    spool.indexOf('ApplyNucleiSnapshotAsync(exploitBatch, nucleiSnapshotId!, ct)') <
    spool.indexOf('File.Move(processingPath, stagedPath, overwrite: true)')
  );
  assert.doesNotMatch(spool, /CompleteNucleiSnapshotAsync/);

  const nucleiApply = store.slice(
    store.indexOf('public async Task<DuckDbNucleiSnapshotStats> ApplyNucleiSnapshotAsync'),
    store.indexOf('public async Task UpsertExploitProjectionAsync')
  );
  assert.match(nucleiApply, /UpsertExploitRowsAsync\(connection, uniqueRows, snapshotId, ct\)/);
  assert.match(nucleiApply, /snapshot_id is distinct from \{SqlValue\(snapshotId\)\}/);
  assert.match(nucleiApply, /Nuclei snapshot verification failed/);
  assert.doesNotMatch(nucleiApply, /delete from exploits/i);

  const rowsUpsert = store.slice(
    store.indexOf('private async Task UpsertExploitRowsAsync'),
    store.indexOf('private async Task CopyThreatScoresAsync')
  );
  assert.match(rowsUpsert, /update exploits target/i);
  assert.match(rowsUpsert, /where not exists \(/i);
  assert.doesNotMatch(rowsUpsert, /delete from exploits/i);
  assert.match(store, /snapshot_id varchar/);
  assert.match(store, /is_active boolean default true/);
  assert.match(store, /where coalesce\(is_active, true\)/);
  assert.match(store, /from source_records\s+where source_code <> 'nuclei-templates'/);

  const legacyExploitLoader = legacyNormalizer.slice(
    legacyNormalizer.indexOf('private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadExploitAsync'),
    legacyNormalizer.indexOf('private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadCnnvdAsync')
  );
  assert.match(legacyExploitLoader, /await store\.UpsertExploitProjectionAsync\(exploits, ct\)/);
  assert.doesNotMatch(legacyExploitLoader, /DeleteDuckRows\(conn, "exploits"/);
});

test('china advisory identifiers collect domestic ids and CVEs', async () => {
  const { chinaIdentifiers } = await import('../../plugins/fetchers/lib/china-advisory.mjs');
  assert.deepEqual(chinaIdentifiers(
    'CNNVD-202605-6652 CVE-2026-4888',
    ['CNVD-2024-12345', 'SSV-99969', 'AVD-2024-1234', 'CT-3888079', 'NSFOCUS-142883', 'CERT360-663c2362c09f255b91b17fdd']
  ), [
    'CVE-2026-4888',
    'CNNVD-202605-6652',
    'CNVD-2024-12345',
    'SSV-99969',
    'AVD-2024-1234',
    'CT-3888079',
    'NSFOCUS-142883',
    'CERT360-663C2362C09F255B91B17FDD'
  ]);
});

test('CNNVD baseline resumes saved pages and migrates legacy checkpoints', async () => {
  const { cnnvdBaselinePage } = await import('../../plugins/fetchers/sources/cnnvd.mjs');
  assert.equal(cnnvdBaselinePage({}, 0, 50), 1);
  assert.equal(cnnvdBaselinePage({ nextPage: 17 }, 50, 50), 17);
  assert.equal(cnnvdBaselinePage({ modifiedAt: '2026-06-01T00:00:00Z' }, 5022, 50), 101);
});

test('domestic HTML fetcher parsers keep source ids and PoC signals', async () => {
  const { parseRows: parseSeebug } = await import('../../plugins/fetchers/sources/seebug.mjs');
  const { parseRows: parseAliyun } = await import('../../plugins/fetchers/sources/aliyun-avd.mjs');
  const { parseRows: parseNsfocus, parseDetail } = await import('../../plugins/fetchers/sources/nsfocus-vulndb.mjs');

  assert.deepEqual(parseSeebug(`
    <tr><td class="datetime">2026-05-01</td><td class="vul-level high"></td>
    <td><a class="vul-title" title="Example CVE-2026-1234" href="/vuldb/ssvid-99969">Example</a></td>
    <td><i class="fa fa-rocket" data-original-title="有 PoC"></i>
    <i class="fa fa-file-text-o" data-original-title="有详情"></i></td></tr>
  `)[0], {
    advisoryId: 'SSV-99969',
    title: 'Example CVE-2026-1234',
    publishedAt: '2026-05-01',
    severityLabel: 'high',
    identifiers: ['CVE-2026-1234'],
    pocAvailable: true,
    detailAvailable: true,
    sourceUrl: 'https://www.seebug.org/vuldb/ssvid-99969'
  });

  assert.equal(parseAliyun(`
    <tr><td>AVD-2024-1234</td><td><a href="/detail?id=AVD-2024-1234">Aliyun example</a></td>
    <td title="POC 已公开"></td><td>2026-05-02</td></tr>
  `)[0].pocAvailable, true);

  assert.equal(parseNsfocus(`
    <li><span>2026-05-03</span><a href="/vulndb/142883">NSFOCUS example</a></li>
  `)[0].advisoryId, 'NSFOCUS-142883');
  assert.equal(parseDetail(`
    <div align="center"><b>NSFOCUS example</b></div>
    <b>发布日期：</b>2026-05-03<br><b>更新日期：</b>2026-05-04<br>
    <b>受影响系统：</b><blockquote>Example Product</blockquote>
    <b>描述：</b><hr>Example description<b>建议：</b>
  `).description, 'Example description');
});
