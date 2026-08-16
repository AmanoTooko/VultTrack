import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { Readable } from 'node:stream';
import { spawnSync } from 'node:child_process';
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
  const { changedGitFiles, gitRevisionUnchanged, sanitizeUnicode } = await import('../../plugins/fetchers/lib/exploit-utils.mjs');
  assert.deepEqual(sanitizeUnicode({
    valid: 'before \uD83D\uDE00 after',
    invalid: ['high \uD800', 'low \uDC00']
  }), {
    valid: 'before \uD83D\uDE00 after',
    invalid: ['high \uFFFD', 'low \uFFFD']
  });
  assert.equal(gitRevisionUnchanged({ gitRevision: 'abc' }, 'abc', false), true);
  assert.equal(gitRevisionUnchanged({ gitRevision: 'abc' }, 'def', false), false);
  assert.equal(gitRevisionUnchanged({ gitRevision: 'abc' }, 'abc', true), false);

  const repo = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-git-diff-'));
  try {
    const git = (...args) => spawnSync('git', ['-C', repo, ...args], { encoding: 'utf8' });
    assert.equal(git('init').status, 0);
    assert.equal(git('config', 'user.email', 'test@vultrack.local').status, 0);
    assert.equal(git('config', 'user.name', 'VulTrack Test').status, 0);
    await fs.mkdir(path.join(repo, '2026'));
    await fs.writeFile(path.join(repo, '2026', 'CVE-2026-0001.json'), '{}');
    assert.equal(git('add', '.').status, 0);
    assert.equal(git('commit', '-m', 'baseline').status, 0);
    const baseline = git('rev-parse', 'HEAD').stdout.trim();
    await fs.writeFile(path.join(repo, '2026', 'CVE-2026-0001.json'), '{"changed":true}');
    assert.equal(git('commit', '-am', 'update').status, 0);
    const revision = git('rev-parse', 'HEAD').stdout.trim();
    const changed = changedGitFiles(
      { dir: repo, revision },
      baseline,
      (file) => file.endsWith('.json'));
    assert.deepEqual(changed, [path.join(repo, '2026', 'CVE-2026-0001.json')]);
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
  }
});

test('init checkpoints resume only matching incomplete imports and persist progress', async () => {
  const { resumeInitOffset, saveInitProgress } = await import('../../plugins/fetchers/lib/db.mjs');
  assert.equal(resumeInitOffset({ initComplete: false, initMode: 'full', offset: '500' }, { initMode: 'full' }), 500);
  assert.equal(resumeInitOffset({ initComplete: true, initMode: 'full', offset: 500 }, { initMode: 'full' }), 0);
  assert.equal(resumeInitOffset({ initComplete: false, initMode: 'full', offset: 500 }, { initMode: 'incremental' }), 0);
  assert.equal(resumeInitOffset({ initComplete: false, initMode: 'full', offset: -1 }, { initMode: 'full' }), 0);

  const client = {};
  const ctx = { source: { id: 'source-id', checkpoint_json: {} } };
  const next = await saveInitProgress(client, ctx, { initMode: 'full', offset: 500 });

  assert.deepEqual(next, { initMode: 'full', offset: 500, initComplete: false });
  assert.deepEqual(client.pendingCheckpoint, next);
  assert.strictEqual(ctx.source.checkpoint_json, next);
});

test('DuckDB scheduler defaults to blocking automatic baseline imports on every due-run path', async () => {
  const scheduler = await fs.readFile('src/VulTrack.App/DuckDbFirstScheduler.cs', 'utf8');
  const program = await fs.readFile('src/VulTrack.App/Program.cs', 'utf8');
  const options = await fs.readFile('src/VulTrack.App/VulTrackOptions.cs', 'utf8');
  const envExample = await fs.readFile('.env.example', 'utf8');
  assert.match(options, /BoolFlag\("DUCKDB_ALLOW_AUTOMATIC_INIT", false\)/);
  assert.match(scheduler, /options\.Scheduler\.AllowAutomaticInit/);
  assert.match(scheduler, /"nvd-cve" or "nvd-cve-init" => "nvd-cve-init"/);
  assert.match(scheduler, /"osv" or "osv-init" => "osv-init"/);
  assert.match(scheduler, /"ghsa" or "ghsa-init" => "ghsa-init"/);
  assert.match(scheduler, /GHSA_BOOTSTRAP_WATERMARK/);
  assert.match(scheduler, /sourceCode\.Equals\("google-osv"[\s\S]*MissingGoogleOsvCursor[\s\S]*OSV_BOOTSTRAP_WATERMARK/);
  assert.match(scheduler, /MissingGoogleOsvCursor\(JsonObject\? checkpoint\)/);
  assert.match(scheduler, /checkpoint\?\["initComplete"\].*== false\)\s*return RequireAutomaticInit/s);
  assert.match(scheduler, /sourceCode\.EndsWith\("-init"[\s\S]*return RequireAutomaticInit/);
  assert.match(scheduler, /HasSourceRecordsAsync\(sourceCode, ct\)\) return sourceCode;\s*return RequireAutomaticInit/s);
  assert.match(program, /AddHostedService\(serviceProvider => serviceProvider\.GetRequiredService<DuckDbFirstScheduler>\(\)\)/);
  assert.match(scheduler, /ExecuteAsync\(CancellationToken stoppingToken\)[\s\S]*RunCycleAsync\(stoppingToken\)/);
  assert.match(envExample, /^DUCKDB_ALLOW_AUTOMATIC_INIT=false$/m);
  for (const composeFile of ['docker-compose.yml', 'docker-compose.duckdb.yml', 'docker-compose.prod.yml']) {
    const compose = await fs.readFile(composeFile, 'utf8');
    assert.doesNotMatch(compose, /^\s+DUCKDB_ALLOW_AUTOMATIC_INIT:/m);
  }
});

test('GHSA repository baseline imports reviewed advisories, segments, and resumes', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-ghsa-init-'));
  const repository = path.join(root, 'repository');
  const spool = path.join(root, 'spool');
  const previous = Object.fromEntries([
    'VULTRACK_SPOOL_PATH',
    'GHSA_ADVISORY_REPOSITORY',
    'GHSA_ADVISORY_MIRROR_PATH',
    'GHSA_INIT_SEGMENT_SIZE',
    'FETCHER_MAX_RECORDS'
  ].map((key) => [key, process.env[key]]));
  try {
    await fs.mkdir(path.join(repository, 'advisories', 'github-reviewed', '2026', '01'), { recursive: true });
    await fs.mkdir(path.join(repository, 'advisories', 'unreviewed', '2026', '01'), { recursive: true });
    const reviewed = [
      ghsaOsv('GHSA-AAAA-BBBB-0001', '2026-01-01T00:00:00Z'),
      { id: 'NOT-GHSA-0002', modified: '2026-01-02T00:00:00Z' },
      ghsaOsv('GHSA-AAAA-BBBB-0003', '2026-01-03T00:00:00Z'),
      ghsaOsv('GHSA-AAAA-BBBB-0004', '2026-01-04T00:00:00Z')
    ];
    for (let index = 0; index < reviewed.length; index++) {
      await fs.writeFile(
        path.join(repository, 'advisories', 'github-reviewed', '2026', '01', `${index}.json`),
        JSON.stringify(reviewed[index]));
    }
    await fs.writeFile(
      path.join(repository, 'advisories', 'unreviewed', '2026', '01', 'ignored.json'),
      JSON.stringify(ghsaOsv('GHSA-UNRE-VIEW-0001', '2026-01-05T00:00:00Z')));
    const git = (...args) => spawnSync('git', ['-C', repository, ...args], { encoding: 'utf8' });
    assert.equal(git('init', '-b', 'main').status, 0);
    assert.equal(git('config', 'user.email', 'test@vultrack.local').status, 0);
    assert.equal(git('config', 'user.name', 'VulTrack Test').status, 0);
    assert.equal(git('add', '.').status, 0);
    assert.equal(git('commit', '-m', 'fixtures').status, 0);

    process.env.VULTRACK_SPOOL_PATH = spool;
    process.env.GHSA_ADVISORY_REPOSITORY = repository;
    process.env.GHSA_ADVISORY_MIRROR_PATH = path.join(root, 'mirror');
    process.env.GHSA_INIT_SEGMENT_SIZE = '1';
    process.env.FETCHER_MAX_RECORDS = '2';
    const first = await runFetcherModule('ghsa-init');
    assert.equal(first.fetchedCount, 2);
    assert.equal(first.checkpoint.initComplete, false);
    assert.equal(first.checkpoint.offset, 3);
    assert.equal(first.checkpoint.skippedEntries, 1);
    assert.equal(first.checkpoint.latestModified, '2026-01-03T00:00:00Z');

    process.env.FETCHER_MAX_RECORDS = '10';
    const second = await runFetcherModule('ghsa-init');
    assert.equal(second.fetchedCount, 1);
    assert.equal(second.checkpoint.initComplete, true);
    assert.equal(second.checkpoint.offset, 4);
    assert.equal(second.checkpoint.skippedEntries, 1);
    assert.equal(second.checkpoint.incrementalSince, first.checkpoint.incrementalSince);
    assert.equal(second.checkpoint.latestModified, '2026-01-04T00:00:00Z');

    const files = (await fs.readdir(path.join(spool, 'incoming'))).sort();
    assert.equal(files.length, 3);
    const lines = [];
    for (const file of files) {
      lines.push(...(await fs.readFile(path.join(spool, 'incoming', file), 'utf8'))
        .trim().split('\n').filter(Boolean).map(JSON.parse));
    }
    assert.deepEqual(lines.map((line) => line.externalKey).sort(), [
      'GHSA-AAAA-BBBB-0001',
      'GHSA-AAAA-BBBB-0003',
      'GHSA-AAAA-BBBB-0004'
    ]);
    assert.ok(lines.every((line) => line.sourceCode === 'ghsa-init'));
    assert.ok(lines.every((line) => line.externalKey !== 'GHSA-UNRE-VIEW-0001'));
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('OSV bulk selector keeps real boundary categories without duplicating spool records', async () => {
  const { profileOsvRecord, selectOsvRecords } = await import('../../scripts/select-osv-bulk-samples.mjs');
  const records = [
    boundaryOsv('GHSA-AAAA-BBBB-0001', [], []),
    boundaryOsv('OSV-ONE', ['CVE-2026-10001'], ['CVE-2026-20001']),
    boundaryOsv('OSV-TWO', ['CVE-2026-10002', 'CVE-2026-10003'], ['CVE-2026-20002', 'CVE-2026-20003']),
    boundaryOsv(
      'DEBIAN-CVE-2026-30001',
      ['CVE-2026-30001', 'CVE-2026-30002', 'CVE-2026-30003'],
      ['CVE-2026-40001', 'CVE-2026-40002', 'CVE-2026-40003', 'CVE-2026-40004'],
      true)
  ];

  const profile = profileOsvRecord(records[3]);
  assert.equal(profile.embeddedCveId, true);
  assert.equal(profile.aliasCveCount, 3);
  assert.equal(profile.upstreamCveCount, 4);
  assert.equal(profile.hasCompleteEvidence, true);

  const selection = selectOsvRecords(records);
  assert.equal(selection.totalRecords, 4);
  assert.deepEqual(selection.aliasCveHistogram, { 0: 1, 1: 1, 2: 1, 3: 1 });
  assert.deepEqual(selection.upstreamCveHistogram, { 0: 1, 1: 1, 2: 1, 4: 1 });
  assert.equal(selection.selections['alias-cve-maximum'], 'DEBIAN-CVE-2026-30001');
  assert.equal(selection.selections['upstream-cve-maximum'], 'DEBIAN-CVE-2026-30001');
  assert.equal(selection.selections['cve-less-ghsa'], 'GHSA-AAAA-BBBB-0001');
  assert.equal(selection.selections['embedded-cve-id'], 'DEBIAN-CVE-2026-30001');
  assert.equal(selection.records.length, 4);
  assert.deepEqual(
    selection.records.find((item) => item.profile.id === 'DEBIAN-CVE-2026-30001').categories,
    ['alias-cve-maximum', 'complete-evidence', 'embedded-cve-id', 'upstream-cve-maximum']);
});

test('OSV bulk prefix feeder emits append-only segmented spool', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-osv-prefix-'));
  try {
    const { writeOsvPrefixRecords } = await import('../../scripts/feed-osv-bulk-prefix.mjs');
    const result = await writeOsvPrefixRecords(
      [
        { id: 'ECHO-0001', aliases: ['CVE-2026-10001'], affected: [] },
        { id: 'GHSA-2222-3333-4444', aliases: [], affected: [] },
        { id: 'echo-0002', upstream: ['CVE-2026-10002'], affected: [] },
        { id: 'ECHO-0003', affected: [] }
      ],
      root,
      { prefix: 'ECHO-', segmentSize: 2, runId: 'echo-fixture' });

    assert.equal(result.records, 3);
    assert.deepEqual(result.files.map((item) => item.records), [2, 1]);
    const lines = [];
    for (const segment of result.files) {
      const content = await fs.readFile(path.join(root, 'incoming', segment.file), 'utf8');
      lines.push(...content.trim().split('\n').map(JSON.parse));
    }
    assert.deepEqual(lines.map((line) => line.externalId), ['ECHO-0001', 'echo-0002', 'ECHO-0003']);
    assert.ok(lines.every((line) => line.sourceCode === 'osv-init'));
    assert.ok(lines.every((line) => line.sourceMode === 'append'));
    assert.ok(lines.every((line) => line.runId === 'echo-fixture'));
    assert.deepEqual(lines[0].identifiers, ['ECHO-0001', 'CVE-2026-10001']);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('OSV bulk ID feeder deduplicates requests and reports missing records', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-osv-ids-'));
  try {
    const { writeOsvIdRecords } = await import('../../scripts/feed-osv-bulk-prefix.mjs');
    const result = await writeOsvIdRecords(
      [
        { id: 'OSV-0001', aliases: ['CVE-2026-10001'] },
        { id: 'OSV-0002' },
        { id: 'OSV-0003' }
      ],
      root,
      { ids: ['osv-0002', 'OSV-0001', 'OSV-0002', 'OSV-MISSING'], segmentSize: 1, runId: 'ids-fixture' });

    assert.equal(result.records, 2);
    assert.deepEqual(result.files.map((item) => item.records), [1, 1]);
    assert.deepEqual(result.missingIds, ['OSV-MISSING']);
    const lines = [];
    for (const segment of result.files) {
      const content = await fs.readFile(path.join(root, 'incoming', segment.file), 'utf8');
      lines.push(...content.trim().split('\n').map(JSON.parse));
    }
    assert.deepEqual(lines.map((line) => line.externalId), ['OSV-0001', 'OSV-0002']);
    assert.ok(lines.every((line) => line.sourceMode === 'append'));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

function boundaryOsv(id, aliases, upstream, complete = false) {
  return {
    id,
    aliases,
    upstream,
    ...(complete ? {
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
      references: [{ type: 'ADVISORY', url: `https://example.test/${id}` }],
      affected: [{ package: { ecosystem: 'npm', name: id.toLowerCase() } }]
    } : {})
  };
}

function ghsaOsv(id, modified) {
  return {
    schema_version: '1.4.0',
    id,
    modified,
    published: modified,
    aliases: [],
    summary: `Fixture ${id}`,
    details: `Details for ${id}`,
    affected: [{
      package: { ecosystem: 'npm', name: 'fixture-package', purl: 'pkg:npm/fixture-package' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }]
    }],
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    references: [{ type: 'ADVISORY', url: `https://github.com/advisories/${id}` }]
  };
}

async function runFetcherModule(sourceCode) {
  const { withClient, getSource, startRun, saveCheckpoint, flushWriteBatch, finishRun } =
    await import('../../plugins/fetchers/lib/db.mjs');
  const mod = await import(`../../plugins/fetchers/sources/${sourceCode}.mjs`);
  return withClient(async (client) => {
    const source = await getSource(client, sourceCode);
    const run = await startRun(client, source.id, 'test');
    const result = await mod.run(client, { source, run });
    await flushWriteBatch(client);
    await saveCheckpoint(client, source.id, result.checkpoint);
    await finishRun(client, run.id, {
      status: 'succeeded',
      fetchedCount: result.fetchedCount,
      parsedCount: result.parsedCount,
      checkpoint: result.checkpoint
    });
    return result;
  });
}

test('Compose env files are not overridden by hardcoded runtime defaults', async () => {
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
      assert.doesNotMatch(compose, new RegExp(`^\\s+${key}: (?!\\$\\{)`, 'm'), `${composeFile} does not hardcode ${key}`);
    }
  }

  const production = await fs.readFile('docker-compose.prod.yml', 'utf8');
  assert.match(production, /path: \.env\.production\s+required: false/);
  assert.match(production, /"\$\{VULTRACK_HTTP_PORT:-3000\}:80"/);
});

test('FIRST EPSS is enabled after its native delta pipeline is accepted', async () => {
  const scheduler = await fs.readFile('src/VulTrack.App/DuckDbFirstScheduler.cs', 'utf8');
  const sourceEndpoints = await fs.readFile('src/VulTrack.App/Endpoints/SourceEndpoints.cs', 'utf8');
  const storeStatus = await fs.readFile('src/VulTrack.App/DuckDbEvidenceStore.Status.cs', 'utf8');
  const options = await fs.readFile('src/VulTrack.App/VulTrackOptions.cs', 'utf8');
  const envExample = await fs.readFile('.env.example', 'utf8');
  const defaults = 'nvd-cve,osv,ghsa,google-osv,cisa-kev,first-epss,exploitdb,nuclei-templates,metasploit,poc-in-github,cargo-advisory';
  assert.match(options, new RegExp(`DefaultFetchSources =\\s*"${defaults}"`));
  assert.match(scheduler, /options\.Scheduler\.SourceCodes\(\)/);
  assert.match(sourceEndpoints, /options\.Scheduler\.SourceCodes\(\)/);
  assert.match(storeStatus, /Options\.Scheduler\.SourceCodes\(\)/);
  assert.match(envExample, new RegExp(`^DUCKDB_FETCH_SOURCES=${defaults}$`, 'm'));
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

test('OSV production snapshot resumes by row offset without refetching a changing index', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-osv-snapshot-'));
  try {
    const csv = [
      '2026-01-03T00:00:00.000000001Z,PyPI/OSV-FIRST',
      '2026-01-03T00:00:00.000000003Z,PyPI/OSV-OUT-OF-ORDER',
      '2026-01-02T00:00:00Z,PyPI/OSV-THIRD',
      '2026-01-01T00:00:00Z,PyPI/OSV-OLD'
    ].join('\n');
    const first = await runOsvIncremental({
      checkpoint: {},
      bootstrapWatermark: '2026-01-01T00:00:00Z',
      csv,
      etag: 'stable-index-v1',
      maxRecords: 1,
      persistIndexSnapshot: true,
      root
    });
    assert.deepEqual(first.fetchedIds, ['PyPI/OSV-FIRST']);
    assert.equal(first.result.checkpoint.pending.offset, 1);
    assert.equal(first.snapshotExists, true);

    const second = await runOsvIncremental({
      checkpoint: first.result.checkpoint,
      status: 500,
      maxRecords: 1,
      persistIndexSnapshot: true,
      root
    });
    assert.equal(second.fetchHeaders, null);
    assert.deepEqual(second.fetchedIds, ['PyPI/OSV-OUT-OF-ORDER']);
    assert.equal(second.result.checkpoint.pending.offset, 2);
    assert.equal(second.result.checkpoint.pending.newestModifiedAt, '2026-01-03T00:00:00.000000003Z');
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
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

test('FIRST EPSS publishes one gzip input and a tiny manifest without advancing the checkpoint', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-epss-native-'));
  const previous = Object.fromEntries(['VULTRACK_SPOOL_PATH'].map((key) => [key, process.env[key]]));
  process.env.VULTRACK_SPOOL_PATH = root;
  try {
    const { withClient, flushWriteBatch } = await import('../../plugins/fetchers/lib/db.mjs');
    const { runEpssSnapshot } = await import('../../plugins/fetchers/sources/first-epss.mjs');
    const gzip = zlib.gzipSync(['#model_version: test', 'cve,epss,percentile', 'CVE-2026-0001,0.01,0.10'].join('\n'));
    const result = await withClient(async (client) => {
      const current = await runEpssSnapshot(client, {
        source: { id: 'first-epss', code: 'first-epss', checkpoint_json: {} },
        run: { id: 'native-test' }
      }, { fetchGzip: async () => gzip });
      await flushWriteBatch(client);
      return current;
    });
    assert.equal(result.fetchedCount, 1);
    const incoming = await fs.readdir(path.join(root, 'incoming'));
    assert.deepEqual(incoming.sort(), [
      'first-epss-native-test.epss.csv.gz.ready',
      'first-epss-native-test.epss.json.ready'
    ]);
    const manifest = JSON.parse(await fs.readFile(path.join(root, 'incoming', 'first-epss-native-test.epss.json.ready'), 'utf8'));
    assert.equal(manifest.bytes, gzip.length);
    assert.match(manifest.contentHash, /^[a-f0-9]{64}$/);
    await assert.rejects(fs.access(path.join(root, 'state', 'first-epss.json')));

    const duplicate = await withClient((client) => runEpssSnapshot(client, {
      source: { id: 'first-epss', code: 'first-epss', checkpoint_json: {} },
      run: { id: 'duplicate-test' }
    }, { fetchGzip: async () => gzip }));
    assert.equal(duplicate.fetchedCount, 0);
    assert.equal((await fs.readdir(path.join(root, 'incoming'))).length, 2);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await fs.rm(root, { recursive: true, force: true });
  }
});

async function runOsvIncremental({
  checkpoint,
  bootstrapWatermark,
  csv = '',
  etag,
  status = 200,
  maxRecords,
  body,
  persistIndexSnapshot = false,
  root: providedRoot
}) {
  const previousPath = process.env.VULTRACK_SPOOL_PATH;
  const previousMax = process.env.OSV_FETCH_MAX_RECORDS;
  const root = providedRoot ?? await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-osv-incremental-'));
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
        persistIndexSnapshot,
        indexSnapshotDirectory: path.join(root, 'osv-index'),
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
    const snapshotPath = result.checkpoint.pending?.indexSnapshotPath;
    const snapshotExists = snapshotPath ? await fs.access(snapshotPath).then(() => true, () => false) : false;
    return { result, fetchedIds, fetchHeaders, spoolIds, snapshotExists };
  } finally {
    if (previousPath === undefined) delete process.env.VULTRACK_SPOOL_PATH;
    else process.env.VULTRACK_SPOOL_PATH = previousPath;
    if (previousMax === undefined) delete process.env.OSV_FETCH_MAX_RECORDS;
    else process.env.OSV_FETCH_MAX_RECORDS = previousMax;
    if (!providedRoot) await fs.rm(root, { recursive: true, force: true });
  }
}

test('spool fetch backend writes one atomic spool batch', async () => {
  const previousPath = process.env.VULTRACK_SPOOL_PATH;
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-spool-'));
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
    if (previousPath === undefined) delete process.env.VULTRACK_SPOOL_PATH;
    else process.env.VULTRACK_SPOOL_PATH = previousPath;
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('spool fetch backend commits resumable spool segments atomically', async () => {
  const previousPath = process.env.VULTRACK_SPOOL_PATH;
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'vultrack-spool-segments-'));
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
    if (previousPath === undefined) delete process.env.VULTRACK_SPOOL_PATH;
    else process.env.VULTRACK_SPOOL_PATH = previousPath;
    await fs.rm(root, { recursive: true, force: true });
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

  const empty = nucleiSnapshotPlan({
    gitRevision: 'revision-a',
    completedGitRevision: 'revision-a',
    snapshotComplete: true,
    recordCount: 2
  }, 'revision-b', 0, 5000);
  assert.equal(empty.snapshotComplete, false);
  assert.equal(empty.checkpoint.rejectedReason, 'empty_snapshot');
  assert.equal(empty.checkpoint.completedGitRevision, 'revision-a');
  assert.equal(empty.checkpoint.gitRevision, 'revision-a');

  const complete = nucleiSnapshotPlan({}, 'revision-b', 4348, 5000);
  assert.equal(complete.snapshotComplete, true);
  assert.equal(complete.checkpoint.snapshotComplete, true);
  assert.equal(complete.checkpoint.completedGitRevision, 'revision-b');
});

test('Nuclei DuckDB projection applies a complete revision before finalizing the spool', async () => {
  const spool = await fs.readFile('src/VulTrack.App/DuckDbEvidenceNormalizer.Spool.cs', 'utf8');
  const store = (await Promise.all([
    'src/VulTrack.App/DuckDbEvidenceStore.Evidence.cs',
    'src/VulTrack.App/DuckDbEvidenceStore.Schema.cs',
    'src/VulTrack.App/DuckDbEvidenceStore.Catalog.cs'
  ].map((file) => fs.readFile(file, 'utf8')))).join('\n');
  const fetcher = await fs.readFile('plugins/fetchers/sources/nuclei-templates.mjs', 'utf8');

  assert.match(fetcher, /const templates = \[\]/);
  assert.doesNotMatch(fetcher, /commitSpoolSegment/);
  assert.match(fetcher, /snapshotComplete: true/);
  assert.match(spool, /Nuclei spool record is not a complete revision snapshot/);
  assert.match(spool, /var expectedRecordCount = EnsureCurrentNucleiSnapshot\(nucleiSnapshotId\)/);
  assert.match(spool, /records != expectedRecordCount/);
  assert.match(spool, /exploitBatch\.Count != expectedRecordCount/);
  assert.match(spool, /distinctRawIds != expectedRecordCount/);
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
  assert.match(nucleiApply, /NUCLEI_ALLOW_LARGE_SNAPSHOT_DROP/);
  assert.match(nucleiApply, /NucleiLargeSnapshotDropThreshold/);
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

  const exploitProjection = store.slice(
    store.indexOf('public async Task UpsertExploitProjectionAsync'),
    store.indexOf('public async Task<DuckDbNucleiSnapshotStats> GetNucleiSnapshotStatsAsync')
  );
  assert.match(exploitProjection, /await UpsertExploitRowsAsync\(connection, exploits, snapshotId: null, ct\)/);
  assert.doesNotMatch(exploitProjection, /delete from exploits/i);
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
