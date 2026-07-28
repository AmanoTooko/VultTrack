import zlib from 'node:zlib';
import fs from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { fetchBuffer } from '../lib/http.mjs';
import { getBoolEnv, getIntEnv, getRootPath } from '../lib/env.mjs';
import { sha256 } from '../lib/hash.mjs';
import { isSpoolBackend, registerSpoolCommitHook, writeArtifact, writeRecord } from '../lib/db.mjs';

const gunzip = promisify(zlib.gunzip);
const gzip = promisify(zlib.gzip);
export const sourceCode = 'first-epss';
const DELTA_STATE_VERSION = 1;
const DELTA_STATE_FILE = 'first-epss.delta.v1.tsv.gz';
const EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';

export async function run(client, ctx) {
  return runEpssDelta(client, ctx, { fetchGzip: fetchBuffer });
}

export async function runEpssDelta(client, ctx, { fetchGzip = fetchBuffer } = {}) {
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const gz = await fetchGzip(EPSS_URL);
  const contentHash = sha256(gz);
  const statePath = epssStatePath();
  const previous = await loadDeltaState(statePath);

  // A content hash alone is not enough to skip: historical checkpoints have
  // no per-CVE state, so using one would silently skip new daily scores.
  if (checkpoint.contentHash === contentHash && previous && process.env.FETCHER_FORCE !== '1') {
    console.error('EPSS data unchanged, skipping.');
    return {
      fetchedCount: 0,
      changedCount: 0,
      parsedCount: 0,
      checkpoint: compactCheckpoint(checkpoint, contentHash, previous.size, 'unchanged')
    };
  }

  const rows = parseEpssCsv((await gunzip(gz)).toString('utf8'));
  const configuredMax = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  if (configuredMax < rows.size) {
    throw new Error(`FIRST EPSS delta requires a complete daily snapshot; FETCHER_MAX_RECORDS=${configuredMax} is below ${rows.size}`);
  }
  const maxRows = Math.max(1, getIntEnv('EPSS_DELTA_MAX_ROWS', 600000));
  if (rows.size > maxRows) {
    throw new Error(`FIRST EPSS snapshot has ${rows.size} rows, exceeding EPSS_DELTA_MAX_ROWS=${maxRows}`);
  }

  if (isSpoolBackend() && !previous && !getBoolEnv('EPSS_DELTA_ALLOW_BASELINE', false)) {
    console.error('FIRST EPSS delta state is missing; skipping until an explicit EPSS_DELTA_ALLOW_BASELINE=1 baseline is approved.');
    return {
      fetchedCount: 0,
      changedCount: 0,
      parsedCount: 0,
      checkpoint: {
        ...checkpoint,
        deltaStateRequired: true,
        deltaStateVersion: DELTA_STATE_VERSION,
        lastAttemptedContentHash: contentHash,
        skipped: 'delta-state-required'
      }
    };
  }

  const changed = diffEpssRows(previous, rows);
  const maxChangedRows = Math.max(1, getIntEnv('EPSS_DELTA_MAX_CHANGED_ROWS', 50000));
  if (isSpoolBackend() && changed.length > maxChangedRows && !getBoolEnv('EPSS_DELTA_ALLOW_BULK', false)) {
    throw new Error(
      `FIRST EPSS delta has ${changed.length}/${rows.size} changed rows, exceeding EPSS_DELTA_MAX_CHANGED_ROWS=${maxChangedRows}; ` +
      'refusing the bulk spool write without EPSS_DELTA_ALLOW_BULK=1'
    );
  }

  const observedAt = new Date().toISOString();

  if (isSpoolBackend()) {
    for (let index = 0; index < changed.length; index++) {
      const record = changed[index];
      await writeRecord(client, ctx, {
        externalKey: record.cve,
        externalId: record.cve,
        sourceUrl: 'https://www.first.org/epss/',
        identifiers: [record.cve],
        recordHash: sha256(Buffer.from(`${record.cve},${record.epss},${record.percentile}`)),
        payload: {
          provider: 'first-epss',
          cve: record.cve,
          epss: record.epss,
          percentile: record.percentile,
          observedAt
        }
      });
      if ((index + 1) % 25000 === 0)
        console.error(`[first-epss] streamed ${index + 1}/${changed.length}`);
    }
    await stageDeltaState(client, ctx, statePath, rows);
    return {
      fetchedCount: rows.size,
      changedCount: changed.length,
      parsedCount: rows.size,
      checkpoint: compactCheckpoint(checkpoint, contentHash, rows.size, null, observedAt)
    };
  }

  const records = [...rows.values()];
  const csv = (await gunzip(gz)).toString('utf8');

  const artifact = await writeArtifact(client, ctx, {
    externalKey: `epss-${observedAt.slice(0, 10)}`,
    filename: 'epss_scores-current.csv',
    contentType: 'text/csv',
    schemaHint: 'first-epss-csv',
    retentionClass: 'hot',
    body: csv
  });
  await upsertArchiveIndex(client, ctx, artifact, observedAt);

  const batchSize = Math.max(100, getIntEnv('EPSS_BATCH_SIZE', 25000));
  let changedCount = 0;
  await client.query("select set_config('vultrack.defer_snapshot_queue', 'on', false)");
  try {
    for (let offset = 0; offset < records.length; offset += batchSize) {
      const batch = records.slice(offset, offset + batchSize);
      changedCount += await updateEpssBatch(client, batch);
      console.error(`[first-epss] projected ${Math.min(offset + batch.length, records.length)}/${records.length}`);
    }
  } finally {
    await client.query("select set_config('vultrack.defer_snapshot_queue', 'off', false)").catch(() => {});
  }
  await client.query(
    `update source_raw_index
     set normalize_status = 'succeeded', updated_at = now()
     where source_id = $1 and normalize_status in ('pending', 'failed')`,
    [ctx.source.id]
  );

  return { fetchedCount: records.length, changedCount, parsedCount: changedCount, checkpoint: { contentHash, lastFetched: observedAt } };
}

export function parseEpssCsv(csv) {
  const rows = new Map();
  const lines = String(csv).split(/\r?\n/);
  let sawHeader = false;
  for (const line of lines) {
    if (!line || line.startsWith('#')) continue;
    if (!sawHeader) {
      if (!/^cve,epss,percentile$/i.test(line.trim())) throw new Error('Unexpected FIRST EPSS CSV header');
      sawHeader = true;
      continue;
    }
    const [rawCve, rawEpss, rawPercentile, ...extra] = line.split(',');
    if (extra.length || !rawCve || !rawEpss || !rawPercentile) throw new Error(`Invalid FIRST EPSS CSV row: ${line.slice(0, 120)}`);
    const cve = rawCve.trim().toUpperCase();
    const epss = Number(rawEpss);
    const percentile = Number(rawPercentile);
    if (!/^CVE-\d{4}-\d{4,}$/i.test(cve) || !Number.isFinite(epss) || !Number.isFinite(percentile)) {
      throw new Error(`Invalid FIRST EPSS values for ${rawCve}`);
    }
    if (rows.has(cve)) throw new Error(`Duplicate FIRST EPSS CVE ${cve}`);
    rows.set(cve, { cve, epss, percentile, signature: `${epss}\t${percentile}` });
  }
  if (!sawHeader || !rows.size) throw new Error('FIRST EPSS CSV did not contain any score rows');
  return rows;
}

export function diffEpssRows(previous, current) {
  if (!previous) return [...current.values()];
  const changed = [];
  for (const row of current.values()) {
    if (previous.get(row.cve) !== row.signature) changed.push(row);
  }
  return changed;
}

async function loadDeltaState(statePath) {
  let compressed;
  try {
    compressed = await fs.readFile(statePath);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
  const rows = new Map();
  const text = (await gunzip(compressed)).toString('utf8');
  const lines = text.split('\n');
  if (lines.shift() !== `# vultrack-first-epss-delta-v${DELTA_STATE_VERSION}`) {
    throw new Error('FIRST EPSS delta state has an unsupported format');
  }
  for (const line of lines) {
    if (!line) continue;
    const [cve, epss, percentile, ...extra] = line.split('\t');
    if (extra.length || !cve || epss === undefined || percentile === undefined || rows.has(cve)) {
      throw new Error('FIRST EPSS delta state is corrupt');
    }
    rows.set(cve, `${epss}\t${percentile}`);
  }
  if (!rows.size) throw new Error('FIRST EPSS delta state is empty');
  return rows;
}

async function stageDeltaState(client, ctx, statePath, rows) {
  const body = serializeDeltaState(rows);
  const maxStateBytes = Math.max(1024, getIntEnv('EPSS_DELTA_MAX_STATE_BYTES', 32 * 1024 * 1024));
  const compressed = await gzip(body, { level: 6 });
  if (compressed.length > maxStateBytes) {
    throw new Error(`FIRST EPSS delta state is ${compressed.length} bytes, exceeding EPSS_DELTA_MAX_STATE_BYTES=${maxStateBytes}`);
  }
  await fs.mkdir(path.dirname(statePath), { recursive: true });
  const temporary = `${statePath}.next-${ctx.run.id}`;
  await fs.writeFile(temporary, compressed, { flag: 'wx' });
  registerSpoolCommitHook(client, {
    commit: async () => fs.rename(temporary, statePath),
    rollback: async () => fs.rm(temporary, { force: true })
  });
}

function serializeDeltaState(rows) {
  const lines = [`# vultrack-first-epss-delta-v${DELTA_STATE_VERSION}`];
  for (const cve of [...rows.keys()].sort()) {
    const row = rows.get(cve);
    lines.push(`${cve}\t${row.signature}`);
  }
  return Buffer.from(`${lines.join('\n')}\n`, 'utf8');
}

function epssStatePath() {
  return getRootPath(process.env.VULTRACK_SPOOL_PATH ?? 'data/spool', 'state', DELTA_STATE_FILE);
}

function compactCheckpoint(previous, contentHash, stateRows, skipped, lastFetched = new Date().toISOString()) {
  const checkpoint = {
    ...previous,
    contentHash,
    deltaStateVersion: DELTA_STATE_VERSION,
    deltaStateRows: stateRows,
    lastFetched
  };
  delete checkpoint.deltaStateRequired;
  delete checkpoint.lastAttemptedContentHash;
  if (skipped) checkpoint.skipped = skipped;
  else delete checkpoint.skipped;
  return checkpoint;
}

async function upsertArchiveIndex(client, ctx, artifact, observedAt) {
  const externalKey = `epss-${observedAt.slice(0, 10)}`;
  await client.query(
    `insert into source_raw_index
       (source_id, sync_run_id, object_id, external_key, external_id, source_url,
        content_hash, record_hash, identifier_summary, status, parse_status, normalize_status)
     values ($1,$2,$3,$4,$4,'https://www.first.org/epss/data_stats',$5,$5,'{}','new','succeeded','succeeded')
     on conflict (source_id, external_key, record_hash) do update set
       sync_run_id = excluded.sync_run_id,
       object_id = excluded.object_id,
       updated_at = now()`,
    [ctx.source.id, ctx.run.id, artifact.objectId, externalKey, artifact.sha256]
  );
}

async function updateEpssBatch(client, records) {
  for (let attempt = 1; attempt <= 5; attempt++) {
    try {
      const result = await client.query(
        `with input as (
       select * from jsonb_to_recordset($1::jsonb) as x(cve text, epss numeric, percentile numeric)
     ), changed as (
       update vulnerabilities v
       set epss_score = x.epss,
           epss_percentile = x.percentile,
           updated_at = now()
       from input x
       where v.primary_identifier = x.cve
         and (v.epss_score is distinct from x.epss or v.epss_percentile is distinct from x.percentile)
       returning v.id
     )
     insert into vulnerability_detail_snapshot_queue(vulnerability_id, queued_at)
     select id, now() from changed
     on conflict (vulnerability_id) do update set queued_at = excluded.queued_at
     returning vulnerability_id`,
        [JSON.stringify(records)]
      );
      return result.rowCount;
    } catch (error) {
      if (error.code !== '40P01' || attempt === 5) throw error;
      const delayMs = (attempt * 1000) + Math.floor(Math.random() * 500);
      console.error(`[first-epss] deadlock on batch, retrying attempt ${attempt + 1}/5 after ${delayMs}ms`);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  return 0;
}
