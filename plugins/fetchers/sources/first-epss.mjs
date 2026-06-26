import zlib from 'node:zlib';
import { promisify } from 'node:util';
import { fetchBuffer } from '../lib/http.mjs';
import { getIntEnv } from '../lib/env.mjs';
import { sha256 } from '../lib/hash.mjs';
import { writeArtifact } from '../lib/db.mjs';

const gunzip = promisify(zlib.gunzip);
export const sourceCode = 'first-epss';

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const checkpoint = ctx.source.checkpoint_json ?? {};

  const gz = await fetchBuffer('https://epss.empiricalsecurity.com/epss_scores-current.csv.gz');
  const contentHash = sha256(gz);

  // Skip if content unchanged
  if (checkpoint.contentHash === contentHash) {
    console.error('EPSS data unchanged, skipping.');
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { contentHash, skipped: true } };
  }

  const csv = (await gunzip(gz)).toString('utf8');
  const lines = csv.split(/\r?\n/).filter((line) => line && !line.startsWith('#'));
  const observedAt = new Date().toISOString();
  const records = [];
  for (const line of lines.slice(1)) {
    if (records.length >= max) break;
    const [cve, epss, percentile] = line.split(',');
    if (!cve) continue;
    records.push({
      cve,
      epss: Number(epss),
      percentile: Number(percentile)
    });
  }

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
