import { authHeaders, fetchJson } from '../lib/http.mjs';
import { getIntEnv, getRootPath } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { resumeInitOffset, saveCheckpoint, saveInitProgress, writeRecord } from '../lib/db.mjs';
import { upsertNvdCve } from '../lib/staging.mjs';

export const sourceCode = 'nvd-cve';

const NVD_MAX_DATE_WINDOW_DAYS = 120;
const GIT_REPO = 'https://github.com/fkie-cad/nvd-json-data-feeds.git';
const MIRROR_DIR = 'data/mirrors/nvd-cve-feeds';

function runGit(spawnSync, args) {
  const result = spawnSync('git', args, { stdio: 'inherit' });
  if (result.status !== 0) throw new Error(`git ${args.join(' ')} failed`);
}

function nvdDate(iso) {
  return String(iso).replace(/(\.\d+)?Z?$/, '.000');
}

// Import from local git mirror (shallow clone of fkie-cad/nvd-json-data-feeds)
export async function initFromMirror(client, ctx, max) {
  const fs = await import('node:fs/promises');
  const path = await import('node:path');
  const { spawnSync } = await import('node:child_process');

  const mirrorPath = getRootPath(MIRROR_DIR);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  console.error(`[nvd-cve] mirror dir: ${mirrorPath}`);

  const localCommit = getMirrorCommit(spawnSync, mirrorPath);
  const resumePinnedMirror = checkpoint.initComplete === false
    && checkpoint.initMode === 'full'
    && checkpoint.mirrorCommit
    && checkpoint.mirrorCommit === localCommit;

  if (resumePinnedMirror) {
    console.error(`[nvd-cve] resuming pinned mirror at commit ${localCommit.slice(0, 8)}`);
  } else if (localCommit) {
    console.error('[nvd-cve] refreshing mirror...');
    runGit(spawnSync, ['-C', mirrorPath, 'fetch', '--depth', '1', 'origin', 'main']);
    runGit(spawnSync, ['-C', mirrorPath, 'reset', '--hard', 'FETCH_HEAD']);
  } else {
    console.error('[nvd-cve] cloning mirror (shallow)...');
    await fs.mkdir(mirrorPath, { recursive: true });
    runGit(spawnSync, ['clone', '--depth', '1', '-b', 'main', GIT_REPO, mirrorPath]);
  }

  // Get the latest commit hash for checkpoint
  const commitHash = getMirrorCommit(spawnSync, mirrorPath);
  if (!commitHash) throw new Error('Unable to resolve NVD CVE mirror revision');
  console.error(`[nvd-cve] mirror at commit ${commitHash.slice(0, 8)}`);

  // Walk all CVE JSON files
  const entries = [];
  async function walk(dir) {
    const items = await fs.readdir(dir, { withFileTypes: true });
    for (const item of items) {
      const full = path.default.join(dir, item.name);
      if (item.isDirectory()) {
        await walk(full);
      } else if (item.name.endsWith('.json') && !full.includes('/.git/') && !full.includes('/LICENSES/')) {
        entries.push(full);
      }
    }
  }
  await walk(mirrorPath);
  entries.sort();
  console.error(`[nvd-cve] found ${entries.length} CVE files`);

  const offset = resumeInitOffset(checkpoint, { initMode: 'full', mirrorCommit: commitHash });
  let nextOffset = offset;
  let count = 0;
  let latestMod = offset > 0 ? (checkpoint.latestModStartDate ?? null) : null;
  const batchSize = 500;

  await saveInitProgress(client, ctx, fullInitCheckpoint(nextOffset, latestMod, commitHash, entries.length));
  if (offset > 0) {
    console.error(`[nvd-cve] resuming full init at offset ${offset}`);
  }

  for (let i = offset; i < entries.length && count < max; i++) {
    const file = entries[i];
    const raw = await fs.readFile(file, 'utf8');
    const item = JSON.parse(raw);
    const cveId = item.id;
    if (cveId) {
      if (item.lastModified && (!latestMod || item.lastModified > latestMod)) {
        latestMod = item.lastModified;
      }

      const rawIndexId = await writeRecord(client, ctx, {
        externalKey: cveId,
        externalId: cveId,
        sourceUrl: `https://nvd.nist.gov/vuln/detail/${cveId}`,
        publishedAt: item.published,
        modifiedAt: item.lastModified,
        identifiers: [cveId],
        recordHash: sha256(stableJson(item)),
        payload: item
      });
      await upsertNvdCve(client, rawIndexId, item);
      count++;
    }

    nextOffset = i + 1;

    if (nextOffset % batchSize === 0) {
      await saveInitProgress(client, ctx, fullInitCheckpoint(nextOffset, latestMod, commitHash, entries.length));
      console.error(`[nvd-cve] imported ${count}/${entries.length} (${Math.round(count/entries.length*100)}%)`);
    }
  }

  const initComplete = nextOffset >= entries.length;
  console.error(`[nvd-cve] init ${initComplete ? 'done' : 'paused'}, imported ${count} records this run`);
  return {
    fetchedCount: count,
    parsedCount: count,
    checkpoint: initComplete
      ? {
          initComplete: true,
          lastModStartDate: latestMod ? nvdDate(latestMod) : null,
          mirrorCommit: commitHash,
          lastFetched: new Date().toISOString()
        }
      : await saveInitProgress(client, ctx, fullInitCheckpoint(nextOffset, latestMod, commitHash, entries.length))
  };
}

function getMirrorCommit(spawnSync, mirrorPath) {
  const result = spawnSync('git', ['-C', mirrorPath, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
  return result.status === 0 ? result.stdout.trim() : null;
}

function fullInitCheckpoint(offset, latestMod, mirrorCommit, totalFiles) {
  return {
    initMode: 'full',
    offset,
    latestModStartDate: latestMod,
    mirrorCommit,
    totalFiles,
    lastFetched: new Date().toISOString()
  };
}

// Incremental sync via NVD API 2.0
async function incrFromApi(client, ctx, max, lastModStartDate) {
  const { nvdKey } = authHeaders();
  const pageSize = Math.min(getIntEnv('NVD_PAGE_SIZE', 1000), 2000);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const savedProgress = checkpoint.incrementalProgress;
  const canResume = savedProgress?.windowStart === lastModStartDate
    && Number.isSafeInteger(savedProgress.nextStartIndex)
    && savedProgress.nextStartIndex >= 0
    && !isNaN(new Date(savedProgress.windowEnd).getTime());
  const windowEnd = canResume ? savedProgress.windowEnd : nvdDate(new Date().toISOString());

  let startIndex = canResume ? savedProgress.nextStartIndex : 0;
  let total = Number.MAX_SAFE_INTEGER;
  let count = 0;
  let latestMod = canResume ? (savedProgress.latestMod ?? lastModStartDate) : lastModStartDate;

  if (canResume) {
    console.error(`[nvd-cve] resuming incremental window at startIndex ${startIndex}`);
  }

  while (startIndex < total && count < max) {
    const url = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
    url.searchParams.set('resultsPerPage', String(Math.min(pageSize, max - count)));
    url.searchParams.set('startIndex', String(startIndex));
    url.searchParams.set('lastModStartDate', lastModStartDate);
    url.searchParams.set('lastModEndDate', windowEnd);

    const data = await fetchJson(url, { headers: nvdKey ? { apiKey: nvdKey } : {} });
    total = data.totalResults ?? 0;
    for (const item of data.vulnerabilities ?? []) {
      if (count >= max) break;
      const cve = item.cve;
      if (!cve) continue;
      if (cve.lastModified && cve.lastModified > latestMod) {
        latestMod = cve.lastModified;
      }
      const rawIndexId = await writeRecord(client, ctx, {
        externalKey: cve.id,
        externalId: cve.id,
        sourceUrl: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
        publishedAt: cve.published,
        modifiedAt: cve.lastModified,
        identifiers: [cve.id],
        recordHash: sha256(stableJson(item)),
        payload: item
      });
      await upsertNvdCve(client, rawIndexId, item);
      count++;
    }
    startIndex += data.resultsPerPage ?? pageSize;
    const incrementalProgress = {
      windowStart: lastModStartDate,
      windowEnd,
      nextStartIndex: startIndex,
      latestMod
    };
    const progressCheckpoint = { ...checkpoint, lastModStartDate, incrementalProgress };
    await saveCheckpoint(client, ctx.source.id, progressCheckpoint);
    ctx.source.checkpoint_json = progressCheckpoint;
    if ((data.vulnerabilities ?? []).length === 0) break;
    const delayMs = nvdKey ? 600 : 10000;
    if (startIndex < total && count < max) {
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
  const complete = startIndex >= total;
  const nextCheckpoint = {
    ...checkpoint,
    lastModStartDate: complete && latestMod ? nvdDate(latestMod) : lastModStartDate,
    lastFetched: new Date().toISOString()
  };
  if (complete) {
    delete nextCheckpoint.incrementalProgress;
  } else {
    nextCheckpoint.incrementalProgress = {
      windowStart: lastModStartDate,
      windowEnd,
      nextStartIndex: startIndex,
      latestMod
    };
  }

  return {
    fetchedCount: count,
    parsedCount: count,
    checkpoint: nextCheckpoint
  };
}

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const checkpoint = ctx.source.checkpoint_json ?? {};

  // Daily source is API incremental only. Baseline mirror import lives in nvd-cve-init.
  let lastModStartDate = checkpoint.lastModStartDate;
  if (!lastModStartDate) {
    const fallbackDays = getIntEnv('NVD_INCREMENTAL_LOOKBACK_DAYS', 2);
    lastModStartDate = nvdDate(new Date(Date.now() - fallbackDays * 86400000).toISOString());
  }
  const now = new Date();
  const maxWindowAgo = new Date(now.getTime() - NVD_MAX_DATE_WINDOW_DAYS * 86400000);
  if (lastModStartDate) {
    const cpDate = new Date(lastModStartDate);
    if (isNaN(cpDate.getTime()) || cpDate < maxWindowAgo) {
      console.error(`[nvd-cve] checkpoint date ${lastModStartDate} too old, capping to ${nvdDate(maxWindowAgo.toISOString())}`);
      lastModStartDate = nvdDate(maxWindowAgo.toISOString());
    }
  }

  return incrFromApi(client, ctx, max, lastModStartDate);
}
