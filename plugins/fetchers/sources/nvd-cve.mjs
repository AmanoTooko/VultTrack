import { authHeaders, fetchJson } from '../lib/http.mjs';
import { getIntEnv, getRootPath } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';
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
  console.error(`[nvd-cve] mirror dir: ${mirrorPath}`);

  // Clone or pull
  try {
    await fs.access(path.default.join(mirrorPath, '.git'));
    console.error('[nvd-cve] refreshing mirror...');
    runGit(spawnSync, ['-C', mirrorPath, 'fetch', '--depth', '1', 'origin', 'main']);
    runGit(spawnSync, ['-C', mirrorPath, 'reset', '--hard', 'FETCH_HEAD']);
  } catch {
    console.error('[nvd-cve] cloning mirror (shallow)...');
    await fs.mkdir(mirrorPath, { recursive: true });
    spawnSync('git', ['clone', '--depth', '1', '-b', 'main', GIT_REPO, mirrorPath], { stdio: 'inherit' });
  }

  // Get the latest commit hash for checkpoint
  const revResult = spawnSync('git', ['-C', mirrorPath, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
  const commitHash = revResult.stdout.trim();
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
  console.error(`[nvd-cve] found ${entries.length} CVE files`);

  let count = 0;
  let latestMod = null;
  const batchSize = 500;

  for (let i = 0; i < entries.length && count < max; i++) {
    const file = entries[i];
    const raw = await fs.readFile(file, 'utf8');
    const item = JSON.parse(raw);
    const cveId = item.id;
    if (!cveId) continue;

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

    if (count % batchSize === 0) {
      console.error(`[nvd-cve] imported ${count}/${entries.length} (${Math.round(count/entries.length*100)}%)`);
    }
  }

  console.error(`[nvd-cve] init done, imported ${count} records`);
  return {
    fetchedCount: count,
    parsedCount: count,
    checkpoint: {
      lastModStartDate: latestMod ? nvdDate(latestMod) : null,
      mirrorCommit: commitHash,
      lastFetched: new Date().toISOString()
    }
  };
}

// Incremental sync via NVD API 2.0
async function incrFromApi(client, ctx, max, lastModStartDate) {
  const { nvdKey } = authHeaders();
  const pageSize = Math.min(getIntEnv('NVD_PAGE_SIZE', 2000), 2000);
  const now = new Date();

  let startIndex = 0;
  let total = Number.MAX_SAFE_INTEGER;
  let count = 0;
  let latestMod = lastModStartDate;

  while (startIndex < total && count < max) {
    const url = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
    url.searchParams.set('resultsPerPage', String(Math.min(pageSize, max - count)));
    url.searchParams.set('startIndex', String(startIndex));
    url.searchParams.set('lastModStartDate', lastModStartDate);
    url.searchParams.set('lastModEndDate', nvdDate(now.toISOString()));

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
    if ((data.vulnerabilities ?? []).length === 0) break;
    const delayMs = nvdKey ? 600 : 10000;
    if (startIndex < total && count < max) {
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
  return {
    fetchedCount: count,
    parsedCount: count,
    checkpoint: {
      lastModStartDate: latestMod ? nvdDate(latestMod) : null,
      lastFetched: now.toISOString()
    }
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
