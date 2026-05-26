#!/usr/bin/env node
// Comprehensive fetcher runner - runs all sources sequentially with error handling and progress logging
import { withClient, getSource, startRun, finishRun, saveCheckpoint, recordError } from '../plugins/fetchers/lib/db.mjs';
import { writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LOGDIR = resolve(__dirname, '..', 'data', 'logs');
mkdirSync(LOGDIR, { recursive: true });

// Sources in execution order: fast first, slow last
const SOURCES = [
  'cisa-kev',
  'first-epss',
  'alpine-secdb',
  'debian-security-tracker',
  'ubuntu-osv',
  'ghsa',
  'cve-list-v5',
  'osv',
  'nvd-cve',
  'nvd-cpe',
  'android-osv',
  'npm-advisory',
  'pypi-advisory',
];

const results = [];
const startTime = Date.now();

function log(msg) {
  const ts = new Date().toISOString();
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
  const line = `[${ts}] [${elapsed}s] ${msg}`;
  console.log(line);
}

log(`Starting clean fetch run for ${SOURCES.length} sources`);

for (const sourceCode of SOURCES) {
  log(`--- ${sourceCode} ---`);
  let result = { source: sourceCode, ok: false, error: null, fetchedCount: 0 };
  
  try {
    const mod = await import(`../plugins/fetchers/sources/${sourceCode}.mjs`);
    await withClient(async (client) => {
      const sourceRow = await getSource(client, sourceCode);
      const run = await startRun(client, sourceRow.id, 'manual');
      const ctx = { source: sourceRow, run };
      try {
        log(`  ${sourceCode}: fetching...`);
        const fetchResult = await mod.run(client, ctx);
        if (fetchResult.checkpoint) {
          await saveCheckpoint(client, sourceRow.id, fetchResult.checkpoint);
        }
        await finishRun(client, run.id, {
          status: 'succeeded',
          fetchedCount: fetchResult.fetchedCount,
          changedCount: fetchResult.fetchedCount,
          parsedCount: fetchResult.parsedCount,
          errorCount: 0,
          checkpoint: fetchResult.checkpoint,
          logSummary: `${sourceCode} fetched ${fetchResult.fetchedCount} records`
        });
        log(`  ${sourceCode}: SUCCESS - ${fetchResult.fetchedCount} records`);
        result = { ...result, ok: true, fetchedCount: fetchResult.fetchedCount };
      } catch (error) {
        const errMsg = error.message || String(error);
        log(`  ${sourceCode}: FAILED - ${errMsg}`);
        await recordError(client, ctx, 'fetch', error);
        await finishRun(client, run.id, {
          status: 'failed',
          fetchedCount: 0, changedCount: 0, parsedCount: 0,
          errorCount: 1, logSummary: errMsg
        });
        result = { ...result, error: errMsg };
      }
    });
  } catch (modError) {
    const errMsg = modError.message || String(modError);
    log(`  ${sourceCode}: MODULE ERROR - ${errMsg}`);
    result = { ...result, error: errMsg };
  }
  
  results.push(result);
}

const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
log(`=== COMPLETE (${elapsed}s) ===`);

const summary = resolve(LOGDIR, `fetch-all-summary-${Date.now()}.json`);
writeFileSync(summary, JSON.stringify(results, null, 2));

const okCount = results.filter(r => r.ok).length;
const failCount = results.filter(r => !r.ok).length;
const totalFetched = results.reduce((s, r) => s + r.fetchedCount, 0);

log(`Results: ${okCount}/${SOURCES.length} succeeded, ${failCount} failed, total ${totalFetched} records`);
log(`Summary saved to: ${summary}`);

// Print results
for (const r of results) {
  const icon = r.ok ? '✅' : '❌';
  console.log(`  ${icon} ${r.source.padEnd(26)} ${String(r.fetchedCount).padStart(8)} ${r.error ? r.error : ''}`);
}
