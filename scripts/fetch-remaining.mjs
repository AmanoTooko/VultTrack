#!/usr/bin/env node
import { withClient, getSource, startRun, finishRun, recordError } from '../plugins/fetchers/lib/db.mjs';
import { writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LOGDIR = resolve(__dirname, '..', 'data', 'logs');
mkdirSync(LOGDIR, { recursive: true });

const SOURCES = process.argv.slice(2).length > 0 ? process.argv.slice(2) : [
  'osv',
  'cve-list-v5',
  'nvd-cve',
  'nvd-cpe'
];

const results = [];

for (const sourceCode of SOURCES) {
  const logFile = resolve(LOGDIR, `fetch-${sourceCode}-${Date.now()}.log`);
  let log = (msg) => {
    const line = `[${new Date().toISOString()}] ${msg}`;
    console.log(line);
    try {
      writeFileSync(logFile, line + '\n', { flag: 'a' });
    } catch {
      // Logging must not fail the fetch batch.
    }
  };

  log(`Starting ${sourceCode}...`);
  try {
    const mod = await import(`../plugins/fetchers/sources/${sourceCode}.mjs`);
    await withClient(async (client) => {
      const sourceRow = await getSource(client, sourceCode);
      const run = await startRun(client, sourceRow.id, 'manual');
      const ctx = { source: sourceRow, run };
      try {
        const result = await mod.run(client, ctx);
        await finishRun(client, run.id, {
          status: 'succeeded',
          fetchedCount: result.fetchedCount,
          changedCount: result.fetchedCount,
          parsedCount: result.parsedCount,
          errorCount: 0,
          checkpoint: result.checkpoint,
          logSummary: `${sourceCode} fetched ${result.fetchedCount} records`
        });
        log(`DONE: fetchedCount=${result.fetchedCount}, parsedCount=${result.parsedCount}`);
        results.push({ source: sourceCode, ok: true, ...result });
      } catch (error) {
        await recordError(client, ctx, 'fetch', error);
        await finishRun(client, run.id, {
          status: 'failed',
          fetchedCount: 0, changedCount: 0, parsedCount: 0,
          errorCount: 1, logSummary: error.message
        });
        log(`FAILED: ${error.message}`);
        results.push({ source: sourceCode, ok: false, error: error.message });
      }
    });
  } catch (error) {
    log(`ERROR loading module: ${error.message}`);
    results.push({ source: sourceCode, ok: false, error: error.message });
  }
}

const summary = resolve(LOGDIR, `summary-${Date.now()}.json`);
writeFileSync(summary, JSON.stringify(results, null, 2));
console.log(`\nSummary written to ${summary}`);
console.log(JSON.stringify(results, null, 2));
