#!/usr/bin/env node
import { withClient, getSource, startRun, finishRun, saveCheckpoint, recordError } from './lib/db.mjs';

const source = getArg('--source');
if (!source) {
  console.error('Usage: npm run fetch -- --source <source-code>');
  process.exit(2);
}
if (!/^[a-z0-9-]+$/.test(source)) {
  console.error(`Invalid source code: ${source}`);
  process.exit(2);
}

const modulePath = `./sources/${source}.mjs`;
const mod = await import(modulePath).catch((err) => {
  console.error(`Failed to load fetcher ${source}:`, err.message);
  process.exit(2);
});
if (mod.sourceCode !== source || typeof mod.run !== 'function') {
  console.error(`Fetcher ${source} does not export matching sourceCode and run()`);
  process.exit(2);
}

await withClient(async (client) => {
  const sourceRow = await getSource(client, source);
  const trigger = process.env.FETCHER_TRIGGER || 'manual';
  const run = await startRun(client, sourceRow.id, trigger);
  const ctx = { source: sourceRow, run };
  try {
    const result = await mod.run(client, ctx);
    if (result.checkpoint) {
      await saveCheckpoint(client, sourceRow.id, result.checkpoint);
    }
    await finishRun(client, run.id, {
      status: 'succeeded',
      fetchedCount: result.fetchedCount,
      changedCount: result.fetchedCount,
      parsedCount: result.parsedCount,
      errorCount: 0,
      checkpoint: result.checkpoint,
      logSummary: `${source} fetched ${result.fetchedCount} records`
    });
    console.log(JSON.stringify({ ok: true, source, runId: run.id, ...result }));
  } catch (error) {
    await recordError(client, ctx, 'fetch', error);
    await finishRun(client, run.id, {
      status: 'failed',
      fetchedCount: 0,
      changedCount: 0,
      parsedCount: 0,
      errorCount: 1,
      logSummary: error.message
    });
    console.error(JSON.stringify({ ok: false, source, error: error.message }));
    process.exit(1);
  }
});

function getArg(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}
