import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';

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
