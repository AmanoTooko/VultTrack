import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

const expectedSources = [
  'nvd-cve',
  'nvd-cpe',
  'ghsa',
  'osv',
  'cve-list-v5',
  'cisa-kev',
  'first-epss',
  'alpine-secdb',
  'debian-security-tracker',
  'ubuntu-osv'
];

test('all required fetchers exist and export run()', async () => {
  for (const source of expectedSources) {
    await fs.access(`plugins/fetchers/sources/${source}.mjs`);
    const mod = await import(`../../plugins/fetchers/sources/${source}.mjs`);
    assert.equal(typeof mod.run, 'function', `${source} exports run`);
    assert.equal(mod.sourceCode, source);
  }
});
