import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { withClient } from '../../plugins/fetchers/lib/db.mjs';

test('database has source rows for every fetcher module', async () => {
  const sourceCodes = (await fs.readdir('plugins/fetchers/sources'))
    .filter((file) => file.endsWith('.mjs'))
    .map((file) => path.basename(file, '.mjs'))
    .sort();
  await withClient(async (client) => {
    const result = await client.query('select code from sources where code = any($1) order by code', [sourceCodes]);
    assert.deepEqual(result.rows.map((row) => row.code), sourceCodes);
  });
});

test('smoke fetchers wrote raw index rows for multiple sources', async () => {
  await withClient(async (client) => {
    const result = await client.query(`
      select s.code, count(r.*)::int as count
      from sources s
      left join source_raw_index r on r.source_id = s.id
      where s.code in ('nvd-cve','nvd-cpe','ghsa','osv','cve-list-v5','cisa-kev','first-epss','alpine-secdb','debian-security-tracker','ubuntu-osv')
      group by s.code
      order by s.code
    `);
    assert.equal(result.rowCount, 10);
    for (const row of result.rows) {
      assert.ok(row.count > 0, `${row.code} should have at least one raw row`);
    }
  });
});

test('staging tables contain NVD CVE rows', async () => {
  await withClient(async (client) => {
    const result = await client.query('select count(*)::int as count from stg_nvd_cves');
    assert.ok(result.rows[0].count > 0);
  });
});
