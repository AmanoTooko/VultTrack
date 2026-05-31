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

test('debian tracker package index is grouped into CVE records', async () => {
  const { groupByCve } = await import('../../plugins/fetchers/sources/debian-security-tracker.mjs');
  const records = groupByCve({
    apt: {
      'CVE-2011-3374': { releases: { bookworm: { status: 'open' } } },
      description: 'ignored'
    },
    zlib: {
      'CVE-2023-45853': { releases: { bookworm: { status: 'open' } } },
      'TEMP-123': { releases: { sid: { status: 'open' } } }
    }
  });

  assert.deepEqual([...records.keys()], ['CVE-2011-3374', 'CVE-2023-45853', 'TEMP-123']);
  assert.deepEqual(records.get('CVE-2011-3374'), {
    apt: { releases: { bookworm: { status: 'open' } } }
  });
});

test('exploit metadata sanitizer replaces only invalid Unicode surrogates', async () => {
  const { sanitizeUnicode } = await import('../../plugins/fetchers/lib/exploit-utils.mjs');
  assert.deepEqual(sanitizeUnicode({
    valid: 'before \uD83D\uDE00 after',
    invalid: ['high \uD800', 'low \uDC00']
  }), {
    valid: 'before \uD83D\uDE00 after',
    invalid: ['high \uFFFD', 'low \uFFFD']
  });
});
