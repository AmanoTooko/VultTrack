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

test('china advisory identifiers collect domestic ids and CVEs', async () => {
  const { chinaIdentifiers } = await import('../../plugins/fetchers/lib/china-advisory.mjs');
  assert.deepEqual(chinaIdentifiers(
    'CNNVD-202605-6652 CVE-2026-4888',
    ['CNVD-2024-12345', 'SSV-99969', 'AVD-2024-1234', 'CT-3888079', 'NSFOCUS-142883', 'CERT360-663c2362c09f255b91b17fdd']
  ), [
    'CVE-2026-4888',
    'CNNVD-202605-6652',
    'CNVD-2024-12345',
    'SSV-99969',
    'AVD-2024-1234',
    'CT-3888079',
    'NSFOCUS-142883',
    'CERT360-663C2362C09F255B91B17FDD'
  ]);
});

test('domestic HTML fetcher parsers keep source ids and PoC signals', async () => {
  const { parseRows: parseSeebug } = await import('../../plugins/fetchers/sources/seebug.mjs');
  const { parseRows: parseAliyun } = await import('../../plugins/fetchers/sources/aliyun-avd.mjs');
  const { parseRows: parseNsfocus, parseDetail } = await import('../../plugins/fetchers/sources/nsfocus-vulndb.mjs');

  assert.deepEqual(parseSeebug(`
    <tr><td class="datetime">2026-05-01</td><td class="vul-level high"></td>
    <td><a class="vul-title" title="Example CVE-2026-1234" href="/vuldb/ssvid-99969">Example</a></td>
    <td><i class="fa fa-rocket" data-original-title="有 PoC"></i>
    <i class="fa fa-file-text-o" data-original-title="有详情"></i></td></tr>
  `)[0], {
    advisoryId: 'SSV-99969',
    title: 'Example CVE-2026-1234',
    publishedAt: '2026-05-01',
    severityLabel: 'high',
    identifiers: ['CVE-2026-1234'],
    pocAvailable: true,
    detailAvailable: true,
    sourceUrl: 'https://www.seebug.org/vuldb/ssvid-99969'
  });

  assert.equal(parseAliyun(`
    <tr><td>AVD-2024-1234</td><td><a href="/detail?id=AVD-2024-1234">Aliyun example</a></td>
    <td title="POC 已公开"></td><td>2026-05-02</td></tr>
  `)[0].pocAvailable, true);

  assert.equal(parseNsfocus(`
    <li><span>2026-05-03</span><a href="/vulndb/142883">NSFOCUS example</a></li>
  `)[0].advisoryId, 'NSFOCUS-142883');
  assert.equal(parseDetail(`
    <div align="center"><b>NSFOCUS example</b></div>
    <b>发布日期：</b>2026-05-03<br><b>更新日期：</b>2026-05-04<br>
    <b>受影响系统：</b><blockquote>Example Product</blockquote>
    <b>描述：</b><hr>Example description<b>建议：</b>
  `).description, 'Example description');
});
