import test from 'node:test';
import assert from 'node:assert/strict';

const baseUrl = process.env.API_BASE_URL ?? 'http://localhost:8080';

test('system.health returns ok envelope', async () => {
  const res = await fetch(`${baseUrl}/api/v1/system.health`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.ok, true);
  assert.equal(body.data.service, 'vultrack-app');
});

test('vulnerability.search returns processed NVD records', async () => {
  const res = await fetch(`${baseUrl}/api/v1/vulnerability.search`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ query: 'CVE', pageSize: 5 })
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.ok, true);
  assert.ok(body.data.items.length > 0);
  assert.match(body.data.items[0].primaryIdentifier, /^CVE-/);
});
