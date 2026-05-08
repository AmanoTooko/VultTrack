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

test('system.status returns pipeline counters', async () => {
  const res = await fetch(`${baseUrl}/api/v1/system.status`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.ok, true);
  assert.equal(typeof body.data.vulnerabilities, 'number');
  assert.ok(Array.isArray(body.data.normalizeStatus));
  assert.ok(Array.isArray(body.data.pendingBySource));
});

test('vulnerability.detail returns multi-source projections', async () => {
  const search = await fetch(`${baseUrl}/api/v1/vulnerability.search`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ query: 'CVE', pageSize: 1 })
  });
  const searchBody = await search.json();
  const id = searchBody.data.items[0].id;

  const res = await fetch(`${baseUrl}/api/v1/vulnerability.detail?id=${encodeURIComponent(id)}`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.ok, true);
  assert.equal(body.data.vulnerability.id, id);
  assert.ok(Array.isArray(body.data.records));
  assert.ok(Array.isArray(body.data.identifiers));
  assert.ok(Array.isArray(body.data.affectedComponents));
});

test('component.search returns component catalog collections', async () => {
  const res = await fetch(`${baseUrl}/api/v1/component.search`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ query: 'pkg:', pageSize: 5 })
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.ok, true);
  assert.ok(Array.isArray(body.data.components));
  assert.ok(Array.isArray(body.data.registryPackages));
});
