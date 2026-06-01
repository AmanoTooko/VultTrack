import test from 'node:test';
import assert from 'node:assert/strict';

const baseUrl = process.env.API_BASE_URL ?? 'http://localhost:8080';
const adminUsername = process.env.VULTRACK_ADMIN_USERNAME ?? 'admin';
const adminPassword = process.env.VULTRACK_ADMIN_PASSWORD ?? 'admin';
let adminCookie = '';

async function login() {
  if (adminCookie) return adminCookie;
  const res = await fetch(`${baseUrl}/api/v1/auth.login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: adminUsername, password: adminPassword })
  });
  assert.equal(res.status, 200);
  adminCookie = res.headers.get('set-cookie')?.split(';')[0] ?? '';
  assert.match(adminCookie, /^vultrack_admin=/);
  return adminCookie;
}

test('system.health returns ok envelope', async () => {
  const res = await fetch(`${baseUrl}/api/v1/system.health`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.ok, true);
  assert.equal(body.data.service, 'vultrack-app');
});

test('frontend shell is served by the app', async () => {
  const res = await fetch(`${baseUrl}/index.html`);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /<title>VulTrack<\/title>/);
  assert.match(html, /\/app\.js/);
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

test('system.status requires an admin login', async () => {
  const res = await fetch(`${baseUrl}/api/v1/system.status`);
  assert.equal(res.status, 401);
});

test('admin login unlocks system.status and fetcher controls', async () => {
  const cookie = await login();
  const res = await fetch(`${baseUrl}/api/v1/system.status`, { headers: { cookie } });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.ok, true);
  assert.equal(typeof body.data.vulnerabilities, 'number');
  assert.ok(Array.isArray(body.data.normalizeStatus));
  assert.ok(Array.isArray(body.data.pendingBySource));

  const sourceRes = await fetch(`${baseUrl}/api/v1/admin.source.list`, { headers: { cookie } });
  assert.equal(sourceRes.status, 200);
  const sourceBody = await sourceRes.json();
  assert.equal(sourceBody.ok, true);
  assert.ok(sourceBody.data.some((source) => source.code === 'cnnvd' && source.enabled === true));
  assert.ok(sourceBody.data.some((source) => source.code === 'seebug' && source.enabled === false && source.runMode === 'manual'));
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
