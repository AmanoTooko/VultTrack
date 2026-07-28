#!/usr/bin/env node
import dotenv from 'dotenv';
import { loginAdmin, requestJson } from './lib/admin-api.mjs';

dotenv.config({ quiet: true });

const baseUrl = (process.env.API_BASE_URL ?? 'http://127.0.0.1:5099').replace(/\/$/, '');
const sources = (process.env.DUCKDB_BOOTSTRAP_SOURCES ?? 'nvd-cve-init,osv-init')
  .split(',')
  .map(value => value.trim())
  .filter(Boolean);
const force = process.env.DUCKDB_BOOTSTRAP_FORCE === '1';

const cookie = await loginAdmin(
  baseUrl,
  process.env.VULTRACK_ADMIN_USERNAME ?? 'admin',
  process.env.VULTRACK_ADMIN_PASSWORD ?? 'change-me');

for (const sourceCode of sources) {
  const startedAt = Date.now();
  console.log(`[bootstrap] fetching and importing ${sourceCode}...`);
  const response = await requestJson(baseUrl, '/api/v1/admin.source.fetch', {
    method: 'POST',
    headers: { cookie },
    body: { sourceCode, force, limit: 0 }
  });
  const result = response.json;
  if (response.statusCode < 200 || response.statusCode >= 300 || !result?.ok)
    throw new Error(`${sourceCode} failed: ${result?.error?.message ?? `HTTP ${response.statusCode}`}`);
  console.log(`[bootstrap] ${sourceCode} complete in ${Math.round((Date.now() - startedAt) / 1000)}s`);
}

const statusResponse = await requestJson(baseUrl, '/api/v1/system.status?fast=true', { headers: { cookie } });
const status = statusResponse.json;
if (statusResponse.statusCode < 200 || statusResponse.statusCode >= 300 || !status?.ok)
  throw new Error('Unable to read final DuckDB status.');
console.log(JSON.stringify(status.data, null, 2));
