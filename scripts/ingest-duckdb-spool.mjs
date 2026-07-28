#!/usr/bin/env node
import dotenv from 'dotenv';
import { loginAdmin, requestJson } from './lib/admin-api.mjs';

dotenv.config({ quiet: true });

const args = new Set(process.argv.slice(2));
const baseUrl = (process.env.API_BASE_URL ?? 'http://127.0.0.1:5099').replace(/\/$/, '');
const maxFilesArg = process.argv.find(value => value.startsWith('--max-files='));
const batchSizeArg = process.argv.find(value => value.startsWith('--batch-size='));
const maxFiles = Math.max(1, Number(maxFilesArg?.split('=', 2)[1] ?? 100));
const batchSize = Math.max(100, Number(batchSizeArg?.split('=', 2)[1] ?? 5000));

const cookie = await loginAdmin(
  baseUrl,
  process.env.VULTRACK_ADMIN_USERNAME ?? 'admin',
  process.env.VULTRACK_ADMIN_PASSWORD ?? 'change-me');

const response = await requestJson(baseUrl, '/api/v1/admin.duckdbSpool.ingest', {
  method: 'POST',
  headers: { cookie },
  body: { batchSize, maxFiles, deleteOnSuccess: !args.has('--keep') }
});
if (response.statusCode < 200 || response.statusCode >= 300)
  throw new Error(`Spool ingestion failed (${response.statusCode}): ${response.text}`);
console.log(response.text);
