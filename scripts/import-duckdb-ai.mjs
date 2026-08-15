#!/usr/bin/env node
import dotenv from 'dotenv';
import { loginAdmin, requestJson } from './lib/admin-api.mjs';

dotenv.config({ quiet: true });

const baseUrl = (process.env.API_BASE_URL ?? 'http://127.0.0.1:5099').replace(/\/$/, '');
const path = process.argv[2]
  ?? process.env.VULTRACK_AI_IMPORT_PATH
  ?? '/workspace/import/vultrack-ai-portable-20260721.csv.gz';
const expectedRowsRaw = process.env.VULTRACK_AI_EXPECTED_ROWS;
const expectedRows = expectedRowsRaw == null ? undefined : Number.parseInt(expectedRowsRaw, 10);
if (expectedRowsRaw != null && (!Number.isSafeInteger(expectedRows) || expectedRows <= 0))
  throw new Error('VULTRACK_AI_EXPECTED_ROWS must be a positive integer when supplied.');
const cookie = await loginAdmin(
  baseUrl,
  process.env.VULTRACK_ADMIN_USERNAME ?? 'admin',
  process.env.VULTRACK_ADMIN_PASSWORD ?? 'change-me');
const response = await requestJson(baseUrl, '/api/v1/admin.duckdbAi.import', {
  method: 'POST',
  headers: { cookie },
  body: { path, ...(expectedRows == null ? {} : { expectedRows }) }
});
if (response.statusCode < 200 || response.statusCode >= 300 || !response.json?.ok)
  throw new Error(`AI import failed (${response.statusCode}): ${response.text}`);
console.log(response.text);
