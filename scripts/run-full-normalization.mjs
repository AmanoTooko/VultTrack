import http from 'node:http';
import https from 'node:https';
import { getAdminCookie } from './lib/admin-auth.mjs';

const apiBaseUrl = process.env.API_BASE_URL ?? 'http://localhost:5099';
const limitPerSource = Number.parseInt(process.env.LIMIT_PER_SOURCE ?? '50', 10) || 50;
const sleepMs = Number.parseInt(process.env.SLEEP_MS ?? '0', 10) || 0;
const maxCycles = Number.parseInt(process.env.MAX_CYCLES ?? '0', 10) || 0;
const requestTimeoutMs = Number.parseInt(process.env.REQUEST_TIMEOUT_MS ?? '0', 10) || 0;
const adminCookie = await getAdminCookie(apiBaseUrl);

function postJson(path, payload) {
  const url = new URL(path, apiBaseUrl);
  const body = JSON.stringify(payload);
  const client = url.protocol === 'https:' ? https : http;

  return new Promise((resolve, reject) => {
    const request = client.request(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        cookie: adminCookie
      }
    }, (response) => {
      response.setEncoding('utf8');
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const text = chunks.join('');
        let parsed;
        try {
          parsed = text.length > 0 ? JSON.parse(text) : null;
        } catch (error) {
          reject(new Error(`Invalid JSON response from ${path}: ${error.message}: ${text}`));
          return;
        }

        resolve({
          ok: response.statusCode >= 200 && response.statusCode < 300,
          statusCode: response.statusCode,
          body: parsed
        });
      });
    });

    request.on('error', reject);
    if (requestTimeoutMs > 0) {
      request.setTimeout(requestTimeoutMs, () => {
        request.destroy(new Error(`Request timed out after ${requestTimeoutMs}ms: ${path}`));
      });
    }

    request.write(body);
    request.end();
  });
}

let cycle = 0;
while (true) {
  if (maxCycles > 0 && cycle >= maxCycles) {
    break;
  }

  cycle += 1;
  console.log(JSON.stringify({ cycle, event: 'cycle_start', limitPerSource }));
  const response = await postJson('/api/v1/raw.normalizePending', { limitPerSource });
  if (!response.ok || response.body?.ok === false) {
    throw new Error(`raw.normalizePending failed: ${JSON.stringify(response.body)}`);
  }

  const results = response.body.data ?? [];
  const processed = results.reduce((sum, item) => sum + Number(item.processed ?? 0), 0);
  const failed = results.reduce((sum, item) => sum + Number(item.failed ?? 0), 0);
  console.log(JSON.stringify({ cycle, processed, failed, results }));

  if (processed === 0) {
    break;
  }

  if (sleepMs > 0) {
    await new Promise((resolve) => setTimeout(resolve, sleepMs));
  }
}
