import http from 'node:http';
import https from 'node:https';

const apiBaseUrl = process.env.API_BASE_URL ?? 'http://localhost:5099';
const batchSize = Number.parseInt(process.env.LIMIT_PER_SOURCE ?? '50', 10) || 50;
const parallelism = Number.parseInt(process.env.NORMALIZE_PARALLELISM ?? '4', 10) || 4;
const maxCycles = Number.parseInt(process.env.MAX_CYCLES ?? '0', 10) || 0;
const sleepMs = Number.parseInt(process.env.SLEEP_MS ?? '0', 10) || 0;
const requestTimeoutMs = Number.parseInt(process.env.REQUEST_TIMEOUT_MS ?? '0', 10) || 0;
const sources = (process.env.NORMALIZE_SOURCES ?? [
  'nvd-cve',
  'cve-list-v5',
  'osv',
  'google-osv',
  'android-osv',
  'ubuntu-osv',
  'go-advisory',
  'cargo-advisory',
  'nvd-cpe',
  'first-epss',
  'cisa-kev',
  'github-advisory',
  'pypi-advisory',
  'maven-osv',
  'npm-osv',
  'nuget-osv'
].join(','))
  .split(',')
  .map((source) => source.trim())
  .filter(Boolean);

function postJson(path, payload) {
  const url = new URL(path, apiBaseUrl);
  const body = JSON.stringify(payload);
  const client = url.protocol === 'https:' ? https : http;

  return new Promise((resolve, reject) => {
    const request = client.request(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body)
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

async function normalizeSource(sourceCode, cycle) {
  const response = await postJson('/api/v1/raw.normalizeSource', {
    sourceCode,
    limit: batchSize
  });
  if (!response.ok || response.body?.ok === false) {
    throw new Error(`raw.normalizeSource failed for ${sourceCode}: ${JSON.stringify(response.body)}`);
  }

  const result = response.body.data ?? { sourceCode, processed: 0, failed: 0 };
  return {
    cycle,
    sourceCode,
    processed: Number(result.processed ?? 0),
    failed: Number(result.failed ?? 0)
  };
}

async function runPool(items, workerCount, cycle) {
  const results = [];
  let index = 0;

  async function worker() {
    while (index < items.length) {
      const source = items[index];
      index += 1;
      const startedAt = Date.now();
      try {
        const result = await normalizeSource(source, cycle);
        results.push({ ...result, elapsedMs: Date.now() - startedAt });
      } catch (error) {
        results.push({
          cycle,
          sourceCode: source,
          processed: 0,
          failed: 1,
          elapsedMs: Date.now() - startedAt,
          error: error.message
        });
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(workerCount, items.length) }, () => worker()));
  return results;
}

let cycle = 0;
while (true) {
  if (maxCycles > 0 && cycle >= maxCycles) {
    break;
  }

  cycle += 1;
  console.log(JSON.stringify({ cycle, event: 'cycle_start', batchSize, parallelism, sources }));
  const results = await runPool(sources, parallelism, cycle);
  results.sort((a, b) => sources.indexOf(a.sourceCode) - sources.indexOf(b.sourceCode));
  const processed = results.reduce((sum, item) => sum + item.processed, 0);
  const failed = results.reduce((sum, item) => sum + item.failed, 0);
  console.log(JSON.stringify({ cycle, processed, failed, results }));

  if (processed === 0) {
    break;
  }

  if (sleepMs > 0) {
    await new Promise((resolve) => setTimeout(resolve, sleepMs));
  }
}
