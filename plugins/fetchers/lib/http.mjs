import { getIntEnv } from './env.mjs';

const BROWSER_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36';

const COMMON_HEADERS = {
  'accept': 'application/json, text/plain, */*',
  'accept-language': 'en-US,en;q=0.9',
  'accept-encoding': 'gzip, deflate, br',
  'user-agent': BROWSER_UA,
  'sec-fetch-dest': 'empty',
  'sec-fetch-mode': 'cors',
  'sec-fetch-site': 'cross-site',
  'sec-gpc': '1',
  'cache-control': 'no-cache',
  'pragma': 'no-cache',
};

export async function fetchJson(url, options = {}) {
  const res = await fetchWithTimeout(url, options);
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status} for ${url}: ${text.slice(0, 500)}`);
  }
  return res.json();
}

export async function fetchBuffer(url, options = {}) {
  const res = await fetchWithTimeout(url, options);
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status} for ${url}: ${text.slice(0, 500)}`);
  }
  return Buffer.from(await res.arrayBuffer());
}

export async function fetchText(url, options = {}) {
  const res = await fetchWithTimeout(url, options);
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status} for ${url}: ${text.slice(0, 500)}`);
  }
  return res.text();
}

async function fetchWithTimeout(url, options = {}) {
  const timeoutMs = getIntEnv('FETCHER_TIMEOUT_MS', 120000);
  const retries = Math.max(0, getIntEnv('FETCHER_HTTP_RETRIES', 3));
  const baseDelayMs = Math.max(100, getIntEnv('FETCHER_HTTP_RETRY_BASE_MS', 1000));
  const method = String(options.method ?? 'GET').toUpperCase();
  const retryableMethod = method === 'GET' || method === 'HEAD';

  for (let attempt = 0; ; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          ...COMMON_HEADERS,
          ...(options.headers ?? {})
        }
      });
      if (!retryableMethod || attempt >= retries || (response.status !== 429 && response.status < 500)) {
        return response;
      }

      const retryAfter = Number.parseInt(response.headers.get('retry-after') ?? '', 10);
      await response.body?.cancel().catch(() => {});
      await delay(Number.isFinite(retryAfter) ? retryAfter * 1000 : retryDelay(baseDelayMs, attempt));
    } catch (error) {
      if (!retryableMethod || attempt >= retries) throw error;
      await delay(retryDelay(baseDelayMs, attempt));
    } finally {
      clearTimeout(timer);
    }
  }
}

function retryDelay(baseDelayMs, attempt) {
  const exponential = Math.min(30000, baseDelayMs * (2 ** attempt));
  return exponential + Math.floor(Math.random() * Math.min(500, baseDelayMs));
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export function authHeaders() {
  const githubToken = process.env.GITHUB_TOKEN;
  const nvdKey = process.env.NVD_API_KEY;
  return { githubToken, nvdKey };
}
