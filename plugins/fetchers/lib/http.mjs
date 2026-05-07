import { getEnv, getIntEnv } from './env.mjs';

export async function fetchJson(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: {
      'accept': 'application/json',
      'user-agent': getEnv('FETCHER_USER_AGENT', 'VulTrack/0.1'),
      ...(options.headers ?? {})
    }
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status} for ${url}: ${text.slice(0, 500)}`);
  }
  return res.json();
}

export async function fetchBuffer(url, options = {}) {
  const timeoutMs = getIntEnv('FETCHER_TIMEOUT_MS', 120000);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'user-agent': getEnv('FETCHER_USER_AGENT', 'VulTrack/0.1'),
        ...(options.headers ?? {})
      }
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status} for ${url}: ${text.slice(0, 500)}`);
    }
    return Buffer.from(await res.arrayBuffer());
  } finally {
    clearTimeout(timer);
  }
}

export function authHeaders() {
  const githubToken = getEnv('GITHUB_TOKEN');
  const nvdKey = getEnv('NVD_API_KEY');
  return { githubToken, nvdKey };
}
