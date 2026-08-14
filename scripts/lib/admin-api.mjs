import http from 'node:http';
import https from 'node:https';

export async function loginAdmin(baseUrl, username, password) {
  const response = await requestJson(baseUrl, '/api/v1/auth.login', {
    method: 'POST',
    body: { username, password }
  });
  const cookie = response.headers['set-cookie']?.[0]?.split(';', 1)[0];
  if (response.statusCode < 200 || response.statusCode >= 300 || !cookie)
    throw new Error(`Admin login failed (${response.statusCode}).`);
  return cookie;
}

export function requestJson(baseUrl, path, options = {}) {
  const url = new URL(path, baseUrl);
  const method = options.method ?? 'GET';
  const payload = options.body === undefined ? null : JSON.stringify(options.body);
  const transport = url.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const headers = { ...(options.headers ?? {}) };
    if (payload !== null) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = Buffer.byteLength(payload);
    }
    const req = transport.request(url, { method, headers }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = text ? JSON.parse(text) : null; } catch { /* response body is not JSON */ }
        resolve({
          statusCode: res.statusCode ?? 0,
          headers: res.headers,
          text,
          json
        });
      });
    });
    req.on('error', reject);
    if (payload !== null) req.write(payload);
    req.end();
  });
}
