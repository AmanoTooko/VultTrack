export async function getAdminCookie(apiBaseUrl) {
  const username = process.env.VULTRACK_ADMIN_USERNAME ?? 'admin';
  const password = process.env.VULTRACK_ADMIN_PASSWORD ?? 'admin';
  const response = await fetch(new URL('/api/v1/auth.login', apiBaseUrl), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  const body = await response.json().catch(() => null);
  if (!response.ok || body?.ok === false) {
    throw new Error(body?.error?.message ?? `Admin login failed: HTTP ${response.status}`);
  }
  const cookie = response.headers.get('set-cookie')?.split(';')[0];
  if (!cookie) throw new Error('Admin login did not return a session cookie.');
  return cookie;
}
