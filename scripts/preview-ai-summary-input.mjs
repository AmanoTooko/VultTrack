const args = parseArgs(process.argv.slice(2));

const apiBaseUrl = args.api ?? process.env.API_BASE_URL ?? 'http://localhost:5099';
const username = args.username ?? process.env.VULTRACK_ADMIN_USERNAME ?? process.env.ADMIN_USERNAME ?? 'admin';
const password = args.password ?? process.env.VULTRACK_ADMIN_PASSWORD ?? process.env.ADMIN_PASSWORD ?? 'admin';
const id = args.id ?? (args.identifier ? await resolveIdentifier(args.identifier) : null);

if (!id) {
  console.error('Usage: node scripts/preview-ai-summary-input.mjs --id <uuid> [--api http://localhost:5099]');
  console.error('   or: node scripts/preview-ai-summary-input.mjs --identifier CVE-2021-44228');
  process.exitCode = 1;
} else {
  const cookie = await login();
  const input = await api(`/api/v1/admin.vulnerability.aiSummaryInput?id=${encodeURIComponent(id)}`, { cookie });
  console.log(JSON.stringify(input, null, 2));
}

async function resolveIdentifier(identifier) {
  const row = await api(`/api/v1/vulnerability.getByIdentifier?identifier=${encodeURIComponent(identifier)}`);
  return row.id;
}

async function login() {
  const response = await fetch(new URL('/api/v1/auth.login', apiBaseUrl), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  const body = await response.json().catch(() => null);
  if (!response.ok || body?.ok === false) {
    throw new Error(`login failed: HTTP ${response.status} ${JSON.stringify(body)}`);
  }

  const cookie = response.headers.get('set-cookie')?.split(';')[0];
  if (!cookie) throw new Error('login did not return an auth cookie');
  return cookie;
}

async function api(path, options = {}) {
  const response = await fetch(new URL(path, apiBaseUrl), {
    headers: options.cookie ? { cookie: options.cookie } : undefined
  });
  const body = await response.json().catch(() => null);
  if (!response.ok || body?.ok === false) {
    throw new Error(`API failed: ${path} HTTP ${response.status} ${JSON.stringify(body)}`);
  }
  return body.data;
}

function parseArgs(argv) {
  const parsed = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    const [rawKey, inlineValue] = arg.slice(2).split('=', 2);
    const key = rawKey.replace(/-([a-z])/g, (_, ch) => ch.toUpperCase());
    parsed[key] = inlineValue ?? argv[++i];
  }
  return parsed;
}
