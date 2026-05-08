const apiBaseUrl = process.env.API_BASE_URL ?? 'http://localhost:5099';
const limitPerSource = Number.parseInt(process.env.LIMIT_PER_SOURCE ?? '1000', 10) || 1000;
const sleepMs = Number.parseInt(process.env.SLEEP_MS ?? '0', 10) || 0;
const maxCycles = Number.parseInt(process.env.MAX_CYCLES ?? '0', 10) || 0;

let cycle = 0;
while (true) {
  if (maxCycles > 0 && cycle >= maxCycles) {
    break;
  }

  cycle += 1;
  const response = await fetch(`${apiBaseUrl}/api/v1/raw.normalizePending`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ limitPerSource })
  });
  const body = await response.json();
  if (!response.ok || body.ok === false) {
    throw new Error(`raw.normalizePending failed: ${JSON.stringify(body)}`);
  }

  const results = body.data ?? [];
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
