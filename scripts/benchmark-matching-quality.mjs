#!/usr/bin/env node

const apiBase = process.env.API_BASE_URL || 'http://localhost:5099';
const params = new URLSearchParams();
for (const [flag, name] of [['--ecosystem', 'ecosystem'], ['--package', 'packageName'], ['--sbom', 'sbomId']]) {
  const value = arg(flag);
  if (value) params.set(name, value);
}

const url = `${apiBase}/api/v1/benchmark.matchingQuality${params.size ? `?${params}` : ''}`;
const res = await fetch(url);
const body = await res.json();
if (!res.ok || body.ok === false) {
  console.error(body.error?.message || `Request failed: ${res.status}`);
  process.exit(1);
}

const data = body.data;
console.log(JSON.stringify({
  filters: data.filters,
  affectedSummary: data.affectedSummary,
  sbomSummary: data.sbomSummary,
  standard: data.standard
}, null, 2));

function arg(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}
