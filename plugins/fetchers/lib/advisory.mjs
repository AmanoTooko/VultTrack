export function extractIdentifiers(...values) {
  const text = values.filter(Boolean).join(' ');
  const ids = new Set();
  for (const match of text.matchAll(/\bCVE-\d{4}-\d{4,}\b/gi)) ids.add(match[0].toUpperCase());
  for (const match of text.matchAll(/\bGHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b/gi)) ids.add(match[0].toUpperCase());
  for (const match of text.matchAll(/\bGO-\d{4}-\d{4}\b/gi)) ids.add(match[0].toUpperCase());
  for (const match of text.matchAll(/\bRUSTSEC-\d{4}-\d{4}\b/gi)) ids.add(match[0].toUpperCase());
  return [...ids];
}

export function advisoryIdFromUrl(url, fallback) {
  const ids = extractIdentifiers(url);
  return ids.find((id) => id.startsWith('GHSA-')) ?? ids[0] ?? fallback;
}

export function nugetSeverityLabel(value) {
  return {
    0: 'low',
    1: 'moderate',
    2: 'high',
    3: 'critical'
  }[Number(value)] ?? null;
}

export function mavenPurl(groupId, artifactId, version = null) {
  const base = `pkg:maven/${encodeURIComponent(groupId)}/${encodeURIComponent(artifactId)}`;
  return version ? `${base}@${encodeURIComponent(version)}` : base;
}

export function npmPurl(name, version = null) {
  const encoded = name.startsWith('@')
    ? `@${encodeURIComponent(name.slice(1)).replace('%2F', '/')}`
    : encodeURIComponent(name);
  const base = `pkg:npm/${encoded}`;
  return version ? `${base}@${encodeURIComponent(version)}` : base;
}

export function firstUrl(item) {
  if (!item) return null;
  if (typeof item === 'string') return item;
  return item.url ?? item.href ?? null;
}
