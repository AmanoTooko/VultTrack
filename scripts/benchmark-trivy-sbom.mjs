#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import { basename } from 'node:path';

const apiBase = process.env.API_BASE_URL ?? 'http://127.0.0.1:5099';
const sbomPath = arg('--sbom');
const trivyPath = arg('--trivy');
const outPath = arg('--out');
if (!sbomPath || !trivyPath) {
  console.error('Usage: node scripts/benchmark-trivy-sbom.mjs --sbom image.cdx.json --trivy image_scan.json [--out report.json]');
  process.exit(1);
}

const [sbomText, trivyText] = await Promise.all([readFile(sbomPath, 'utf8'), readFile(trivyPath, 'utf8')]);
const trivy = JSON.parse(trivyText);
const upload = await api('/api/v1/sbom.upload?name=' + encodeURIComponent(`Trivy benchmark: ${basename(sbomPath)}`), {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: sbomText
});
const sbomId = upload.id;
await api('/api/v1/sbom.match', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ sbomId })
});
const scanned = await api(`/api/v1/sbom.get?id=${encodeURIComponent(sbomId)}&vulnerabilityLimit=10000`);

const trivyRows = (trivy.Results ?? []).flatMap((result) =>
  (result.Vulnerabilities ?? []).map((finding) => ({
    cve: finding.VulnerabilityID,
    packageName: finding.PkgName,
    installedVersion: finding.InstalledVersion,
    fixedVersion: finding.FixedVersion ?? null,
    status: finding.Status ?? null,
    target: result.Target,
    type: result.Type,
    dataSource: finding.DataSource?.ID ?? null
  })));
const vultrackRows = (scanned.vulnerabilities ?? []).map((finding) => ({
  cve: finding.primaryIdentifier,
  componentName: finding.componentName,
  ecosystem: finding.ecosystem,
  range: finding.versionRange,
  matchBasis: finding.matchBasis,
  matchedVersion: finding.matchedVersion
}));

const trivyIds = new Set(trivyRows.map((row) => row.cve));
const vultrackIds = new Set(vultrackRows.map((row) => row.cve));
const both = [...trivyIds].filter((id) => vultrackIds.has(id)).sort();
const trivyOnly = [...trivyIds].filter((id) => !vultrackIds.has(id)).sort();
const vultrackOnly = [...vultrackIds].filter((id) => !trivyIds.has(id)).sort();
const report = {
  generatedAt: new Date().toISOString(),
  apiBase,
  sbomId,
  standard: {
    reference: 'Trivy is a comparison oracle, not an absolute truth source.',
    affected: 'A finding is confirmed only when component identity and an ecosystem-aware affected version range both match.',
    debian: 'Debian image packages are matched against Debian Security Tracker release facts. Binary packages may use Trivy SrcName/SrcVersion to match the source package advisory.',
    triage: 'trivyOnly and vultrackOnly findings require source evidence review before being labeled false negative or false positive.'
  },
  summary: {
    trivyFindingRows: trivyRows.length,
    trivyUniqueCves: trivyIds.size,
    vultrackFindingRows: vultrackRows.length,
    vultrackUniqueCves: vultrackIds.size,
    confirmedByBoth: both.length,
    trivyOnly: trivyOnly.length,
    vultrackOnly: vultrackOnly.length
  },
  confirmedByBoth: both,
  trivyOnly: group(trivyOnly, trivyRows, classifyTrivyOnly),
  vultrackOnly: group(vultrackOnly, vultrackRows, classifyVultrackOnly)
};

const output = JSON.stringify(report, null, 2);
if (outPath) await writeFile(outPath, output + '\n');
console.log(output);

async function api(path, init) {
  const response = await fetch(`${apiBase}${path}`, init);
  const body = await response.json();
  if (!response.ok || body.ok === false) throw new Error(body.error?.message ?? `${path}: HTTP ${response.status}`);
  return body.data;
}

function group(ids, rows, classify) {
  return ids.map((cve) => {
    const findings = rows.filter((row) => row.cve === cve);
    return { cve, reason: classify(findings), findings };
  });
}

function classifyTrivyOnly(rows) {
  if (rows.some((row) => row.type === 'debian'))
    return 'debian_advisory_missing_source_mapping_or_requires_clean_renormalization';
  if (rows.some((row) => row.type === 'alpine'))
    return 'alpine_advisory_missing_release_fact_or_requires_clean_renormalization';
  return 'source_coverage_or_database_snapshot_gap';
}

function classifyVultrackOnly(rows) {
  if (rows.some((row) => row.range === '>= 0'))
    return 'broad_vendor_open_range_requires_authority_review';
  return 'newer_local_advisory_trivy_snapshot_gap_or_historical_projection_pollution';
}

function arg(flag) {
  const index = process.argv.indexOf(flag);
  return index >= 0 ? process.argv[index + 1] : null;
}
