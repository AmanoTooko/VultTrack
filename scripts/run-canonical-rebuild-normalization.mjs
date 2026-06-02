#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import pg from 'pg';

const phases = [
  {
    name: 'authoritative-cve-base',
    parallelism: '1',
    sources: ['nvd-cve', 'cve-list-v5']
  },
  {
    name: 'package-and-distribution-advisories',
    parallelism: '4',
    sources: [
      'ghsa', 'npm-advisory', 'npm-audit', 'osv', 'osv-init', 'ubuntu-osv',
      'android-osv', 'android-osv-init', 'google-osv', 'google-osv-init',
      'go-advisory', 'cargo-advisory', 'maven-osv', 'maven-osv-init',
      'pypi-advisory', 'maven-advisory', 'nuget-advisory', 'redhat-csaf',
      'suse-csaf', 'alpine-secdb', 'debian-security-tracker'
    ]
  },
  {
    name: 'enrichment-and-domestic-advisories',
    parallelism: '3',
    sources: [
      'cisa-kev', 'first-epss', 'cnnvd', 'cnvd', 'seebug', 'aliyun-avd',
      'nsfocus-vulndb', 'chaitin-vuldb', 'cert-360'
    ]
  },
  {
    name: 'exploit-intelligence',
    parallelism: '2',
    sources: ['exploitdb', 'metasploit', 'nuclei-templates', 'poc-in-github', 'trickest-cve']
  },
  {
    name: 'component-catalogs',
    parallelism: '3',
    sources: [
      'nvd-cpe', 'npm-registry', 'nuget-registry', 'maven-registry',
      'pypi-registry', 'crates-registry', 'rubygems-registry', 'packagist-registry'
    ]
  }
];

for (const phase of phases) {
  console.log(JSON.stringify({ event: 'canonical_rebuild_phase_start', ...phase }));
  const result = spawnSync(process.execPath, ['scripts/run-parallel-normalization.mjs'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      NORMALIZE_SOURCES: phase.sources.join(','),
      NORMALIZE_PARALLELISM: process.env.NORMALIZE_PARALLELISM ?? phase.parallelism
    },
    stdio: 'inherit'
  });
  if (result.status !== 0) {
    throw new Error(`Canonical rebuild phase failed: ${phase.name}`);
  }
  console.log(JSON.stringify({ event: 'canonical_rebuild_phase_complete', name: phase.name }));
}

const { Client } = pg;
const databaseUrl = process.env.DATABASE_URL ?? 'postgres://vultrack:vultrack@127.0.0.1:5432/vultrack';
const client = new Client({ connectionString: databaseUrl });
await client.connect();
try {
  console.log(JSON.stringify({ event: 'canonical_rebuild_analyze_start' }));
  await client.query('analyze');
  console.log(JSON.stringify({ event: 'canonical_rebuild_analyze_complete' }));
} finally {
  await client.end();
}
