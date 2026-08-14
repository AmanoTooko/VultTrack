import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { getIntEnv, getRootPath } from '../lib/env.mjs';
import { sha256, stableJson } from '../lib/hash.mjs';
import { writeRecord } from '../lib/db.mjs';

export const sourceCode = 'cargo-advisory';

// Clone rustsec/advisory-db and process TOML advisory files
async function ensureRepo(repoPath) {
  try {
    await fs.access(path.join(repoPath, '.git'));
    console.error('[cargo-advisory] refreshing rustsec/advisory-db...');
    runGit(['-C', repoPath, 'fetch', '--depth', '1', 'origin', 'HEAD']);
    runGit(['-C', repoPath, 'reset', '--hard', 'FETCH_HEAD']);
  } catch {
    console.error('[cargo-advisory] cloning rustsec/advisory-db...');
    await fs.mkdir(repoPath, { recursive: true });
    spawnSync('git', ['clone', '--depth', '1', 'https://github.com/rustsec/advisory-db.git', repoPath], { stdio: 'inherit' });
  }
}

function runGit(args) {
  const result = spawnSync('git', args, { stdio: 'inherit' });
  if (result.status !== 0) throw new Error(`git ${args.join(' ')} failed`);
}

// Simple TOML parser for RustSec advisory frontmatter
function parseAdvisoryToml(raw) {
  const item = { advisory: { aliases: [], categories: [] }, versions: {} };
  let currentSection = 'advisory';
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    // Section header
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      currentSection = trimmed.slice(1, -1);
      if (!item[currentSection]) item[currentSection] = {};
      continue;
    }
    const eq = trimmed.indexOf('=');
    if (eq < 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let val = trimmed.slice(eq + 1).trim();
    // Parse value
    const isQuoted = val.length >= 2 && (
      (val[0] === '\u0022' && val[val.length-1] === '\u0022') ||
      (val[0] === '\u0027' && val[val.length-1] === '\u0027')
    );
    if (isQuoted) {
      val = val.slice(1, -1);
    } else if (val.startsWith('[') && val.endsWith(']')) {
      // Array: strip brackets and quotes
      val = val.slice(1, -1).split(',').map(v => v.trim().replace(/^["']|["']$/g, '')).filter(Boolean);
    } else if (val === 'true') val = true;
    else if (val === 'false') val = false;

    const target = currentSection === 'advisory' ? item.advisory : (item.versions || {});
    if (Array.isArray(target[key])) {
      if (Array.isArray(val)) target[key].push(...val);
      else target[key].push(val);
    } else {
      target[key] = val;
    }
    if (currentSection === 'versions') item.versions = target;
  }
  return item;
}

export async function run(client, ctx) {
  const max = getIntEnv('FETCHER_MAX_RECORDS', Number.MAX_SAFE_INTEGER);
  const checkpoint = ctx.source.checkpoint_json ?? {};
  const repoPath = getRootPath('data/mirrors/rustsec-advisory-db');

  await ensureRepo(repoPath);

  const headResult = spawnSync('git', ['-C', repoPath, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
  const headCommit = headResult.status === 0 ? headResult.stdout.trim() : null;
  if (headCommit && checkpoint.commit === headCommit) {
    console.error('[cargo-advisory] unchanged, skipping.');
    return { fetchedCount: 0, parsedCount: 0, checkpoint: { commit: headCommit, skipped: true } };
  }

  // RustSec advisories are .md files with TOML frontmatter
  const cratesDir = path.join(repoPath, 'crates');
  const files = [];
  async function walk(dir) {
    const items = await fs.readdir(dir, { withFileTypes: true });
    for (const item of items) {
      const full = path.join(dir, item.name);
      if (item.isDirectory()) await walk(full);
      else if (item.name.endsWith('.md')) files.push(full);
    }
  }
  await walk(cratesDir);
  console.error(`[cargo-advisory] found ${files.length} advisory files`);

  let count = 0;
  for (const file of files) {
    if (count >= max) break;
    const raw = await fs.readFile(file, 'utf8');
    // Extract TOML frontmatter from markdown
    const tomlMatch = raw.match(/```toml\n([\s\S]*?)```/);
    const advisory = tomlMatch ? parseAdvisoryToml(tomlMatch[1]) : {};
    const adv = advisory.advisory || advisory;
    const id = adv.id || path.basename(file, '.md');
    const pkgName = adv.package;

    // Convert to OSV-like format
    const payload = {
      id: id,
      summary: adv.title || adv.description?.slice?.(0, 200) || '',
      details: adv.description || '',
      aliases: (adv.aliases || []).filter(Boolean),
      affected: pkgName ? [{
        package: { name: pkgName, ecosystem: 'crates.io' },
        ranges: [{ type: 'SEMVER', events: [] }]
      }] : [],
      references: (adv.url ? [{ url: adv.url, type: 'ADVISORY' }] : []),
      published: adv.date || null,
      modified: adv.date || null,
      severity: adv.cvss ? [{ type: 'CVSS_V3', score: adv.cvss }] : []
    };

    // Parse version bounds
    const versions = advisory.versions || {};
    if (versions.patched) {
      const patched = Array.isArray(versions.patched) ? versions.patched : [versions.patched];
      patched.forEach(v => payload.affected[0].ranges[0].events.push({ fixed: String(v) }));
    }
    if (versions.unaffected) {
      const unaff = Array.isArray(versions.unaffected) ? versions.unaffected : [versions.unaffected];
      unaff.forEach(v => payload.affected[0].ranges[0].events.push({ introduced: String(v) }));
    }

    const ids = [payload.id, ...payload.aliases].filter(Boolean);
    await writeRecord(client, ctx, {
      externalKey: payload.id,
      externalId: payload.id,
      sourceUrl: `https://rustsec.org/advisories/${id}.html`,
      publishedAt: payload.published,
      modifiedAt: payload.modified,
      identifiers: ids,
      recordHash: sha256(stableJson(payload)),
      payload
    });
    count++;
  }

  console.error(`[cargo-advisory] done, ${count} records`);
  return { fetchedCount: count, parsedCount: count, checkpoint: { commit: headCommit, lastFetched: new Date().toISOString() } };
}
