import { runOsvModifiedIdIncremental } from '../lib/osv-database.mjs';

export const sourceCode = 'maven-osv';

export async function run(client, ctx) {
  const smokeIds = (process.env.MAVEN_OSV_IDS ?? 'GHSA-jfh8-c2jp-5v3q,GHSA-7rjr-3q55-vv33')
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);

  return runOsvModifiedIdIncremental(client, ctx, {
    ecosystem: 'Maven',
    smokeIds
  });
}
