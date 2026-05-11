import { runOsvModifiedIdIncremental } from '../lib/osv-database.mjs';
import { getCsvEnv } from '../lib/env.mjs';

export const sourceCode = 'maven-osv';

export async function run(client, ctx) {
  return runOsvModifiedIdIncremental(client, ctx, {
    ecosystem: 'Maven',
    ids: getCsvEnv('MAVEN_OSV_IDS'),
    smokeIds: ['GHSA-jfh8-c2jp-5v3q', 'GHSA-7rjr-3q55-vv33']
  });
}
