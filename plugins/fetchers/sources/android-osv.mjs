import { runOsvModifiedIdIncremental } from '../lib/osv-database.mjs';
import { getCsvEnv } from '../lib/env.mjs';

export const sourceCode = 'android-osv';

export async function run(client, ctx) {
  return runOsvModifiedIdIncremental(client, ctx, {
    ecosystem: 'Android',
    androidTable: true,
    ids: getCsvEnv('ANDROID_OSV_IDS'),
    smokeIds: ['ASB-A-111893654', 'ASB-A-112551163']
  });
}
