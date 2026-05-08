import { runOsvModifiedIdIncremental } from '../lib/osv-database.mjs';

export const sourceCode = 'android-osv';

export async function run(client, ctx) {
  const smokeIds = (process.env.ANDROID_OSV_IDS ?? 'ASB-A-111893654,ASB-A-112551163')
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);

  return runOsvModifiedIdIncremental(client, ctx, {
    ecosystem: 'Android',
    androidTable: true,
    smokeIds
  });
}
