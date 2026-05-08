import { runOsvAllZipInit } from '../lib/osv-database.mjs';

export const sourceCode = 'android-osv-init';
export const runMode = 'init';

export async function run(client, ctx) {
  return runOsvAllZipInit(client, ctx, {
    ecosystem: 'Android',
    androidTable: true
  });
}
