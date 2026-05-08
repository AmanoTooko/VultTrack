import { runOsvAllZipInit } from '../lib/osv-database.mjs';

export const sourceCode = 'osv-init';
export const runMode = 'init';

export async function run(client, ctx) {
  return runOsvAllZipInit(client, ctx);
}
