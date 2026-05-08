import { runOsvAllZipInit } from '../lib/osv-database.mjs';

export const sourceCode = 'google-osv-init';
export const runMode = 'init';

const GOOGLE_ECOSYSTEMS = ['Android', 'Chromium', 'Fuchsia', 'linux'];
const GOOGLE_OSV_PREFIXES = ['ASB-', 'OSV-', 'V8-'];

export async function run(client, ctx) {
  return runOsvAllZipInit(client, ctx, {
    prefixes: GOOGLE_OSV_PREFIXES,
    filter: (item) => (item.affected ?? [])
      .map((affected) => affected.package?.ecosystem ?? '')
      .some((ecosystem) => GOOGLE_ECOSYSTEMS.some((google) => ecosystem.toLowerCase().includes(google.toLowerCase()))),
    androidTable: false
  });
}
