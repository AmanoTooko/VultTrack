import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const scriptPath = path.join(__dirname, 'run-ai-vulnerability-analysis.mjs');

const defaults = [
  'analyze',
  `--endpoint=${process.env.VULTRACK_AI_BASE_URL ?? ''}`,
  `--api-key=${process.env.VULTRACK_AI_API_KEY ?? ''}`,
  `--model=${process.env.VULTRACK_AI_MODEL ?? 'mimo-v2.5-pro'}`,
  '--limit=14029',
  '--years=2020-2023',
  '--severity=CRITICAL',
  '--min-description-chars=0',
  '--concurrency=60',
  '--rpm=0',
  '--timeout-ms=180000',
  '--retries=4',
  '--retry-delay-ms=5000',
  '--retry-429-step-ms=5000',
  '--max-output-tokens=4096',
  '--no-fetch-original',
  '--quiet'
];

const child = spawn(process.execPath, [scriptPath, ...defaults, ...process.argv.slice(2)], {
  stdio: 'inherit'
});

child.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  process.exit(code ?? 1);
});
