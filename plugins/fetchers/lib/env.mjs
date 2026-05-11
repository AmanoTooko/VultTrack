import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../../../.env'), quiet: true });
dotenv.config({ path: path.resolve(__dirname, '../../../.env.example'), quiet: true });

export function getEnv(name, fallback = undefined) {
  const value = process.env[name];
  return value === undefined || value === '' ? fallback : value;
}

export function getIntEnv(name, fallback = undefined) {
  const value = getEnv(name);
  if (value === undefined) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function getBoolEnv(name, fallback = false) {
  const value = getEnv(name);
  if (value === undefined) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
}

export function getCsvEnv(name, fallback = '') {
  return getEnv(name, fallback)
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
}

export function getRootPath(...parts) {
  return path.resolve(__dirname, '../../..', ...parts);
}
