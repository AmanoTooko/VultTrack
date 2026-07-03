#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

mkdir -p data/duckdb data/vulnerability-details data/logs

docker compose up -d --build postgres api frontend adminer

echo "Waiting for API readiness..."
for _ in $(seq 1 120); do
  if curl -fsS "http://127.0.0.1:5099/api/v1/system.ready" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! curl -fsS "http://127.0.0.1:5099/api/v1/system.ready" >/dev/null 2>&1; then
  echo "API did not become ready within 120 seconds." >&2
  docker compose logs --tail=120 api >&2 || true
  exit 1
fi

echo
echo "VulTrack is running:"
echo "  Frontend: http://localhost:3000"
echo "  API:      http://localhost:5099"
echo "  Adminer:  http://localhost:8081"
echo
node scripts/status-local.mjs
