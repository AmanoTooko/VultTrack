#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

mkdir -p data/duckdb data/spool/incoming data/spool/state

docker compose up -d --build --remove-orphans api frontend

echo "Waiting for API readiness..."
READY_URL="${API_BASE_URL:-}"
if [[ -n "$READY_URL" ]]; then
  READY_URL="${READY_URL%/}/api/v1/system.ready"
fi
for _ in $(seq 1 120); do
  if [[ -n "$READY_URL" ]] && curl -fsS "$READY_URL" >/dev/null 2>&1; then
    break
  fi
  for candidate in \
    "http://127.0.0.1:5099/api/v1/system.ready" \
    "http://127.0.0.1:3000/api/v1/system.ready"; do
    if curl -fsS "$candidate" >/dev/null 2>&1; then
      READY_URL="$candidate"
      break 2
    fi
  done
  sleep 1
done

if [[ -z "$READY_URL" ]] || ! curl -fsS "$READY_URL" >/dev/null 2>&1; then
  echo "API did not become ready within 120 seconds." >&2
  docker compose logs --tail=120 api >&2 || true
  exit 1
fi

echo
echo "VulTrack is running:"
echo "  Frontend: http://localhost:3000"
echo "  Ready:    $READY_URL"
echo
API_BASE_URL="${READY_URL%/api/v1/system.ready}" node scripts/status-local.mjs
