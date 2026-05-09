#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-vultrack-postgres}"
DB_NAME="${DB_NAME:-vultrack}"
DB_USER="${DB_USER:-vultrack}"
OUT_DIR="${OUT_DIR:-backups}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_FILE="${OUT_FILE:-$OUT_DIR/vultrack-${DB_NAME}-${STAMP}.sql.gz}"

mkdir -p "$OUT_DIR"

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  echo "Postgres container not running: $CONTAINER_NAME" >&2
  exit 1
fi

docker exec "$CONTAINER_NAME" pg_dump -U "$DB_USER" -d "$DB_NAME" | gzip > "$OUT_FILE"
echo "$OUT_FILE"
