#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <dump.sql.gz|dump.sql>" >&2
  exit 1
fi

INPUT_FILE="$1"
CONTAINER_NAME="${CONTAINER_NAME:-vultrack-postgres}"
DB_NAME="${DB_NAME:-vultrack}"
DB_USER="${DB_USER:-vultrack}"

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  echo "Postgres container not running: $CONTAINER_NAME" >&2
  exit 1
fi

if [[ "$INPUT_FILE" == *.gz ]]; then
  gzip -dc "$INPUT_FILE" | docker exec -i "$CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME"
else
  docker exec -i "$CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME" < "$INPUT_FILE"
fi
