#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/home/ubuntu/vultrack}"
ENV_FILE="$APP_DIR/.env.production"
RELEASE_SHA="${RELEASE_SHA:-}"
DUCKDB_PATH="${DUCKDB_PATH:-}"
SCHEDULER_ENABLED="${SCHEDULER_ENABLED:-false}"

if [[ ! "$RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "RELEASE_SHA must be a full lowercase Git commit SHA" >&2
  exit 1
fi
if [[ "$DUCKDB_PATH" != /workspace/data/* || "$DUCKDB_PATH" == *..* ]]; then
  echo "DUCKDB_PATH must be a normalized path below /workspace/data" >&2
  exit 1
fi
if [[ "$SCHEDULER_ENABLED" != "false" && "$SCHEDULER_ENABLED" != "true" ]]; then
  echo "SCHEDULER_ENABLED must be false or true" >&2
  exit 1
fi
if [[ ! -f "$ENV_FILE" || -L "$ENV_FILE" ]]; then
  echo "A regular $ENV_FILE is required" >&2
  exit 1
fi

host_duckdb_candidate="$APP_DIR/data/${DUCKDB_PATH#/workspace/data/}"
if [[ -L "$host_duckdb_candidate" ]]; then
  echo "Configured DuckDB must not be a symbolic link: $host_duckdb_candidate" >&2
  exit 1
fi
host_duckdb_path="$(realpath -m -- "$host_duckdb_candidate")"
case "$host_duckdb_path" in
  "$APP_DIR"/data/*) ;;
  *) echo "Resolved DuckDB path escapes $APP_DIR/data" >&2; exit 1 ;;
esac
if [[ ! -f "$host_duckdb_path" ]]; then
  echo "Configured DuckDB must already exist as a regular non-symbolic file: $host_duckdb_path" >&2
  exit 1
fi

umask 077
temporary_file="$(mktemp "$APP_DIR/.env.production.tmp.XXXXXX")"
cleanup() {
  if [[ -n "${temporary_file:-}" && -f "$temporary_file" ]]; then
    rm -- "$temporary_file"
  fi
}
trap cleanup EXIT

awk '
  BEGIN {
    drop["VULTRACK_STORAGE_BACKEND"] = 1
    drop["VULTRACK_DUCKDB_ENABLED"] = 1
    drop["VULTRACK_DUCKDB_PATH"] = 1
    drop["VULTRACK_DUCKDB_MEMORY_LIMIT"] = 1
    drop["VULTRACK_DUCKDB_THREADS"] = 1
    drop["VULTRACK_SCHEDULER_ENABLED"] = 1
    drop["DUCKDB_ALLOW_AUTOMATIC_INIT"] = 1
    drop["VULTRACK_API_IMAGE"] = 1
    drop["VULTRACK_FRONTEND_IMAGE"] = 1
  }
  {
    separator = index($0, "=")
    key = separator > 0 ? substr($0, 1, separator - 1) : ""
    if (!(key in drop)) print
  }
' "$ENV_FILE" > "$temporary_file"

{
  printf '\nVULTRACK_STORAGE_BACKEND=duckdb\n'
  printf 'VULTRACK_DUCKDB_ENABLED=true\n'
  printf 'VULTRACK_DUCKDB_PATH=%s\n' "$DUCKDB_PATH"
  printf 'VULTRACK_DUCKDB_MEMORY_LIMIT=3g\n'
  printf 'VULTRACK_DUCKDB_THREADS=4\n'
  printf 'VULTRACK_SCHEDULER_ENABLED=%s\n' "$SCHEDULER_ENABLED"
  printf 'DUCKDB_ALLOW_AUTOMATIC_INIT=false\n'
  printf 'VULTRACK_API_IMAGE=ghcr.io/amanotooko/vultrack-api:%s\n' "$RELEASE_SHA"
  printf 'VULTRACK_FRONTEND_IMAGE=ghcr.io/amanotooko/vultrack-frontend:%s\n' "$RELEASE_SHA"
} >> "$temporary_file"

chmod --reference="$ENV_FILE" "$temporary_file"
sync -f "$temporary_file"
mv -- "$temporary_file" "$ENV_FILE"
temporary_file=""
sync -f "$ENV_FILE"
trap - EXIT
echo "Configured production release $RELEASE_SHA with scheduler=$SCHEDULER_ENABLED and DuckDB=$DUCKDB_PATH"
