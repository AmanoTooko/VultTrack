#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/home/ubuntu/vultrack}"
BRANCH="${BRANCH:-main}"

cd "$APP_DIR"

current_branch="$(git branch --show-current)"
if [[ "$current_branch" != "$BRANCH" ]]; then
  echo "Refusing to deploy branch $BRANCH while $current_branch is checked out" >&2
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Refusing to deploy over tracked local changes in $APP_DIR" >&2
  exit 1
fi

case "$(uname -m)" in
  aarch64|arm64|x86_64|amd64) ;;
  *) echo "Unsupported deployment architecture: $(uname -m)" >&2; exit 1 ;;
esac

available_memory_kb="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
if [[ -z "$available_memory_kb" || "$available_memory_kb" -lt 4194304 ]]; then
  echo "Refusing to deploy with less than 4 GiB available memory" >&2
  exit 1
fi

available_disk_kb="$(df -Pk "$APP_DIR" | awk 'NR == 2 {print $4}')"
if [[ -z "$available_disk_kb" || "$available_disk_kb" -lt 20971520 ]]; then
  echo "Refusing to deploy with less than 20 GiB available disk" >&2
  exit 1
fi

if [[ ! -f .env.production || -L .env.production ]]; then
  echo "A regular .env.production file is required" >&2
  exit 1
fi

read_env_setting() {
  local key="$1"
  awk -v key="$key" '
    index($0, key "=") == 1 { value = substr($0, length(key) + 2); found = 1 }
    END { if (!found || value == "") exit 1; print value }
  ' .env.production
}

unquote_env_value() {
  local value="${1%$'\r'}"
  value="${value#\"}"
  value="${value%\"}"
  value="${value#\'}"
  value="${value%\'}"
  printf '%s\n' "$value"
}

# Production must never fall through to the in-code filename and silently create an empty
# catalog. A genuinely fresh deployment has to opt in explicitly.
duckdb_path="$(unquote_env_value "$(read_env_setting VULTRACK_DUCKDB_PATH || true)")"
if [[ "$duckdb_path" != /workspace/data/* || "$duckdb_path" == */../* || "$duckdb_path" == */.. ]]; then
  echo "VULTRACK_DUCKDB_PATH must be explicitly set below /workspace/data" >&2
  exit 1
fi
host_duckdb_candidate="$APP_DIR/data/${duckdb_path#/workspace/data/}"
if [[ -L "$host_duckdb_candidate" ]]; then
  echo "Refusing symbolic DuckDB path: $host_duckdb_candidate" >&2
  exit 1
fi
host_duckdb_path="$(realpath -m -- "$host_duckdb_candidate")"
case "$host_duckdb_path" in
  "$APP_DIR"/data/*) ;;
  *) echo "Resolved DuckDB path escapes $APP_DIR/data: $host_duckdb_path" >&2; exit 1 ;;
esac
if [[ ! -f "$host_duckdb_path" ]]; then
  if [[ "${ALLOW_EMPTY_DUCKDB_INIT:-false}" != "true" ]]; then
    echo "DuckDB file does not exist: $host_duckdb_path" >&2
    echo "Set ALLOW_EMPTY_DUCKDB_INIT=true only for an intentional empty deployment." >&2
    exit 1
  fi
  echo "WARNING: deploying with an intentionally empty DuckDB path: $host_duckdb_path" >&2
else
  duckdb_size_kb="$(( ($(stat -c %s -- "$host_duckdb_path") + 1023) / 1024 ))"
  required_disk_kb="$((duckdb_size_kb + 20971520))"
  if [[ "$available_disk_kb" -lt "$required_disk_kb" ]]; then
    echo "Refusing to deploy without DuckDB size plus 20 GiB free disk" >&2
    exit 1
  fi
fi

if [[ "${REQUIRE_SCHEDULER_DISABLED:-false}" == "true" ]]; then
  scheduler_enabled="$(unquote_env_value "$(read_env_setting VULTRACK_SCHEDULER_ENABLED || true)")"
  if [[ "$scheduler_enabled" != "false" ]]; then
    echo "Migration requires VULTRACK_SCHEDULER_ENABLED=false" >&2
    exit 1
  fi
fi

admin_password="$(unquote_env_value "$(read_env_setting VULTRACK_ADMIN_PASSWORD || true)")"
if [[ -z "$admin_password" || "$admin_password" == "admin" || "$admin_password" == "change-me" ]]; then
  echo "VULTRACK_ADMIN_PASSWORD must be explicitly set to a non-default value" >&2
  exit 1
fi

for image_key in VULTRACK_API_IMAGE VULTRACK_FRONTEND_IMAGE; do
  image="$(unquote_env_value "$(read_env_setting "$image_key" || true)")"
  if [[ -z "$image" ]]; then
    echo "$image_key must pin an image built from a verified commit" >&2
    exit 1
  fi
  if [[ "$image" == *:latest && "${ALLOW_FLOATING_IMAGE_TAG:-false}" != "true" ]]; then
    echo "$image_key must not use the floating latest tag" >&2
    exit 1
  fi
done

git fetch origin "$BRANCH"
git merge --ff-only "origin/$BRANCH"

if command -v systemctl >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  sudo systemctl restart vultrack-docker-forward.service || true
fi

if [[ "${GHCR_PASSWORD_STDIN:-false}" == "true" ]]; then
  : "${GHCR_USERNAME:?GHCR_USERNAME is required when GHCR_PASSWORD_STDIN=true}"
  ghcr_token=""
  if ! IFS= read -r ghcr_token; then
    echo "GHCR password was not supplied on stdin" >&2
    exit 1
  fi
  docker_config_dir="$(mktemp -d "${TMPDIR:-/tmp}/vultrack-docker-config.XXXXXX")"
  chmod 700 "$docker_config_dir"
  export DOCKER_CONFIG="$docker_config_dir"
  cleanup_docker_config() {
    docker logout ghcr.io >/dev/null 2>&1 || true
    rm -rf -- "$docker_config_dir"
  }
  trap cleanup_docker_config EXIT
  printf '%s' "$ghcr_token" | docker login ghcr.io \
    --username "$GHCR_USERNAME" --password-stdin >/dev/null
  unset ghcr_token
fi

compose=(docker compose --env-file .env.production -f docker-compose.prod.yml)
"${compose[@]}" pull
"${compose[@]}" up -d --remove-orphans
"${compose[@]}" exec -T api \
  sh -lc '
    for attempt in $(seq 1 60); do
      node -e "fetch(\"http://127.0.0.1:8080/api/v1/system.ready\").then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))" &&
        exit 0
      sleep 2
    done
    echo "API readiness check timed out" >&2
    exit 1
  '
"${compose[@]}" ps
