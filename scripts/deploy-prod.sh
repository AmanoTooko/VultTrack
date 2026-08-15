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

git fetch origin "$BRANCH"
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Refusing to deploy over tracked local changes in $APP_DIR" >&2
  exit 1
fi
git merge --ff-only "origin/$BRANCH"

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

if command -v systemctl >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  sudo systemctl restart vultrack-docker-forward.service || true
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
