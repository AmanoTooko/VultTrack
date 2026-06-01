#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/home/ubuntu/vultrack}"
BRANCH="${BRANCH:-main}"

cd "$APP_DIR"

git fetch origin "$BRANCH"
git reset --hard "origin/$BRANCH"

if command -v systemctl >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  sudo systemctl restart vultrack-docker-forward.service || true
fi

docker compose --env-file .env.production -f docker-compose.prod.yml up -d postgres
docker compose --env-file .env.production -f docker-compose.prod.yml exec -T postgres \
  sh -lc '
    for attempt in $(seq 1 60); do
      pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1 && break
      sleep 2
    done
    pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"
    psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"
  ' \
  < db/init/001_schema.sql
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --build
docker compose --env-file .env.production -f docker-compose.prod.yml ps
