#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
docker compose -p vultrack-benchmark -f docker-compose.benchmark.yml down -v --remove-orphans
docker compose -p vultrack-benchmark -f docker-compose.benchmark.yml up -d --build

for _ in $(seq 1 90); do
  if curl --silent --fail http://127.0.0.1:5199/api/v1/system.ready >/dev/null; then
    echo "Benchmark API ready: http://127.0.0.1:5199"
    exit 0
  fi
  sleep 2
done

echo "Benchmark API did not become ready" >&2
docker compose -p vultrack-benchmark -f docker-compose.benchmark.yml logs --tail=200
exit 1
