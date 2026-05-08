#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_BASE_URL="${API_BASE_URL:-http://localhost:5099}"

cd "$ROOT_DIR"

docker run --rm \
  -v "$ROOT_DIR:/workspace" \
  -w /workspace \
  mcr.microsoft.com/dotnet/sdk:10.0 \
  dotnet build VulTrack.slnx

docker run --rm \
  -v "$ROOT_DIR:/workspace" \
  -w /workspace \
  mcr.microsoft.com/dotnet/sdk:10.0 \
  dotnet test VulTrack.slnx --no-build

npm test

API_BASE_URL="$API_BASE_URL" npm run test:api
