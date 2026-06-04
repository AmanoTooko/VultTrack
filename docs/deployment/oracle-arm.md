# Oracle ARM Deployment

Target: Oracle Cloud Ampere ARM, 4 vCPU / 24 GB RAM.

## Recommended Workflow

1. Develop and test locally.
2. Push to GitHub.
3. GitHub Actions runs Node/.NET tests and publishes multi-arch images to GHCR.
4. The server pulls the latest images and restarts Docker Compose.
5. VulTrack scheduler handles fetchers and normalization continuously.

## Server Setup

Install Docker and clone the repo:

```bash
git clone https://github.com/<owner>/<repo>.git /opt/vultrack
cd /opt/vultrack
cp .env.example .env
```

Set production values in `.env`:

```bash
POSTGRES_PASSWORD=<strong-password>
DATABASE_URL=postgres://vultrack:<strong-password>@postgres:5432/vultrack
VULTRACK_SCHEDULER_ENABLED=true
SCHEDULER_NORMALIZE_LIMIT=5000
SCHEDULER_FETCH_TIMEOUT_SECONDS=1800
SCHEDULER_INCLUDE_INIT_SOURCES=true
NVD_API_KEY=<optional>
GITHUB_TOKEN=<optional-but-recommended>
```

Start:

```bash
docker compose up -d postgres api frontend
```

The current `docker-compose.yml` is tuned for a 24 GB node: PostgreSQL uses `shared_buffers=6GB`, `effective_cache_size=18GB`, `maintenance_work_mem=2GB`, and a `2g` shared memory segment.

## Auto Update Options

Preferred simple option: run Watchtower on the server to pull GHCR images:

```bash
docker run -d --name watchtower --restart unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock \
  containrrr/watchtower vultrack-api vultrack-frontend --interval 300
```

Alternative: create a GitHub Actions deploy job over SSH that runs:

```bash
cd /opt/vultrack
git pull --ff-only
docker compose pull
docker compose up -d --remove-orphans
```

Use SSH deploy only after adding repository secrets for `DEPLOY_HOST`, `DEPLOY_USER`, and `DEPLOY_KEY`.

## Initial Data Flow

On a fresh database, `db/init/001_schema.sql` seeds sources and marks baseline sources with `config_json.runMode = "init"`. With scheduler enabled, daily/incremental sources run by `schedule_cron`. If `SCHEDULER_INCLUDE_INIT_SOURCES=true`, init-only sources run once until they have a successful sync run; leave it `false` locally to avoid surprise bulk downloads.

For a controlled first import:

```bash
docker compose exec api node /workspace/plugins/fetchers/run-all.mjs
docker compose exec api npm run normalize:parallel
```

For scheduler-driven init, set `SCHEDULER_NORMALIZE_PARALLELISM=4` first and tune upward only after watching PostgreSQL memory and I/O. The standalone `normalize:parallel` runner discovers pending sources from the database by default, so it avoids repeatedly calling idle sources during long imports.

For init mirrors, run specific sources during an off-peak window:

```bash
docker compose exec api node /workspace/plugins/fetchers/run-fetcher.mjs --source nvd-cve-init
docker compose exec api node /workspace/plugins/fetchers/run-fetcher.mjs --source osv-init
```

## Matching Benchmark

After normalizer or matcher changes:

```bash
API_BASE_URL=http://localhost:5099 npm run benchmark:matching
API_BASE_URL=http://localhost:5099 npm run benchmark:matching -- --sbom <sbom-id>
```

Keep `noRange`, `openLowerBound`, `unparseableRange`, and `actionableRangeRatio` in release notes when the matching engine changes.
