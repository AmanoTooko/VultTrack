# Oracle ARM Production Runbook

VulTrack production is DuckDB-first: one `api` container owns scheduling and writes for one DuckDB file, while `frontend` serves the UI. The public Oracle ARM host and cafemini run CI-published full-SHA images.

## Roles

- cafemini is the development, fetcher, and Normalizer validation host.
- Oracle ARM serves the public site and runs the validated incremental source set.
- CNNVD is disabled on both hosts because its detail endpoint is unreliable.
- Stop Oracle scheduling during database transfer or bulk replay; enable it only after readiness and a supervised cycle.

## Required Production Settings

```dotenv
VULTRACK_DUCKDB_PATH=/workspace/data/duckdb/vultrack.duckdb
VULTRACK_DUCKDB_MEMORY_LIMIT=3g
VULTRACK_DUCKDB_THREADS=4
VULTRACK_SPOOL_PATH=/workspace/data/spool
VULTRACK_SCHEDULER_ENABLED=true
DUCKDB_ALLOW_AUTOMATIC_INIT=false
DUCKDB_FETCH_INTERVAL_SECONDS=300
DUCKDB_FETCH_SOURCES=nvd-cve,osv,ghsa,google-osv,cisa-kev,first-epss,exploitdb,nuclei-templates,metasploit,poc-in-github,cargo-advisory
VULTRACK_API_IMAGE=ghcr.io/amanotooko/vultrack-api:<verified-full-sha>
VULTRACK_FRONTEND_IMAGE=ghcr.io/amanotooko/vultrack-frontend:<verified-full-sha>
```

Store `GITHUB_TOKEN`, NVD credentials, and admin credentials only in the host `.env.production`. Never commit or print them.

## Deploy

Deploy only a full SHA whose GitHub Actions test and multi-architecture Docker jobs are green:

```bash
cd /home/ubuntu/vultrack
git fetch origin main && git merge --ff-only origin/main
RELEASE_SHA="$(git rev-parse HEAD)" DUCKDB_PATH=/workspace/data/duckdb/vultrack.duckdb SCHEDULER_ENABLED=false ./scripts/configure-prod-release.sh
docker compose --env-file .env.production -f docker-compose.prod.yml pull
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --remove-orphans
```

After readiness and spool/checkpoint review, enable scheduler explicitly:

```bash
sed -i 's/^VULTRACK_SCHEDULER_ENABLED=.*/VULTRACK_SCHEDULER_ENABLED=true/' .env.production
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --force-recreate api
```

## Database Transfer

1. Stop the destination API and scheduler.
2. Rename the destination DB to a timestamped rollback name.
3. Transfer a cafemini snapshot directly to Oracle staging, not through local Mac storage.
4. Compare source/destination byte count and SHA-256.
5. Atomically move staging to `data/duckdb/vultrack.duckdb`.
6. Start the pinned API with scheduler disabled.
7. Verify health, readiness, search, detail, AI, relationships, and source counts.
8. Enable scheduler and observe one complete cycle.

Keep one accepted rollback and the prior image until the new state has aged in. Do not delete the active DB, WAL, checkpoints, or ready spool files.

## Monitoring

```bash
curl -fsS https://vul.qqvq.de/api/v1/system.health
curl -fsS https://vul.qqvq.de/api/v1/system.ready
docker inspect vultrack-api --format '{{.Config.Image}} status={{.State.Status}} restarts={{.RestartCount}} oom={{.State.OOMKilled}}'
docker logs --since 10m vultrack-api | grep -E 'fetcher|catalog rebuild|failed|OOM|invalidated'
```

Expected sources are `nvd-cve`, `osv`, `ghsa`, `google-osv`, `cisa-kev`, `first-epss`, `exploitdb`, `nuclei-templates`, `metasploit`, `poc-in-github`, and `cargo-advisory`. CNNVD must not be configured.

## Quality Audit

Run [scripts/audit-duckdb-quality.sql](../../scripts/audit-duckdb-quality.sql) only while `api` is stopped:

```bash
docker run --rm --entrypoint duckdb -v "$PWD/data/duckdb:/data" -v "$PWD/scripts/audit-duckdb-quality.sql:/audit.sql:ro" duckdb/duckdb:1.5.3 /data/vultrack.duckdb -c '.read /audit.sql'
```

The audit is read-only. It checks canonical IDs, alias ownership, ID/key pairing, duplicate relations, projection leaks, content gaps, and AI foreign keys. Correct data through Normalizer code and source replay, never direct catalog edits.

## Cleanup

After acceptance, remove only known obsolete staging files, failed spool files with advanced checkpoints, development copies, shadow-work directories, and unneeded tagged images. Keep the active DB/WAL, one rollback, source mirrors, checkpoints, ready spool files, and the running verified image. Do not run global Docker pruning.

## Current Findings

The latest audit has no duplicate canonical keys, alias owner conflicts, ID/key mismatches, self-relations, AI orphan IDs, or duplicate AI evidence. Legacy replay work remains for approximately 8,043 `ECHO-*` empty catalog projections and 170 duplicate OSV `related` source relations. Track and fix these through a Normalizer replay, not SQL cleanup.
