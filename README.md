# VulTrack

VulTrack is a DuckDB-first vulnerability intelligence service. It fetches advisory data from
multiple upstreams, normalizes identifiers and affected ranges, preserves source evidence, and
serves a search/detail API with a web UI.

## Runtime

- `.NET 10` owns the API, scheduler, spool ingestion, Normalizer, catalog rebuilds, snapshots, and SBOM matching.
- Node.js fetchers publish atomic NDJSON spool files.
- One DuckDB file stores catalog, source evidence, affected facts, severity, references, exploits, threat scores, AI evidence, and SBOM data.
- Production Compose runs only `api` and `frontend`; PostgreSQL, Redis, and external search are not runtime dependencies.
- CI publishes `linux/amd64` and `linux/arm64` images. Hosts pull full commit-SHA tags and do not build locally.

The authoritative architecture is [docs/design/duckdb-first-architecture.md](docs/design/duckdb-first-architecture.md).

## Development

Requirements: Node.js 22+, Docker, and access to the .NET 10 SDK container.

```bash
cp .env.example .env
npm ci
npm run start:local
npm test
npm run lint
docker run --rm -v "$PWD:/src" -w /src -v vultrack-nuget:/root/.nuget/packages mcr.microsoft.com/dotnet/sdk:10.0 dotnet test VulTrack.slnx
```

Open `http://localhost:3000`; the API listens on `http://localhost:5099`. Do not run large DuckDB copies, full archive scans, or full Normalizer replays on the local external SSD. Use cafemini for those operations.

## Fetching And Normalization

```bash
npm run fetch -- --source nvd-cve
npm run fetch:all:smoke
npm run status
```

Fetchers write `*.ndjson.partial` and publish `*.ndjson.ready` only after a file is complete. The Normalizer imports ready files into DuckDB, rebuilds canonical catalog and affected-component projections, then removes consumed spool files.

Automatic baseline initialization is blocked by default. Run intentional OSV, NVD, or GHSA bulk baselines explicitly, validate the result, and only then enable incremental scheduling.

The production source set excludes CNNVD because its detail endpoint is unreliable:

```text
nvd-cve,osv,ghsa,google-osv,cisa-kev,first-epss,exploitdb,nuclei-templates,metasploit,poc-in-github,cargo-advisory
```

Set `GITHUB_TOKEN` in host-only environment files for reliable GHSA incremental paging. Never commit tokens, `.env` files, databases, backups, or raw payloads.

## Data Quality Audit

The read-only rules are in [scripts/audit-duckdb-quality.sql](scripts/audit-duckdb-quality.sql). Run them only while the API and scheduler are stopped:

```bash
docker run --rm --entrypoint duckdb -v "$PWD/data/duckdb:/data" -v "$PWD/scripts/audit-duckdb-quality.sql:/audit.sql:ro" duckdb/duckdb:1.5.3 /data/vultrack.duckdb -c '.read /audit.sql'
```

The audit checks canonical identifiers, alias ownership, ID/key pairing, duplicate relations, content gaps, projection versions, and AI foreign keys. It is read-only. Fix Normalizer rules and replay source data instead of patching catalog tables.

## Deployment

Production requires an explicit DuckDB path and full-SHA image pins in `.env.production`:

```dotenv
VULTRACK_DUCKDB_PATH=/workspace/data/duckdb/vultrack.duckdb
VULTRACK_SCHEDULER_ENABLED=true
DUCKDB_ALLOW_AUTOMATIC_INIT=false
DUCKDB_FETCH_SOURCES=nvd-cve,osv,ghsa,google-osv,cisa-kev,first-epss,exploitdb,nuclei-templates,metasploit,poc-in-github,cargo-advisory
VULTRACK_API_IMAGE=ghcr.io/amanotooko/vultrack-api:<full-40-char-sha>
VULTRACK_FRONTEND_IMAGE=ghcr.io/amanotooko/vultrack-frontend:<full-40-char-sha>
```

Deploy only an image whose GitHub Actions test and multi-architecture jobs are green:

```bash
cd /home/ubuntu/vultrack
git fetch origin main && git merge --ff-only origin/main
RELEASE_SHA="$(git rev-parse HEAD)" DUCKDB_PATH=/workspace/data/duckdb/vultrack.duckdb SCHEDULER_ENABLED=false ./scripts/configure-prod-release.sh
docker compose --env-file .env.production -f docker-compose.prod.yml pull
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --remove-orphans
```

Keep scheduler disabled during a database transfer or baseline import. After readiness and spool/checkpoint inspection, enable it explicitly:

```bash
sed -i 's/^VULTRACK_SCHEDULER_ENABLED=.*/VULTRACK_SCHEDULER_ENABLED=true/' .env.production
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --force-recreate api
```

Verify every deployment:

```bash
curl -fsS https://vul.qqvq.de/api/v1/system.health
curl -fsS https://vul.qqvq.de/api/v1/system.ready
docker inspect vultrack-api --format '{{.Config.Image}} restarts={{.RestartCount}} oom={{.State.OOMKilled}}'
docker logs --since 10m vultrack-api
```

Keep one known-good database rollback and the previous image tag until the new release has aged in. Do not delete WAL files or unknown spool files. The detailed ARM runbook is [docs/deployment/oracle-arm.md](docs/deployment/oracle-arm.md).

## Repository Map

- `src/VulTrack.App/`: .NET API, DuckDB store, scheduler, and Normalizer
- `src/VulTrack.App/wwwroot/`: frontend UI
- `plugins/fetchers/`: Node.js fetchers and source adapters
- `scripts/`: operational tools, bulk feeders, audits, and deployment helpers
- `tests/`: .NET and Node regression tests
- `docs/design/`: current architecture
- `docs/deployment/`: host runbooks

## License

Apache License 2.0. See [LICENSE](LICENSE).
