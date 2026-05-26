# VulTrack

VulTrack is a vulnerability intelligence pipeline for collecting raw advisories, normalizing multi-source vulnerability records, linking aliases, mapping affected components, and serving search APIs plus a lightweight web UI.

## Current Scope

- Pluggable Node.js fetchers for NVD, CVE List v5, OSV-family feeds, GHSA, distro advisories, registry package catalogs, EPSS, KEV, and related sources.
- PostgreSQL raw storage, staging tables, canonical vulnerability tables, component catalog, affected component facts, and query indexes.
- .NET API and normalization engine with source-scoped normalizers.
- Static frontend served either by the .NET app or by the `frontend` nginx container.
- Operational scripts for database backup/restore, smoke tests, fetcher runs, and full/parallel normalization.

## Quick Start

```bash
cp .env.example .env
docker compose up -d postgres adminer api frontend
```

Open:

- Frontend: <http://localhost:3000>
- API readiness: <http://localhost:5099/api/v1/system.ready>
- Adminer: <http://localhost:8081>

Run tests:

```bash
npm test
docker exec -w /workspace vultrack-api dotnet test tests/VulTrack.Tests/VulTrack.Tests.csproj
```

Run fetchers:

```bash
npm run fetch -- --source nvd-cve
npm run fetch:all:smoke
```

Run normalization:

```bash
API_BASE_URL=http://localhost:5099 LIMIT_PER_SOURCE=50 NORMALIZE_PARALLELISM=4 npm run normalize:parallel
```

Run matching benchmark:

```bash
API_BASE_URL=http://localhost:5099 npm run benchmark:matching
```

## Important Paths

- Fetchers: `plugins/fetchers/`
- Fetcher guide: `plugins/fetchers/README.md`
- Database schema: `db/init/001_schema.sql`
- API and normalizers: `src/VulTrack.App/`
- Frontend container: `frontend/`
- Design docs: `docs/design/`
- Performance report: `docs/reports/pgsql-normalization-performance.md`
- Matching benchmark: `docs/benchmark-matching.md`
- Oracle ARM deployment: `docs/deployment/oracle-arm.md`
- Current agent TODO/status: `docs/agent-todo.md`

## Configuration

Local secrets and machine-specific settings belong in `.env`. Do not commit `.env`, raw vulnerability payload dumps, database backups, or private SBOMs.

Common environment variables:

- `DATABASE_URL`
- `NVD_API_KEY`
- `GITHUB_TOKEN`
- `FETCHER_MAX_RECORDS`
- `LIMIT_PER_SOURCE`
- `NORMALIZE_PARALLELISM`
- `VULTRACK_SCHEDULER_ENABLED`
- `SCHEDULER_INTERVAL_SECONDS`
- `SCHEDULER_FETCH_TIMEOUT_SECONDS`
- `SCHEDULER_NORMALIZE_LIMIT`
- `SCHEDULER_SOURCE_CODES`
- `SCHEDULER_INCLUDE_INIT_SOURCES`

## License

Apache License 2.0. See `LICENSE`.
