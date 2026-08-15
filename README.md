# VulTrack

VulTrack is a vulnerability intelligence pipeline for collecting raw advisories, normalizing multi-source vulnerability records, linking aliases, mapping affected components, and serving search APIs plus a lightweight web UI.

## Current Scope

- Pluggable Node.js fetchers for NVD, CVE List v5, OSV-family feeds, GHSA, distro advisories, registry package catalogs, EPSS, KEV, and related sources.
- Atomic NDJSON fetch spool with direct DuckDB catalog, evidence, affected-component, PoC, threat-score, AI, and SBOM storage.
- .NET API and DuckDB-first normalization engine; the embedded DuckDB file is the only store (PostgreSQL and Redis are removed from the default stack).
- Static frontend served either by the .NET app or by the `frontend` nginx container.
- Operational scripts for database backup/restore, smoke tests, fetcher runs, and full/parallel normalization.

## Quick Start

```bash
cp .env.example .env
npm run start:local
```

On macOS, double-click `VulTrack.command` from Finder for the same local start flow.

Open:

- Frontend: <http://localhost:3000>
- API readiness: <http://localhost:5099/api/v1/system.ready>

Run tests:

```bash
npm test
docker run --rm -v $PWD:/src -w /src mcr.microsoft.com/dotnet/sdk:10.0 dotnet test VulTrack.slnx
```

Run fetchers:

```bash
npm run fetch -- --source nvd-cve
npm run fetch:all:smoke
```

Monitor services, fetchers, pending normalization, storage mode, snapshots, and DuckDB file stats:

```bash
npm run status
```

Run a full baseline explicitly (automatic init is blocked by default):

```bash
npm run bootstrap:duckdb
```

Each completed fetch is promoted atomically to `data/spool/incoming/*.ready`. The
DuckDB-first scheduler imports ready files, rebuilds the canonical catalog and
affected-component projection, then removes the transient spool data. No
PostgreSQL server is started by the default Compose stack. On an empty database,
the scheduler refuses to start NVD/OSV init feeds while
`DUCKDB_ALLOW_AUTOMATIC_INIT=false`. Run intentional baselines through the
authenticated bootstrap command, verify their checkpoints, and only then enable
incremental scheduling.

Run matching benchmark:

```bash
API_BASE_URL=http://localhost:5099 npm run benchmark:matching
```

Historical PostgreSQL-to-DuckDB migration measurements live in
`docs/reports/pgsql-normalization-performance.md`; they are not instructions for
the current runtime.

## Important Paths

- Fetchers: `plugins/fetchers/`
- Fetcher guide: `plugins/fetchers/README.md`
- DuckDB schema: `src/VulTrack.App/DuckDbEvidenceStore.Schema.cs` (owned in code)
- Current architecture: `docs/design/duckdb-first-architecture.md`
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

- `VULTRACK_ADMIN_USERNAME`
- `VULTRACK_ADMIN_PASSWORD`
- `NVD_API_KEY`
- `GITHUB_TOKEN`
- `FETCHER_MAX_RECORDS`
- `EXPLOITDB_ARCHIVE_ARTIFACTS`
- `LIMIT_PER_SOURCE`
- `NORMALIZE_PARALLELISM`
- `BENCHMARK_FETCH_SOURCES`
- `BENCHMARK_REPORT_DIR`
- `VULTRACK_DUCKDB_ENABLED`
- `VULTRACK_DUCKDB_PATH`
- `VULTRACK_DUCKDB_MEMORY_LIMIT`
- `VULTRACK_DUCKDB_THREADS`
- `VULTRACK_SCHEDULER_ENABLED`
- `DUCKDB_ALLOW_AUTOMATIC_INIT`
- `DUCKDB_FETCH_INTERVAL_SECONDS`
- `DUCKDB_FETCH_SOURCES`
- `OSV_FETCH_MAX_RECORDS`
- `OSV_PENDING_MAX_BATCHES_PER_CYCLE`

`Status` and fetcher administration require an admin login. Set a non-default `VULTRACK_ADMIN_PASSWORD` before exposing the UI beyond local development.

## License

Apache License 2.0. See `LICENSE`.
