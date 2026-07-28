# VulTrack

VulTrack is a vulnerability intelligence pipeline for collecting raw advisories, normalizing multi-source vulnerability records, linking aliases, mapping affected components, and serving search APIs plus a lightweight web UI.

## Current Scope

- Pluggable Node.js fetchers for NVD, CVE List v5, OSV-family feeds, GHSA, distro advisories, registry package catalogs, EPSS, KEV, and related sources.
- Atomic NDJSON fetch spool with direct DuckDB catalog, evidence, affected-component, PoC, threat-score, AI, and SBOM storage.
- .NET API and DuckDB-first normalization engine; PostgreSQL remains available only through legacy deployment manifests.
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
docker exec -w /workspace vultrack-api dotnet test tests/VulTrack.Tests/VulTrack.Tests.csproj
```

Run fetchers:

```bash
npm run fetch -- --source nvd-cve
npm run fetch:all:smoke
```

Monitor services, fetchers, pending normalization, storage mode, snapshots, and largest PostgreSQL tables:

```bash
npm run status
```

Run a full baseline explicitly (normal scheduled runs are incremental):

```bash
npm run bootstrap:duckdb
```

Each completed fetch is promoted atomically to `data/spool/incoming/*.ready`. The
DuckDB-first scheduler imports ready files, rebuilds the canonical catalog and
affected-component projection, then removes the transient spool data. No
PostgreSQL server is started by the default Compose stack. On an empty database,
the scheduler automatically runs or resumes the NVD and OSV baselines; after
their checkpoints complete, subsequent cycles use only incremental fetchers.

Run matching benchmark:

```bash
API_BASE_URL=http://localhost:5099 npm run benchmark:matching
```

Run an isolated fresh-init benchmark:

```bash
npm run benchmark:init -- --reset
npm run benchmark:init -- --reset --smoke
```

Migration measurements:

- DuckDB-only current-effective rebuild from local PostgreSQL staging tables, `limit=5000000`, `batchSize=10000`: 12,288,317 affected facts, 1,102,239 severity scores, 4,012,827 references, 421,699 weaknesses, 1,286,676 CPE dictionary rows, 59,689 exploit rows, 337,476 threat score rows. Final DuckDB file size: 1,016,344,576 bytes. No network fetch is performed by this path.
- Android OSV direct-spool import: 3,403 records in about 1.1s on the workstation and 7.2s on the 8GB test host, versus about 45.9s through the previous PostgreSQL-first path.
- DuckDB vs PostgreSQL detail JSON aggregation, limit 250, sample set `CVE-2021-44228,CVE-2023-4863,CVE-2017-5753,CGA-V7V4-9R6P-X7FC`: DuckDB averaged 45.7ms for affected JSON aggregation vs PostgreSQL 217.9ms, 20.5ms for references vs PostgreSQL 32.5ms, and 9.4ms for severities vs PostgreSQL 13.7ms. Severity sample Jaccard was 0.917 after key/severity normalization fixes; affected still differs because DuckDB stores current-effective/deduplicated facts while PostgreSQL contains duplicate and historical projections.
- Debian legacy staging compatibility, limit 10: 13,593 CVE evidence records -> 60,086 affected facts, 1.0 MB DuckDB file, 1.4s end-to-end.
- Detail snapshot rebuild, limit 5000, concurrency 8, gzip level 6: 112.45s, 256 shards touched.
- Current detail snapshot sample: 6,229 entries, 34.6 MB gzip, 393 MB uncompressed JSON. At 417k vulnerabilities this projects to roughly 2.3 GB gzip and 26 GB uncompressed JSON serialization work.

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
- `VULTRACK_SCHEDULER_ENABLED`
- `SCHEDULER_INTERVAL_SECONDS`
- `SCHEDULER_FETCH_TIMEOUT_SECONDS`
- `SCHEDULER_NORMALIZE_LIMIT`
- `SCHEDULER_NORMALIZE_PARALLELISM`
- `SCHEDULER_SOURCE_CODES`
- `SCHEDULER_INCLUDE_INIT_SOURCES`

`Status` and fetcher administration require an admin login. Set a non-default `VULTRACK_ADMIN_PASSWORD` before exposing the UI beyond local development.

## License

Apache License 2.0. See `LICENSE`.
