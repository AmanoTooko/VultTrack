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

`normalize:parallel` discovers pending sources from PostgreSQL by default. Set `NORMALIZE_SOURCES=source-a,source-b` to pin a source list, or `NORMALIZE_SOURCE_DISCOVERY=static` to use the built-in fallback list.

Run matching benchmark:

```bash
API_BASE_URL=http://localhost:5099 npm run benchmark:matching
```

Run an isolated fresh-init benchmark:

```bash
npm run benchmark:init -- --reset
npm run benchmark:init -- --reset --smoke
```

Run the experimental DuckDB-only evidence normalizer. This path reads parsed
staging tables and writes only `data/duckdb/vultrack-evidence.duckdb`; it does
not update PostgreSQL normalization status and does not affect SBOM matching.

```bash
API_BASE_URL=http://localhost:5099 npm run benchmark:duckdb -- --reset --sources osv,ubuntu-osv,android-osv,ghsa,nvd-cve --limit 5000 --batch-size 1000
API_BASE_URL=http://localhost:5099 npm run benchmark:duckdb -- --reset --source debian-security-tracker --limit 10
API_BASE_URL=http://localhost:5099 npm run benchmark:duckdb:compare -- --limit 250
```

Current local measurements:

- DuckDB-only current-effective rebuild from local PostgreSQL staging tables, `limit=5000000`, `batchSize=10000`: 12,288,317 affected facts, 1,102,239 severity scores, 4,012,827 references, 421,699 weaknesses, 1,286,676 CPE dictionary rows, 59,689 exploit rows, 337,476 threat score rows. Final DuckDB file size: 1,016,344,576 bytes. No network fetch is performed by this path.
- Full rebuild elapsed time observed on the local workstation was about 1,085s total across the main run and targeted consistency reruns. The main bottlenecks were NVD CVE offset paging (417s), SUSE CSAF parsing (225s), OSV (97s), Ubuntu OSV (63s), and NVD CPE dictionary streaming/COPY (106s).
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
