# CLAUDE.md

This file gives AI coding agents persistent project instructions for VulTrack. Keep it concise and update it when project conventions change.

## Project Overview

VulTrack is a vulnerability tracking and component intelligence platform. It ingests public vulnerability sources (NVD, GHSA, OSV, CVE List v5, distro trackers, CISA KEV, FIRST EPSS, package registries, exploit feeds), normalizes them into an embedded DuckDB file, links aliases such as CVE/GHSA/OSV, maps affected components across PURL/CPE/package names, and exposes RPC-style APIs for search, detail, and SBOM matching.

Current state: DuckDB-first single binary. One .NET 10 service `VulTrack.App` is the whole runtime; the embedded DuckDB file is the ONLY store. PostgreSQL and Redis are removed from the default architecture.

## Source Of Truth

- Current work queue and handoff state: `docs/agent-todo.md` (read this first).
- Current architecture: `docs/design/duckdb-first-architecture.md`.
- Completed migration history: `docs/proposals/affected-duckdb-migration.md`.
- Actual API routes: `src/VulTrack.App/Endpoints/` and `src/VulTrack.App/SbomEndpoints.cs`.
- Actual DuckDB schema ownership: `src/VulTrack.App/DuckDbEvidenceStore.Schema.cs`.
- Fetcher behavior: `plugins/fetchers/README.md` and `plugins/fetchers/sources/*.mjs`.

Legacy design docs: everything else under `docs/design/` describes the superseded PG-first design; consult only for historical intent, not for implementation truth.

## Architecture Rules

- Build a modular monolith as a single binary, not microservices.
- Main runtime is one `.NET 10 LTS` service: `VulTrack.App` (API, `DuckDbFirstScheduler`, normalizers, matching, detail snapshots).
- DuckDB (embedded file, default `data/duckdb/vultrack-evidence.duckdb`, overridable via `VULTRACK_DUCKDB_PATH`) is the ONLY store: catalog, evidence, affected components, exploits, threat scores, AI analyses, SBOM. No PostgreSQL server in the default stack.
- Host-specific DuckDB paths differ. cafemini's live database is `data/duckdb/vultrack.duckdb` (~13.5 GB) and its `vultrack-evidence.duckdb` is an empty placeholder; never remove that host's explicit `VULTRACK_DUCKDB_PATH` or the API will serve an empty catalog.
- Node.js fetchers (`plugins/fetchers/sources/*.mjs`, ~46 sources) run as child processes and write atomic gzipped NDJSON spool files to `data/spool/incoming/`; a file becomes visible to the scheduler only when promoted with the `.ready` suffix.
- FIRST EPSS uses a native gzip CSV snapshot pipeline, not the NDJSON spool.
- `DuckDbFirstScheduler` runs fetchers serially and ingests spool files directly into DuckDB; there is no staging database.
- Do not reintroduce PostgreSQL, OpenSearch, Temporal, RabbitMQ, NATS, or Kubernetes. Redis may be reintroduced later ONLY as an optional cache/queue if profiling demands it; never as the source of truth.
- Deployment is `docker-compose.yml` = api + frontend only.

## Repository Layout

```text
src/
  VulTrack.App/          # single project; endpoint groups live under Endpoints/ + SbomEndpoints.cs
plugins/
  fetchers/
    sources/*.mjs        # Node fetcher child processes
    lib/                 # shared fetcher helpers
tests/
  VulTrack.Tests/        # xUnit, DuckDB-focused
  node/                  # node:test for fetchers
  api/ integration/      # API smoke scripts
docs/
  design/                # legacy PG-first docs + duckdb-first-architecture.md
  proposals/
data/
  spool/incoming/        # fetcher output spool (.ndjson.partial -> .ndjson.ready)
  duckdb/                # embedded DuckDB file
  raw-objects/ mirrors/ logs/ vulnerability-details/
```

## API Rules

- Only use `GET` and `POST`.
- Do not add `PUT`, `PATCH`, or `DELETE` endpoints.
- Use RPC-style paths such as `/api/v1/vulnerability.search` and `/api/v1/system.status`.
- All JSON responses must use the `ApiResult` envelope:
  - success: `{ "ok": true, "data": ..., "requestId": "..." }`
  - failure: `{ "ok": false, "error": { "code": "...", "message": "...", "details": ... }, "requestId": "..." }`
- Raw payload access must require elevated permission.

## Database Rules

- DuckDB schema lives in code: `DuckDbEvidenceStore.Schema.cs` creates and owns all tables (`source_records`, `vulnerabilities`, `vulnerability_latest`, `vulnerability_identifiers`, `affected_facts`, `affected_components`, `severity_scores`, `evidence_references`, `weaknesses`, `cpe_entries`, `exploits`, `threat_scores`, `ai_vulnerability_analyses`, `sbom_uploads`, `sbom_components`, `sbom_matches`, ...). Do not add SQL migration files; evolve schema inside the store with `create table if not exists` / guarded alters.
- The catalog is rebuilt inside DuckDB from `source_records`; `vulnerability_latest` is a 5000-row materialized latest table, not a full listing.
- Preserve all source-level facts in `source_records`; do not overwrite one source with another.
- Store CVSS/vendor severity as rows in `severity_scores`; only projection fields go on `vulnerabilities`.
- Affected evidence lives in `affected_facts` (source facts) and `affected_components` (query projection). `affected_components` is rebuilt by table swap for bulk rebuilds and by delete-and-append for small batches.
- Spool files are transient: ingested ready files are removed after successful import.
- `db/init/*.sql` is the legacy PostgreSQL schema; do not extend it.

## Fetcher Rules

- Fetchers are plain Node.js ESM scripts under `plugins/fetchers/sources/`, executed as child processes by the .NET scheduler. There is no sandbox, no `plugin.json`, and no stdin/stdout plugin protocol.
- Each fetcher writes NDJSON to `data/spool/incoming/` and atomically promotes it via the `.ready` suffix; the scheduler only ingests `*.ndjson.ready` files.
- Shared helpers live in `plugins/fetchers/lib/`; use them instead of duplicating HTTP/retry/checkpoint logic.
- Fetchers must be idempotent, support incremental checkpoints, and respect `FETCHER_MAX_RECORDS` / source limits.
- Fetcher crashes or invalid output must not crash `VulTrack.App`; the scheduler isolates failures per source.
- Large payloads must go through spool files or mirrors, never through process stdio.

## Vulnerability Matching Rules

- Treat LLM/AI output as evidence, never as final authority. AI analyses are stored in `ai_vulnerability_analyses` and may raise/lower confidence but cannot alone confirm a match.
- Conflicting affected ranges must remain visible. For example, `<1.11`, `=1.11`, and LLM `<=1.11` must not be silently collapsed unless trusted rules or manual review approve it.
- SBOM/PURL matching reads the canonical `affected_components` projection in DuckDB, not raw source facts at query time.
- Version comparison must go through `EcosystemVersionComparer`/ecosystem-specific resolvers; never compare versions with plain string ordering.

## Coding Standards

- Prefer clear, boring code over clever abstractions.
- Single project `VulTrack.App`; keep endpoint mappings in `Endpoints/`/`SbomEndpoints.cs` and services as flat siblings.
- Use dependency injection for services and cancellation tokens on async I/O.
- Make fetch cycles and normalization idempotent and retry-safe.
- Use structured logging with stable event names.
- Avoid ad hoc JSON string manipulation; use typed DTOs or JSON DOM parsing.
- DuckDB is single-writer: serialize all writes through the scheduler/evidence store; never open concurrent write connections.
- Do not introduce network calls in unit tests.

## Testing Requirements

- xUnit tests in `tests/VulTrack.Tests` are DuckDB-focused (schema init, spool ingestion, catalog rebuild, matching).
- Fetcher tests use `node:test` in `tests/node` with fixtures for success, changed input, and invalid input.
- API smoke checks live in `tests/api` and `scripts/test-mvp.sh` and require a running API.
- Prefer focused tests near the changed module before running the full suite.
- If tests cannot be run, state why and what remains unverified.

## Essential Commands

```bash
docker compose up                                                   # api + frontend stack
npm test                                                            # node:test fetcher tests
npm run start:local                                                 # local dev start
docker run --rm -v $PWD:/src -w /src mcr.microsoft.com/dotnet/sdk:10.0 dotnet build VulTrack.slnx
docker run --rm -v $PWD:/src -w /src mcr.microsoft.com/dotnet/sdk:10.0 dotnet test VulTrack.slnx
```

dotnet SDK is not assumed to be installed on the host; always run dotnet build/test in the Docker SDK image. Do not invent successful command results. If a command is not available, say so.

## Security And Reliability

- Never commit secrets, API keys, `.env` files with real values, raw vulnerability payload dumps, database backups, or private SBOMs.
- Validate all external source data before writing DuckDB tables.
- Set a non-default `VULTRACK_ADMIN_PASSWORD` before exposing the UI beyond local development; admin auth protects status and fetcher administration.
- Preserve spool file hashes and source record identifiers for replay and forensic checks.
- The scheduler's serial fetch cycle and DuckDB single-writer discipline prevent concurrent-write corruption; do not bypass it.
- Fail closed on authorization and raw payload access.

## Known Gotchas

- DuckDB is single-writer per file; all writes must be serialized. Readers should share the store's managed connection.
- DuckDB 1.5.x ART index state can become persistently corrupted under incremental UPDATE/DELETE workloads. Explicit ART indexes are currently removed during schema initialization; do not re-enable them until the upstream issue is closed and production-scale churn benchmarks pass.
- `vulnerability_latest` is capped at 5000 rows; it is a "latest" materialization, not the full catalog.
- Spool promotion is atomic via the `.ready` suffix; never ingest files without the suffix and never rename partially written files.
- The catalog is rebuilt from `source_records` inside DuckDB; do not hand-edit projection tables.
- `vulnerability_latest` and detail snapshots are cached render data, not source truth.
- Legacy PG docs under `docs/design/` contradict the current architecture in places; trust `duckdb-first-architecture.md` and the code.
