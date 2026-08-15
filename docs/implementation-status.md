# Implementation Status

Date: 2026-08-15

## Current Runtime

VulTrack is a DuckDB-first modular monolith:

- one `.NET 10` process owns API, fetch scheduling, spool ingestion,
  normalization, catalog projection, AI evidence, snapshots, and SBOM matching;
- one embedded DuckDB file is the only database;
- Node.js fetchers are child processes that publish atomic
  `data/spool/incoming/*.ndjson.ready` artifacts;
- production Compose contains only `api` and `frontend`;
- PostgreSQL, Redis, Adminer, message brokers, and external search engines are
  not runtime dependencies.

The authoritative architecture is `docs/design/duckdb-first-architecture.md`.
Older PG-first documents are historical context only.

## Implemented Data Flow

1. A fetcher downloads or incrementally checks one upstream source.
2. It writes gzip NDJSON to a partial file and atomically publishes a ready
   artifact. FIRST EPSS uses its dedicated gzip CSV snapshot path.
3. `DuckDbFirstScheduler` serializes fetch and ingestion work.
4. `DuckDbEvidenceNormalizer` imports source facts into DuckDB.
5. The catalog, affected-component projection, latest materialization, and
   detail snapshot queue are updated from source truth.
6. API, AI evidence lookup, component search, and SBOM matching read DuckDB.

Automatic NVD/OSV baseline init is blocked unless explicitly enabled. Normal
scheduler cycles must remain incremental and must never select an init source by
surprise.

## Operational Safety

- `system.health` is a liveness probe.
- `system.ready` executes a real DuckDB query and returns 503 when the database
  is not queryable.
- A fatal DuckDB invalidation causes the scheduler to fail-stop instead of
  retrying writes indefinitely.
- Explicit ART indexes are disabled while the open DuckDB 1.5.x persisted-index
  corruption issue remains unresolved. Current tables have no PK/UNIQUE
  constraints, so this removes the ART mutation path.
- Production deploys pull CI-published `linux/amd64,linux/arm64` images; ARM
  hosts do not build locally.
- GitHub production deploy is opt-in through `VULTRACK_AUTO_DEPLOY=true`.

## API Surface

Primary endpoints include:

```text
GET  /api/v1/system.health
GET  /api/v1/system.ready
GET  /api/v1/system.status                 (admin)
GET  /api/v1/source.list
GET  /api/v1/admin.source.list             (admin)
POST /api/v1/admin.source.fetch            (admin)
POST /api/v1/admin.duckdbSpool.ingest      (admin)
GET  /api/v1/admin.duckdbEvidence.stats    (admin)
GET  /api/v1/admin.duckdbEvidence.coverage (admin)
POST /api/v1/vulnerability.search
GET  /api/v1/vulnerability.getByIdentifier
GET  /api/v1/vulnerability.detail
POST /api/v1/component.vulnerabilitySearch
POST /api/v1/sbom.upload
POST /api/v1/sbom.match
```

All endpoints use GET/POST and the `ApiResult` envelope.

## Verification Baseline

The 2026-08-15 main baseline passed:

- Node fetcher tests: 25/25;
- ESLint;
- .NET tests and formatting in GitHub Actions;
- multi-architecture API and frontend image publication.

The prior automatic deploy failed because the retired script still requested a
`postgres` Compose service. The deploy script and production Compose have since
been aligned to API/frontend-only image pulls; the next CI run must verify this
change before production migration.

## Known External Constraints

- GHSA is rate-limited without an authenticated GitHub token.
- Google OSV incremental mode requires a completed baseline cursor.
- CNNVD availability is source/network dependent and failures must remain
  isolated from other sources.
- Large baselines are intentionally excluded from CI and must run serially with
  disk, memory, swap, spool, and restart monitoring.
- Runtime databases, AI exports, SBOMs, secrets, backups, queues, and handoff
  files must remain outside Git.
