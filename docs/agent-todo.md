# VulTrack Agent TODO

Last updated: 2026-08-15 Asia/Shanghai.

**Read this file first.** It is the authoritative work queue and handoff state for AI agents.
Architecture truth is `docs/design/duckdb-first-architecture.md`; schema truth is
`src/VulTrack.App/DuckDbEvidenceStore.Schema.cs`. When those disagree with any other doc, they win.

## Handoff Rules

- Update this file in the same commit as the change it describes. A stale TODO is a bug.
- One logical change per commit. Large multi-thousand-line commits are not acceptable
  because they cannot be reverted safely.
- Never invent verification results. If a command was not run, say so.
- `dotnet` is not installed on the macOS host. Build and test only inside the Docker SDK
  image, or on the cafemini host (see Environments).

## Environments

| Host | Role | Arch | Notes |
| --- | --- | --- | --- |
| local macOS | development | arm64 | Code only. External SSD overheats under heavy write IO, so avoid large local ingest/rebuild jobs. |
| cafemini | primary data host + build host | amd64 | Live DuckDB is `data/duckdb/vultrack.duckdb` (~13.5 GB). Use for builds and long jobs. |
| ubuntu remote | production | arm64 | 4c/24g, ~200 GB disk, disk pressure from the legacy PG era. Pulls images from GHCR; do not build there. |

Critical path gotcha: cafemini sets `VULTRACK_DUCKDB_PATH=/workspace/data/duckdb/vultrack.duckdb`
explicitly. The in-code default is `vultrack-evidence.duckdb`, and on cafemini that file is a
13 MB empty database. Never drop the explicit env var on that host, or the API will silently
serve an empty catalog.

## Verified State (2026-08-15)

- cafemini `dotnet build VulTrack.slnx`: passed, 0 errors, 1 pre-existing warning (CS9113,
  unread `services` parameter in `DuckDbEvidenceNormalizer.cs:6`).
- cafemini `dotnet test VulTrack.slnx`: passed, 36/36, 17 s.
- cafemini `POST /api/v1/vulnerability.search` (`log4j`): HTTP 200 in 766 ms, returned real
  results with affected-component mappings. Data integrity confirmed.
- cafemini `GET /api/v1/system.ready`: HTTP 200, but the running container predates the probe
  fix and therefore still reports readiness without a real query. Not yet redeployed.
- Not verified: ubuntu remote cutover, local Docker DuckDB switch, AI-analysis backup restore.

## P0 — Highest Priority

- [x] Remove ART index recreation that corrupts DuckDB 1.5.x under UPDATE/DELETE churn, with a
      regression test.
- [x] Make `system.ready` run a real query instead of returning ready after init only, and
      return 503 when the store cannot serve.
- [x] Add a bounded manual fetch endpoint so ingest can be exercised without the scheduler.
- [x] Switch prod compose to pull GHCR images, make auto-deploy opt-in, and default the
      scheduler off so a first start never writes unexpectedly.
- [x] Drop the PostgreSQL step from `deploy-prod.sh` (root cause of the CI deploy failure
      `no such service: postgres`) and add memory/disk/branch/env preflight checks.
- [ ] Redeploy cafemini onto the current branch so the real readiness probe takes effect.
- [ ] Back up `ai_vulnerability_analyses` off-host and verify the restore before any
      destructive cleanup. This table is the only asset that cannot be re-downloaded.
- [ ] Cap DuckDB memory and threads in every compose file. Unbounded DuckDB takes ~80 % of host
      RAM; the container budget is far smaller, so this is an active OOM risk.
- [x] Serialize SBOM candidate matching with the single-writer lock. The path creates a temp
      table and uses COPY, so it intentionally uses a dedicated connection while holding
      `_writeLock` rather than borrowing a read-pool connection.
      Location: `DuckDbEvidenceStore.Sbom.cs`.
- [x] Accumulate changed keys across the whole scheduler cycle and rebuild the catalog once at
      the end. The normalizer returns deferred rebuild state and the scheduler coalesces it
      across all ready files and sources.
      Location: `DuckDbEvidenceNormalizer.Spool.cs`, `DuckDbFirstScheduler.cs`.

## P1 — Performance

- [ ] Replace the 640 k-row `LIKE` search (correlated subqueries, full sort, `OFFSET` paging)
      with FTS or a normalized token table, and move to keyset/search-after paging.
      Location: `DuckDbEvidenceStore.cs:1249-1276`.
- [ ] Parallelize the 8 serial detail queries and put them behind the existing cache. The
      DuckDB detail path currently bypasses both the 5-minute cache and snapshots.
      Location: `DuckDbEvidenceStore.cs:1712-1840`.
- [ ] Bound the unbounded static version-comparison cache, or use the already-present but idle
      `version_match_cache` table. Current behaviour is a long-lived memory leak.
      Location: `EcosystemVersionComparer.cs:8`.
- [ ] Push component version filtering into SQL. The service takes 20 k candidates and filters
      in .NET memory, so popular packages (log4j, openssl) silently under-report.
      Location: `ComponentVulnerabilitySearchService.cs:21-38`.
- [ ] Speed up EPSS ingest (350 k rows in ~112.9 s, ~3.1 k rows/s) by merging compact CSV
      directly instead of per-row `JsonNode.Parse`. The delta path is currently marked unsafe
      for production.
      Location: `DuckDbEvidenceNormalizer.Spool.cs:129-198`.
- [ ] Cut the ~5.1 s fixed per-source overhead: merge stats counting to once per cycle, and
      allow independent sources to overlap within the single-writer constraint.
      Location: `DuckDbFirstScheduler.cs:51-77`.

## P2 — Refactoring And Debt

- [ ] Decide the fate of the PostgreSQL path, then delete it or hide it behind an
      `IEvidenceStore` abstraction. Today nearly every endpoint carries an
      `if (duckDbPrimary) ... else Npgsql ...` branch, and the 13 PG normalizers,
      `SourceScheduler` (733 lines), and `db/init/*.sql` are dead code in the default
      deployment. This is the single largest structural drag on the codebase.
- [x] Split `DuckDbEvidenceStore` into Catalog / Evidence / Affected / AI / EPSS / SBOM /
      Status / Schema / DTO partial-class units. The shared connection and COPY discipline
      remains in the small root file.
- [x] Move endpoints out of `Program.cs` into per-area endpoint files. `Program.cs` now only
      wires services, middleware, endpoint groups, and cache warm-up.
- [ ] Collapse scattered `Environment.GetEnvironmentVariable` reads and `appsettings.json` into
      strongly typed Options.
- [x] Split the old single-file frontend into native ES modules under `wwwroot/js`. A bundler
      is not currently required because the static frontend has no compile-time dependency.
- [ ] Remove the pre-existing CS9113 warning by using or deleting the unread `services`
      parameter.

## P3 — Documentation

- [x] Align README and architecture docs with the DuckDB-first runtime and safe-start defaults.
- [x] Rewrite this TODO for the DuckDB-first architecture.
- [ ] Mark every superseded PG-first doc under `docs/design/` with an explicit obsolete banner,
      or move them to `docs/design/legacy/`. They still contradict the implementation and
      mislead new agents.
- [x] Document the ubuntu-remote cutover runbook, including the 30 GiB transfer budget,
      server-to-server/no-local-SSD rule, AI restore gate, and delete-after-import rule for
      rebuildable payloads.

## P4 — Product Gaps Versus OpenCVE / Dependency-Track

Ordered by how much each closes a real competitive gap.

- [ ] Alerting and subscriptions: new CVE matches an uploaded SBOM, then notify via
      webhook/email. This is the highest-value missing loop; both competitors have it and it is
      what makes continuous monitoring useful.
- [ ] VEX import/export and per-finding disposition state.
- [ ] API keys plus a minimal role model. Auth is currently a single hard-coded admin.
- [ ] Audit log. There is not even a table for it today.
- [ ] SPDX ingest alongside CycloneDX.
- [ ] Project/asset portfolio grouping for uploaded SBOMs.

Known ceiling: the DuckDB single-writer design is excellent for read-heavy analysis but blocks
multi-instance horizontal scaling and concurrent writes. Dependency-Track's strength is exactly
the write-back-heavy continuous monitoring path, so any alerting work must respect the
single-writer discipline rather than fight it.

## Test Commands

```bash
# Build and test (no dotnet SDK on the macOS host)
docker run --rm -v "$PWD:/src" -w /src mcr.microsoft.com/dotnet/sdk:10.0 dotnet build VulTrack.slnx
docker run --rm -v "$PWD:/src" -w /src mcr.microsoft.com/dotnet/sdk:10.0 dotnet test VulTrack.slnx

npm test                                              # node:test fetcher tests
API_BASE_URL=http://localhost:5099 npm run test:api    # needs a running API
API_BASE_URL=http://localhost:5099 ./scripts/test-mvp.sh
```

Search is `POST`, not `GET`; a `GET` returns 405 by design. Admin endpoints use session login,
not basic auth, so `curl -u` returns 401.

```bash
curl -sS -X POST http://localhost:5099/api/v1/vulnerability.search \
  -H 'content-type: application/json' \
  -d '{"query":"log4j","page":1,"pageSize":3}'
```
