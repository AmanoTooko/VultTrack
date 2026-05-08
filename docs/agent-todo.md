# VulTrack Agent TODO

Last updated: 2026-05-09 Asia/Shanghai.

## Current MVP State

VulTrack has a working fetch -> staging -> normalize -> query path.

Implemented ingestion/fetcher pieces:

- Fetcher plugins under `plugins/fetchers/sources`.
- Init fetchers are separated from daily/incremental fetchers for large file or mirror-backed sources.
- `plugins/fetchers/README.md` documents how to add and debug fetchers.
- `run-all` skips init fetchers by default.

Implemented normalizer/parser pieces:

- Canonical vulnerability identity uses `vulnerabilities.id` plus immutable `vuln:<uuid>` canonical keys.
- Source aliases are indexed in `vulnerability_identifier_index`, grouped in `vulnerability_identifier_groups`, and linked in `vulnerability_identifier_edges`.
- NVD CVE is the preferred display identifier when available.
- Multi-source facts stay in source-specific tables and records.
- Affected component facts flow through `IAffectedComponentHook` into `vulnerability_affected_components`.
- Component catalog records from NVD CPE and package registries are normalized into `cpe_entries`, `registry_packages`, `components`, and `component_identity_index`.

Implemented frontend:

- Static UI served by `src/VulTrack.App/wwwroot`.
- Supports vulnerability search, component search, component vulnerability matching, and multi-source vulnerability detail display.

## Implemented API

System:

- `GET /api/v1/system.health`
- `GET /api/v1/system.ready`
- `GET /api/v1/system.status`

Sources and processing:

- `GET /api/v1/source.list`
- `POST /api/v1/nvd.processPending`
- `POST /api/v1/raw.normalizePending`

Vulnerability query:

- `POST /api/v1/vulnerability.search`
- `GET /api/v1/vulnerability.getByIdentifier?identifier=...`
- `GET /api/v1/vulnerability.get?id=...`
- `GET /api/v1/vulnerability.detail?id=...`

Component query:

- `POST /api/v1/component.search`
- `POST /api/v1/component.vulnerabilitySearch`

Frontend:

- `GET /index.html`
- `GET /app.js`
- `GET /styles.css`

## Repeatable Test Commands

Run the consolidated MVP test script while the API is available at `http://localhost:5099`:

```bash
API_BASE_URL=http://localhost:5099 ./scripts/test-mvp.sh
```

Individual checks:

```bash
docker run --rm -v "$PWD:/workspace" -w /workspace mcr.microsoft.com/dotnet/sdk:10.0 dotnet build VulTrack.slnx
docker run --rm -v "$PWD:/workspace" -w /workspace mcr.microsoft.com/dotnet/sdk:10.0 dotnet test VulTrack.slnx --no-build
npm test
API_BASE_URL=http://localhost:5099 npm run test:api
```

Recent verification records:

- 2026-05-09: `dotnet build VulTrack.slnx` passed.
- 2026-05-09: `dotnet test VulTrack.slnx --no-build` passed.
- 2026-05-09: `npm test` passed.
- 2026-05-09: `API_BASE_URL=http://localhost:5099 npm run test:api` passed, 6 API tests.

## Current Runtime Notes

Local services used during development:

- Postgres: `localhost:5432`, database `vultrack`, user `vultrack`.
- API: `http://localhost:5099`.
- Adminer: `http://localhost:8081`.

Useful normalization smoke command:

```bash
curl -sS -X POST http://localhost:5099/api/v1/raw.normalizePending \
  -H 'content-type: application/json' \
  -d '{"limitPerSource":100}'
```

Useful status checks:

```bash
curl -sS http://localhost:5099/api/v1/system.status
docker exec vultrack-postgres psql -U vultrack -d vultrack -c "select normalize_status, count(*) from source_raw_index group by 1 order by 1;"
docker exec vultrack-postgres psql -U vultrack -d vultrack -c "select s.code, count(*) from source_raw_index r join sources s on s.id = r.source_id where r.normalize_status <> 'succeeded' group by s.code order by count(*) desc limit 25;"
```

## Next Development Queue

Parser completeness:

- Add shared helper methods in `NormalizerBase` for descriptions, severity scores, references, weaknesses, and source properties.
- Extend OSV, GHSA, PyPI, distro, and ecosystem advisory normalizers to populate those source fact tables, not only `vulnerability_records` and affected facts.
- Add idempotency constraints or cleanup for duplicated `vulnerability_affected_facts`, `vulnerability_descriptions`, `vulnerability_references`, and severity rows before large repeated normalization runs.
- Add a backfill command for old canonical rows that still use legacy CVE/GHSA canonical keys.

Query and matching:

- Improve `ComponentVulnerabilitySearchService` with ecosystem-specific version range resolvers.
- Add CPE-to-package mapping hooks for NVD CPE facts.
- Add query explain output so the frontend can show why a component matched a vulnerability.

Scheduler and queue:

- Keep Postgres as the authoritative queue for MVP.
- Add `FOR UPDATE SKIP LOCKED` claiming for concurrent normalizer workers.
- Introduce Redis later only as an optional short-lived queue/cache layer, not as the source of truth.

Frontend:

- Add pagination and source filters.
- Add record diff views for multi-source descriptions and affected ranges.
- Add richer component detail pages backed by `components` and `component_identity_index`.

Operations:

- Add a repeatable full normalization script with resumable batch size and progress logging.
- Add database backup/restore scripts around full update and full normalization jobs.
- Add integration fixtures so API tests can run against a small seeded database, not only the local large dev DB.
