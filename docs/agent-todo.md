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
- 2026-05-09: `API_BASE_URL=http://localhost:5099 ./scripts/test-mvp.sh` passed.
- 2026-05-09: ran `POST /api/v1/raw.normalizePending` with `limitPerSource=1000`.
  Processed `nvd-cve=1000`, `osv-family=1000`, `ghsa-family=1000`, `pypi-advisory=1000`,
  `cve-list-v5=1000`, `threat-intel=1000`, `distro=1000`, `component-catalog=533`, all with `failed=0`.
- 2026-05-09: parser enrichment added shared source fact extraction for descriptions, severities, references, and weaknesses.
- 2026-05-09: after parser enrichment, ran `POST /api/v1/raw.normalizePending` with `limitPerSource=500`.
  Processed `nvd-cve=500`, `osv-family=500`, `ghsa-family=500`, `pypi-advisory=500`,
  `cve-list-v5=500`, `threat-intel=500`, `distro=500`, `component-catalog=250`, all with `failed=0`.
- 2026-05-09: added source-scoped normalization API and smoke script at `scripts/normalize-source-smoke.mjs`.
- 2026-05-09: ran source-scoped smoke with `nvd-cve`, `ghsa`, `ubuntu-osv`, `pypi-advisory`, `cisa-kev`, `nvd-cpe` at 500 each.
  Processed `nvd-cve=500`, `ghsa=500`, `ubuntu-osv=500`, `pypi-advisory=109`,
  `cisa-kev=500`, `nvd-cpe=500`, all with `failed=0`.
- 2026-05-09: added full pending normalization loop script at `scripts/run-full-normalization.mjs`.

Post-batch database snapshot:

- `source_raw_index`: `succeeded=25105`, `pending=2804600`.
- `vulnerabilities`: `26502`.
- `vulnerability_records`: `45700`.
- `vulnerability_descriptions`: `6936`.
- `vulnerability_severity_scores`: `1560`.
- `vulnerability_references`: `7365`.
- `vulnerability_weaknesses`: `754`.
- `vulnerability_affected_components`: `40173`.
- `cpe_entries`: `1386`.
- `registry_packages`: `20`.

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

Source-scoped smoke:

```bash
API_BASE_URL=http://localhost:5099 SOURCE_SMOKE_LIMIT=500 node scripts/normalize-source-smoke.mjs nvd-cve ghsa ubuntu-osv pypi-advisory cisa-kev nvd-cpe
```

Full normalization loop:

```bash
API_BASE_URL=http://localhost:5099 LIMIT_PER_SOURCE=1000 npm run normalize:run
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
- Extend ecosystem advisory normalizers and remaining fetcher-backed sources to populate those source fact tables, not only `vulnerability_records` and affected facts.
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
