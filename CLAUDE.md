# CLAUDE.md

This file gives AI coding agents persistent project instructions for VulTrack. Keep it concise and update it when project conventions change.

## Project Overview

VulTrack is a vulnerability tracking and component intelligence platform inspired by Black Duck and Dependency-Track. It ingests public vulnerability sources such as NVD, GHSA, OSV, CVE List v5, distro trackers, CISA KEV, FIRST EPSS, and package registries; normalizes them into PostgreSQL; links aliases such as CVE/GHSA/OSV; maps affected components across PURL, CPE, package names, and repositories; and exposes RPC-style APIs for search, detail, and matching.

Current state: design-first project. The implementation should follow the modular documents under `docs/design/`.

## Source Of Truth

- Start with `docs/design/README.md` for document order.
- Use `docs/design/architecture.md` for workflow and business data flow.
- Use `docs/design/database.md` for PostgreSQL schema, initialization, and indexes.
- Use `docs/design/contracts/api-rpc.md` for API definitions.
- Use `docs/design/testing/test-plan.md` for smoke, module, integration, and E2E tests.
- Plugin-specific behavior lives under `docs/design/plugins/*/design.md`.
- The older high-level design remains in `docs/vultrack-system-design-v2.md`; prefer `docs/design/` when documents disagree.

## Architecture Rules

- Build a modular monolith first, not microservices.
- Main runtime is one `.NET 10 LTS` service named `vultrack-app`.
- `vultrack-app` owns API, scheduler, background worker, plugin orchestration, normalization, matching, and query aggregation.
- PostgreSQL is the primary fact store and initial search engine.
- Redis is only for queueing, distributed locks, short-term cache, and task state.
- Raw payloads must not be stored directly in business tables; store compressed raw payloads in filesystem/S3-compatible object storage and keep metadata in PostgreSQL.
- Node.js/TypeScript plugins are executed as sandboxed child processes controlled by the .NET core.
- Do not introduce OpenSearch, Temporal, RabbitMQ, NATS, Kubernetes, or extra services in MVP unless the design docs are updated first.

## Repository Layout

Expected implementation layout:

```text
src/
  VulTrack.Api/
  VulTrack.Core/
  VulTrack.Infrastructure/
  VulTrack.Worker/
plugins/
  nvd/
  ghsa/
  osv/
  cve-list/
  threat-intel/
tests/
  VulTrack.UnitTests/
  VulTrack.IntegrationTests/
  PluginFixtures/
docs/
  design/
```

If the actual layout differs after implementation begins, update this section immediately.

## API Rules

- Only use `GET` and `POST`.
- Do not add `PUT`, `PATCH`, or `DELETE` endpoints.
- Use RPC-style paths such as `/api/v1/vulnerability.search` and `/api/v1/source.syncStart`.
- All JSON responses must use the standard envelope:
  - success: `{ "ok": true, "data": ..., "requestId": "..." }`
  - failure: `{ "ok": false, "error": { "code": "...", "message": "...", "details": ... }, "requestId": "..." }`
- Match endpoint names and DTO intent in `docs/design/contracts/api-rpc.md`.
- Raw payload access must require elevated permission and write an audit event.

## Database Rules

- Enable PostgreSQL extensions: `pg_trgm`, `unaccent`, `btree_gin`, `pgcrypto`.
- Keep `vulnerabilities` as a canonical query projection, not a catch-all source field table.
- Store source-specific fields in staging tables, `vulnerability_records.source_specific`, typed properties, or detail blocks.
- Preserve all source-level facts; do not overwrite one source with another.
- Store CVSS/vendor severity as many rows in `vulnerability_severity_scores`; only projection fields go on `vulnerabilities`.
- Store affected component evidence in:
  - `vulnerability_affected_facts`
  - `vulnerability_affected_components`
  - `vulnerability_affected_evidence`
- Identifier lookup must be precomputed through `vulnerability_identifier_index`; do not perform recursive graph traversal during normal queries.
- Schema migrations must be forward-only and repeatable against an empty database.

## Plugin Rules

- Every plugin must have `plugin.json`, fixtures, and protocol tests.
- Plugin types are `source-fetcher`, `source-parser`, `source-detail-renderer`, `version-resolver`, `component-matcher`, and `llm-matcher`.
- Plugin stdin/stdout protocol must follow `docs/design/modules/plugin-runtime.md`.
- Plugins must output structured JSON only.
- Detail renderer plugins must never output HTML or JavaScript; they return safe JSON blocks rendered by trusted frontend components.
- Plugin crashes, invalid JSON, timeouts, or oversized stdout must not crash `vultrack-app`.
- Large payloads should be passed by object URI, not through stdin.

## Vulnerability Matching Rules

- Treat LLM output as evidence, never as final authority.
- LLM evidence may raise/lower confidence but cannot alone set `resolution_status = confirmed`.
- Conflicting affected ranges must remain visible. For example, `<1.11`, `=1.11`, and LLM `<=1.11` must not be silently collapsed unless trusted rules or manual review approve it.
- SBOM/PURL matching should read canonical affected sets, not scan every source fact at query time.
- Version comparison must go through ecosystem-specific resolvers; do not compare versions with plain string ordering.

## Coding Standards

- Prefer clear, boring code over clever abstractions.
- Keep module boundaries aligned with `docs/design/modules/`.
- Use dependency injection for module services.
- Use cancellation tokens on async I/O.
- Make background tasks idempotent and retry-safe.
- Use structured logging with stable event names from design docs.
- Avoid ad hoc JSON string manipulation; use typed DTOs or JSON DOM parsing.
- Do not add columns to `vulnerabilities` for source-specific fields without updating the design docs.
- Do not introduce network calls in unit tests.

## Testing Requirements

- Each module needs smoke tests and module tests as defined in `docs/design/testing/test-plan.md`.
- Each plugin needs fixture tests for success, changed input, invalid input, and protocol errors.
- Integration tests must cover:
  - NVD + GHSA alias merge.
  - affected component conflict with source facts and LLM evidence.
  - PURL match using version resolver cache.
  - detail blocks generated from source-specific data.
  - raw payload permission enforcement.
- Prefer focused tests near the changed module before running the full suite.
- If tests cannot be run, state why and what remains unverified.

## Essential Commands

The project is currently design-only. Once implementation begins, keep these commands accurate:

```text
dotnet build
dotnet test
dotnet ef database update
npm test --workspaces
docker compose up
```

Do not invent successful command results. If a command is not yet available, say so.

## Security And Reliability

- Never commit secrets, API keys, `.env` files with real values, raw vulnerability payload dumps, or private SBOMs.
- Validate all external source data before writing normalized tables.
- Audit manual merges/splits, mapping approvals/rejections, raw payload downloads, and source configuration changes.
- Use Redis locks to prevent concurrent sync of the same source.
- Preserve raw object hashes and source record hashes for replay and forensic checks.
- Fail closed on authorization and raw payload access.

## Development Workflow

- Read the relevant design file before implementing a module.
- If implementation needs to diverge from design, update the design document in the same change.
- Keep changes small and module-scoped.
- Add or update tests with behavior changes.
- Do not rewrite unrelated docs or refactor unrelated modules.
- Prefer explicit TODOs only when paired with an owner-facing explanation or follow-up issue.

## Known Gotchas

- `vulnerabilities` is a projection table; do not use it as the only source of truth.
- Identifier relations are precomputed; avoid runtime recursive alias graph queries.
- Detail blocks are cached render data, not raw source data.
- LLM matcher is optional and must be disableable by configuration.
- MinIO is optional; filesystem raw object storage is valid for MVP.
- API style is intentionally RPC over GET/POST, not REST.

