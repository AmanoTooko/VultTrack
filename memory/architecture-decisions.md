# Architecture Decisions

These decisions are invariants unless a new design explicitly replaces them with tests, migration,
rollback, and documentation.

## Modular Monolith

VulTrack is one .NET 10 runtime plus a static frontend. Do not introduce microservices, a message
broker, Kubernetes, PostgreSQL, Redis, or an external search engine without measured requirements
that cannot be met by the current design. Optional caches may never become source truth.

## DuckDB Is The Only Store

One embedded DuckDB file stores source records, canonical catalog, affected evidence, severity,
references, exploit/threat data, AI analyses, and SBOM state. Schema is owned in
`DuckDbEvidenceStore.Schema.cs`; do not add SQL migration files or extend legacy `db/init` PG
schemas.

DuckDB is single-writer. Every mutation must be serialized through the scheduler/evidence store.
Readers use managed read connections. Do not open ad hoc concurrent write connections.

## Source Evidence Is Durable; Projections Are Rebuildable

- Preserve records per `(source_code, source_record_id)`.
- Preserve conflicting source ranges, severity, references, and relationships.
- Build catalog and affected-component projections from source evidence.
- Repair logic in code and replay original source records.
- Never directly delete or rewrite catalog/source data to make an audit pass.

AI output is evidence, not authority. It cannot independently establish canonical identity or an
affected-version conclusion.

## Canonical Identity

- CVE is preferred when the record is itself a CVE, embeds one terminal CVE, or has exactly one
  direct CVE alias.
- Zero direct CVEs means the advisory remains independent.
- Multiple direct CVEs mean the advisory remains independent and those CVEs become relationship
  evidence.
- `upstream` and `related` never establish canonical identity.
- CVE-less GHSA and future BDSA advisories must remain independently visible.
- An identifier may have only one catalog owner, and its owner ID/key pair must come from the same
  canonical row.

## Evidence-only Projections

Content-free `MINI-*`, `CGA-*`, and `ECHO-*` records are package evidence, not useful top-level
advisories. One direct CVE alias owns the facts; otherwise exactly one CVE relationship may own
them. Ambiguous/unlinked records remain source evidence and are suppressed from catalog. Contentful
records remain independent. ECHO references are retained and do not alone make an empty advisory
contentful.

## Relationship Model

`source_record_relations` is relationship truth. Store outgoing `upstream` and `related` values,
deduplicate overlap, remove canonical self-relations, and expose reverse `downstream` evidence at
query time. Relationship references carry source code, source record ID, primary identifier, and
real source URL when available; never invent ordinary URL references or rewrite descriptions.

## Spool Contract

- Fetchers write `.partial` and atomically publish `.ready` only when complete.
- Only `.ready` files are ingestible.
- Large payloads travel through files/mirrors, not process stdio.
- A bad startup spool is quarantined and cannot terminate the API host.
- Duplicate source identities within a flush are folded with the last occurrence winning.
- Targeted replay must use `sourceMode=append`; source replacement is reserved for intentional full
  baselines.
- `forceNormalize=true` is restricted to controlled bulk replay and bypasses hash/version skipping.

## Bulk First, Incremental Second

Use official bulk data for baselines: OSV `all.zip`, GitHub Advisory Database, and NVD bulk feeds.
Use APIs and Git deltas for incremental scheduling. Validate boundary samples through the real
Normalizer before a full rebuild. Generate bulk replay on the destination host when that avoids a
multi-gigabyte database transfer.

## Query And API Contracts

- RPC-style GET/POST routes only; do not add PUT/PATCH/DELETE.
- Responses use `ApiResult`.
- Search is POST.
- Admin auth is session based.
- `system.health` is liveness; `system.ready` must execute a real DuckDB query.
- `vulnerability_latest` is a 5,000-row cache, not the full catalog.
- Version comparison must use ecosystem-specific comparers, never lexical string ordering.

## Reliability

- Explicit ART indexes remain disabled until the DuckDB 1.5.x persisted-index corruption issue is
  fixed upstream and a production-scale churn benchmark passes.
- Fatal storage invalidation must fail-stop writes.
- Keep one database and image rollback during release aging.
- Never delete active WAL/checkpoint/spool files based only on filename guesses.
