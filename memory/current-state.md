# Current State

Last verified: 2026-08-16 Asia/Shanghai.

## Release

- Accepted release: `f4d6c2b486107e1d78ab373ab61ffb6d5566c2db`.
- GitHub Actions run `31942654570` passed tests, formatting, lint, Node tests, and multi-architecture
  API/frontend image publication.
- Both production environments run the full-SHA API and frontend images with zero restart count
  and no OOM event at acceptance.
- Public production health and readiness return HTTP 200.

## Runtime

- VulTrack is a DuckDB-first modular monolith: one .NET 10 API/scheduler/Normalizer process, one
  frontend container, and one mounted DuckDB file.
- Both operational hosts have the scheduler enabled.
- Production source set:

  ```text
  nvd-cve,osv,ghsa,google-osv,cisa-kev,first-epss,exploitdb,nuclei-templates,metasploit,poc-in-github,cargo-advisory
  ```

- CNNVD is disabled on both hosts. Its fetcher is retained only for controlled manual use.
- GHSA incremental fetching is authenticated through host-only `GITHUB_TOKEN` settings.
- A complete supervised scheduler cycle returned success for all configured sources on both hosts.

## Data Acceptance

The current databases were rebuilt and repaired through official bulk source records and the real
Normalizer. No catalog/source tables were patched directly.

- Empty `MINI-*`, `CGA-*`, and `ECHO-*` catalog projections: 0.
- Duplicate primary identifier groups: 0.
- Duplicate identifier owner groups: 0.
- Identifier ID/key mismatches: 0.
- Canonical self-relations: 0.
- Duplicate source relation rows: 0.
- Blank relation identifiers: 0.
- AI analyses: 63,244.
- AI orphan vulnerability IDs: 0.
- Duplicate AI evidence rows: 0.
- Twenty-one contentful ECHO advisories remain independently visible by design.

The original database was roughly 13.5 GB and the accepted active files are roughly 11.0 GB. The
difference is expected DuckDB compaction after obsolete projections and old pages were removed and
checkpointed. Logical evidence counts and integrity audits, not physical file bytes, are the
acceptance criteria.

## Accepted Behaviors

- `ECHO-0019-8EBD-2524` resolves to canonical `CVE-2026-53182`, HIGH/CVSS 7.8, rather than an empty
  ECHO catalog row.
- CVSS descending search returns score 10.0 records first; ascending sort is numeric and places the
  lowest scores first.
- CVE-less GHSA records remain independent.
- Advisories with multiple direct CVEs remain independent and expose those CVEs as relationships.
- Advisory detail exposes outgoing upstream/related references; CVE detail exposes reverse
  downstream references with source attribution.
- Large relationship groups are bounded in the UI and expandable.
- Light and dark themes are supported and persisted.

## Bulk Baselines And Replay

- OSV uses the official `all.zip` bulk archive.
- GHSA baseline uses the GitHub Advisory Database `github-reviewed` records.
- NVD should use its official bulk feeds for baselines.
- Targeted official-bulk replay uses `scripts/feed-osv-bulk-prefix.mjs` in append mode and emits
  `forceNormalize=true` so unchanged hashes can be deliberately recomputed.
- The latest repair replay normalized 984 source identities implicated in duplicate relations and
  all 8,045 ECHO records. Both hosts independently generated and ingested their replay from an
  official OSV archive; the multi-gigabyte database was not copied between hosts.

## Retention

- Keep the active database, WAL/checkpoints, AI backup, current source checkpoints, and one known
  database rollback.
- Keep the current release image and one known-good rollback image until the release has aged in.
- Official bulk mirrors may be retained when they save future baseline/replay bandwidth.
- Consumed replay directories, old build checkouts, stale failed spool, and temporary audit files
  were removed at acceptance.

## Known Operational Follow-up

- Rotate any GitHub token that has appeared in terminal or agent logs, then update only ignored
  host environment files and recreate the API containers.
- Delete rollback databases only after an explicit retention decision and a stable observation
  period. This is maintenance, not an active data-quality blocker.
