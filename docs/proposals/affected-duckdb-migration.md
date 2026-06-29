# Affected Data DuckDB Migration Proposal

## Summary

The affected-component data path should move from PostgreSQL to DuckDB. PostgreSQL is still useful for vulnerability metadata, source run state, raw object references, and small queues, but the affected facts/components workload is append-heavy, mostly read-only after normalization, and dominated by analytical candidate scans. DuckDB is a better fit for this shape.

## Current Findings

- `vulnerability_affected_facts` is about 29M rows and 12GB in PostgreSQL.
- `vulnerability_affected_components` is about 10M rows and 7.5GB in PostgreSQL.
- The affected PostgreSQL indexes alone consume several GB and create high write amplification.
- The existing DuckDB evidence file is much smaller while already holding affected facts, affected components, severity scores, references, and weaknesses.
- SBOM and component candidate lookup already have DuckDB read paths.

## Target Shape

1. Store canonical affected facts in DuckDB.
2. Store the affected component projection in DuckDB.
3. Keep only lightweight affected summaries on `vulnerabilities` in PostgreSQL.
4. Read detail snapshots, SBOM candidate matching, component search, and AI evidence from DuckDB or static JSON snapshots.
5. Use PostgreSQL only for small queues and metadata around affected updates.

## Required Engineering Changes

- Replace the current DuckDB affected-component incremental update path with in-place delete-and-append for small vulnerability batches.
- Keep full table swap only for explicit bulk rebuilds.
- Add a single writer queue/lock for DuckDB affected writes.
- Extend DuckDB affected component rows with fix metadata currently present only in PostgreSQL, such as introduced/fixed/last affected and fixed versions.
- Move normalizer affected fact writes to DuckDB instead of first writing PostgreSQL facts and then syncing.
- Switch remaining scripts and admin/benchmark fallbacks away from PostgreSQL affected tables.
- Validate parity before deleting PostgreSQL affected tables.

## Rollout Plan

1. Make DuckDB affected components authoritative for all reads.
2. Stop writing PostgreSQL affected component projections.
3. Move affected fact writes into DuckDB.
4. Run local and cloud parity checks.
5. Rebuild snapshots from DuckDB.
6. Drop or truncate PostgreSQL affected components.
7. Drop or truncate PostgreSQL affected facts.
8. Reclaim PostgreSQL disk with a controlled vacuum or volume rebuild.

## Risk Notes

- DuckDB is single-writer, so concurrent normalizers must serialize writes.
- Affected facts should remain recoverable from raw source records until DuckDB direct writes are proven.
- Version matching should stay in the existing C# resolver where ecosystem-specific semantics are required.
- Parquet can be used later as an immutable archive/export format, but it should not replace the primary DuckDB query store.
