# VulTrack PostgreSQL Normalization Performance Report

Date: 2026-05-09

## Executive Summary

The current normalization bottleneck is PostgreSQL, not the Node runner and not an explicit Docker CPU limit on the runner. The runner only dispatches HTTP requests and stays near idle CPU. The .NET API performs parsing and writes, but during full normalization PostgreSQL consumes the dominant CPU and I/O.

Observed during the parallel runner:

| Component | CPU | Memory | Notes |
| --- | ---: | ---: | --- |
| `vultrack-normalizer-runner` | ~1% | ~31 MiB | HTTP orchestration only |
| `vultrack-api` | ~1-14% | ~180 MiB | .NET parser/API, bounded by DB round trips |
| `vultrack-postgres` | ~340-670% | ~4.0 GiB of 7.65 GiB Docker VM | Primary bottleneck |

Current throughput after the source-parallel runner:

- `LIMIT_PER_SOURCE=50`
- `NORMALIZE_PARALLELISM=4`
- About `250` raw records per cycle.
- Recent cycles complete in roughly `4-6s` for the active sources.
- Failed count stays `0`.

This is materially better than the old single request loop, but the next major gains require PostgreSQL read/write tuning and reducing per-record SQL work.

## Current Runtime Shape

The pipeline now has these layers:

1. Fetchers write raw records into `source_objects`, `source_raw_index`, and source staging tables.
2. Runner calls the .NET API:
   - legacy: `/api/v1/raw.normalizePending`
   - parallel: `/api/v1/raw.normalizeSource`
3. Normalizers parse staging rows into:
   - `vulnerabilities`
   - `vulnerability_records`
   - `vulnerability_identifier_index`
   - `vulnerability_*` fact tables
   - `components` and affected component tables
4. Canonicalization matches aliases through `vulnerability_identifier_index`; fallback still checks `vulnerabilities`.

Recent optimization already implemented:

- Added `scripts/run-parallel-normalization.mjs`.
- Added `npm run normalize:parallel`.
- Split canonical lookup into fast identifier-index path and fallback path.
- Added indexes:
  - `ix_raw_pending_by_source`
  - `ix_identifier_canonical_group`
  - `ix_vuln_primary_identifier`

## Observed Database State

Approximate database size:

- Database: `22 GB`

Largest relevant tables:

| Table | Total Size | Table Size | Live Rows |
| --- | ---: | ---: | ---: |
| `vulnerability_affected_facts` | 5228 MB | 3756 MB | 3,763,426 |
| `source_raw_index` | 2452 MB | 1299 MB | 2,827,722 |
| `vulnerability_records` | 2254 MB | 493 MB | 581,066 |
| `source_objects` | 1465 MB | 944 MB | 2,797,604 |
| `vulnerability_affected_components` | 1435 MB | 954 MB | 3,551,964 |
| `vulnerabilities` | 871 MB | 404 MB | 345,888 |
| `vulnerability_identifier_index` | 271 MB | 126 MB | 647,903 |

PostgreSQL settings are still near defaults:

| Setting | Current |
| --- | ---: |
| `shared_buffers` | 128 MB |
| `effective_cache_size` | 4 GB |
| `work_mem` | 4 MB |
| `maintenance_work_mem` | 64 MB |
| `max_connections` | 100 |
| `checkpoint_timeout` | 5 min |
| `max_wal_size` | 1 GB |
| `random_page_cost` | 4 |

The database is much larger than memory, and `shared_buffers=128MB` is too small for this workload. The high PostgreSQL CPU and very large block I/O are expected under these settings.

## Main Bottlenecks

### 1. Per-Record Write Amplification

Each normalized vulnerability can trigger many individual SQL statements:

- canonical lookup
- insert/update `vulnerabilities`
- upsert source record
- insert identifier index rows
- insert descriptions
- insert severity facts
- insert references
- insert weaknesses
- insert affected facts
- affected component hook upserts
- update raw normalize status

This is reliable and simple, but it creates many round trips and many index updates per raw record.

Impact:

- PostgreSQL spends time in both CPU and I/O.
- Small batches keep requests stable but lower throughput.
- More runner parallelism increases DB pressure quickly.

### 2. Canonical Matching Reads

Canonicalization is a hot path. The key matching path is:

```sql
select distinct v.id, v.primary_identifier
from vulnerability_identifier_index i
join vulnerabilities v on v.id = i.canonical_vulnerability_id
where i.normalized_value = any($1)
```

Before the latest change, this was unioned with a fallback query against `vulnerabilities`:

```sql
where v.canonical_key = any($1)
   or v.primary_identifier = any($1)
   or v.identifiers && $1
```

The fallback includes an array overlap check and can be expensive at scale. It is now only executed when the identifier-index path finds nothing.

Remaining concern:

- Fallback still exists for new records and weakly indexed cases.
- If source rows often arrive before their aliases are indexed, fallback can remain hot.

### 3. Raw Queue Selection

Most normalizers select rows by joining staging tables to `source_raw_index` and checking:

```sql
where r.normalize_status <> 'succeeded'
```

Several source-specific queries order by staging-table timestamps or `r.updated_at`. This keeps the logic clear but makes the planner sensitive to stats and available indexes.

Recent index added:

```sql
create index if not exists ix_raw_pending_by_source
  on source_raw_index(source_id, updated_at, id)
  where normalize_status <> 'succeeded';
```

Potential issue:

- This index helps queries that filter by `source_id` and order by `updated_at`.
- It may not help staging queries ordered by staging timestamps such as `modified_at` or `updated_at`.

### 4. Hot Updates and Dead Tuples

`source_raw_index` is updated on every normalized row:

```sql
update source_raw_index
set normalize_status = 'succeeded', updated_at = now()
where id = $1
```

This is unavoidable in the current queue model, but it creates update churn on a large table and updates indexes that include `updated_at`.

Observed:

- `source_raw_index` has non-trivial dead tuples.
- The primary key and status update path are extremely hot.

### 5. PostgreSQL Memory and Checkpoint Defaults

The current PostgreSQL settings are too conservative for a 22GB working database and heavy write workload.

Likely effects:

- Low `shared_buffers` causes more churn between OS cache and PostgreSQL buffers.
- Low `max_wal_size` and short checkpoint interval can cause frequent checkpoint pressure.
- Low `maintenance_work_mem` slows index creation and maintenance.
- `random_page_cost=4` may bias planner decisions as if storage were slow spinning disks.

## Docker Resource Assessment

The runner container has no explicit CPU or memory cap:

```text
NanoCpus=0
CpuQuota=0
CpusetCpus=
Memory=0
```

The effective constraint is Docker Desktop VM resources:

- Observed container memory limit: about `7.65 GiB`.
- PostgreSQL uses about `4.0 GiB`.
- Database is `22 GB`.

Conclusion:

- Docker is not limiting the runner.
- Docker VM memory may be limiting PostgreSQL cache effectiveness.
- Increasing Docker Desktop memory and CPU can help, especially memory.

## Optimization Plan

### Phase 0: Measure Before Each Change

Install or enable measurement tools:

```sql
create extension if not exists pg_stat_statements;
```

Track:

- top queries by total time
- top queries by mean time
- block reads vs cache hits
- WAL generation
- checkpoint frequency
- dead tuples and autovacuum

Useful commands:

```sql
select query, calls, total_exec_time, mean_exec_time, rows,
       shared_blks_hit, shared_blks_read, shared_blks_dirtied, shared_blks_written
from pg_stat_statements
order by total_exec_time desc
limit 20;
```

```sql
select relname, n_live_tup, n_dead_tup, vacuum_count, autovacuum_count,
       analyze_count, autoanalyze_count
from pg_stat_user_tables
order by n_dead_tup desc
limit 20;
```

### Phase 1: PostgreSQL Runtime Tuning

For Docker Desktop with 16GB allocated to Docker:

```conf
shared_buffers = 4GB
effective_cache_size = 12GB
work_mem = 16MB
maintenance_work_mem = 1GB
checkpoint_timeout = 15min
max_wal_size = 8GB
random_page_cost = 1.1
effective_io_concurrency = 200
```

For current 8GB Docker VM, use smaller values:

```conf
shared_buffers = 2GB
effective_cache_size = 6GB
work_mem = 8MB
maintenance_work_mem = 512MB
checkpoint_timeout = 15min
max_wal_size = 4GB
random_page_cost = 1.1
effective_io_concurrency = 100
```

Expected impact:

- Better cache residency.
- Less checkpoint churn.
- Better planner choices on SSD.

Risk:

- Too much `work_mem` multiplied by concurrent queries can exhaust memory.
- Tune with the chosen normalizer parallelism.

### Phase 2: Query and Index Refinement

Candidate indexes to evaluate with `EXPLAIN (ANALYZE, BUFFERS)`:

```sql
create index concurrently if not exists ix_raw_pending_source_modified
  on source_raw_index(source_id, source_modified_at, id)
  where normalize_status <> 'succeeded';
```

```sql
create index concurrently if not exists ix_vuln_identifier_lookup_cover
  on vulnerability_identifier_index(normalized_value)
  include (canonical_vulnerability_id);
```

Potential source staging indexes:

- `stg_nvd_cves(modified_at, cve_id, raw_index_id)`
- `stg_cve_list_records(updated_at, cve_id, raw_index_id)`
- source-specific OSV staging indexes if `ORDER BY r.updated_at` remains expensive.

Important:

- Do not blindly add every index. Every extra index slows inserts/updates.
- Use `EXPLAIN (ANALYZE, BUFFERS)` against live representative queries first.

### Phase 3: Queue Claiming and True Parallelism

Current source-parallel runner is safe because it runs different source codes in parallel. True same-source parallelism needs a queue claim mechanism.

Recommended queue pattern:

```sql
with claimed as (
  select r.id
  from source_raw_index r
  where r.source_id = $1
    and r.normalize_status = 'pending'
  order by r.updated_at
  for update skip locked
  limit $2
)
update source_raw_index r
set normalize_status = 'processing',
    normalize_started_at = now(),
    normalize_worker_id = $3,
    updated_at = now()
from claimed
where r.id = claimed.id
returning r.id;
```

Then workers process claimed IDs and mark:

- `succeeded`
- `failed`
- `pending` again if lease expires

Benefits:

- Multiple workers can process the same high-volume source safely.
- Avoids duplicate work.
- Makes batch sizing and retries explicit.

Schema additions:

- `normalize_started_at timestamptz`
- `normalize_finished_at timestamptz`
- `normalize_worker_id text`
- `normalize_attempts integer default 0`
- `normalize_error text`

### Phase 4: Bulk Insert / Batch Writes

The current design favors simple per-record writes. For speed, batch common facts:

- collect descriptions and insert with one multi-row command
- collect references and insert with one multi-row command
- collect affected facts and use `COPY` or batched insert
- mark raw rows succeeded in batches:

```sql
update source_raw_index
set normalize_status = 'succeeded',
    updated_at = now()
where id = any($1);
```

Highest-value tables for batching:

- `vulnerability_affected_facts`
- `vulnerability_references`
- `vulnerability_descriptions`
- `vulnerability_severity_scores`
- `source_raw_index` status updates

Expected impact:

- Fewer network round trips.
- Fewer transaction overheads.
- Better WAL locality.

Risk:

- Error isolation becomes harder. Need per-record error handling or savepoints.

### Phase 5: Data Model and Partitioning

If full-scale normalization remains slow, consider partitioning:

1. `source_raw_index` partitioned by `source_id` or source family.
2. Very large fact tables partitioned by `source_id` or time.
3. Move immutable raw payload storage out of hot database tables if raw lookup is not frequent.

Likely candidates:

- `source_raw_index`
- `vulnerability_affected_facts`
- `source_objects`

Risks:

- Partitioning adds operational complexity.
- Existing foreign keys and staging table joins need review.

## Recommended Immediate Next Steps

1. Increase Docker Desktop resources.
   - CPU: 6-8 cores if available.
   - Memory: 16GB minimum, 24GB better if the host can spare it.

2. Tune PostgreSQL memory/checkpoint settings.
   - Start with the 8GB or 16GB profile above.
   - Restart Postgres and rerun normalization for 10-15 minutes.

3. Enable `pg_stat_statements`.
   - Capture before/after top query stats.
   - Use this to decide which indexes to keep or add.

4. Add `EXPLAIN (ANALYZE, BUFFERS)` test scripts for:
   - canonical lookup
   - NVD pending selection
   - CVE List pending selection
   - OSV pending selection
   - CPE pending selection

5. Implement queue claiming with `FOR UPDATE SKIP LOCKED`.
   - This unlocks safe same-source parallelism.
   - Then raise `NORMALIZE_PARALLELISM` gradually.

6. Batch-write affected facts and references.
   - This is likely the largest code-level write reduction.

## Current Safe Operating Point

Recommended current runner:

```bash
API_BASE_URL=http://localhost:5099 \
LIMIT_PER_SOURCE=50 \
NORMALIZE_PARALLELISM=4 \
npm run normalize:parallel
```

Do not raise parallelism aggressively until PostgreSQL memory/checkpoint tuning is done. Current Postgres CPU already reaches around 6-7 cores during bursts, and block I/O is high.

## Open Questions

- What Docker Desktop CPU/memory limits can be allocated on the host?
- Is the workload intended to run on Docker Desktop long-term, or on a dedicated PostgreSQL host?
- Is full normalization a one-time bootstrap only, or a recurring operation?
- Is it acceptable to temporarily relax durability for bootstrap, for example `synchronous_commit=off` or an unlogged staging queue?
- Should failed records be tracked explicitly before enabling same-source parallel workers?

