# Historical Normalizer Rebuild Lessons

> **Archive only.** These PG-first incident notes describe the June 2026 runtime, not current
> DuckDB operations. For current rules, read `memory/architecture-decisions.md` and
> `memory/agent-guide.md`.

This note captures the operational traps found during the June 2026 normalizer rebuild and status-page repair. Treat it as a project-local skill before changing fetcher, normalizer, or status logic.

## Status Accounting

- Do not use the latest `source_sync_runs.fetched_count` as a source raw total. Incremental sources often fetch `0` or a small delta after a large baseline already exists.
- Separate active backlog from disabled/manual backlog. UI and alerts should count `pending`/`failed` only for enabled sources whose `runMode` is not `manual`.
- A failed latest fetch run does not mean the source has no usable data. `osv`, `suse-csaf`, and `cnnvd` can have good normalized rows while the latest run failed or was interrupted.
- Fast status must not scan all of `source_raw_index` on every page load. Use estimates or cached values for raw totals, and reserve full `count(*)` scans for explicit exact refreshes.
- When sampling source raw totals, normalize the sample against the estimated global raw count. Scaling every source independently can make per-source totals exceed the global total.
- Small sources can be distorted by block sampling. Label fast snapshots as estimates and use exact SQL for reports or one-off audits.
- `source_sync_runs` uses `log_summary`; do not query a non-existent `error_message` column.
- Avoid raw/run joins without pre-aggregation. They multiply rows and produce inflated counts.

## Source Semantics

- Keep exploit/enrichment update dates separate from vulnerability-source update dates. Metasploit or PoC updates should not overwrite the CVE "last modified" meaning.
- `nvd-cve` and `cve-list-v5` overlap heavily. If both are enabled, make NVD the canonical CVE base and keep CVE List manual/secondary unless a specific field is needed.
- Init sources (`*-init`) are baselines. Regular sources are deltas. Do not interpret a regular delta source with `0 raw` as an empty ecosystem if its init source owns the baseline.
- `trickest-cve` is disabled by default because local and cloud fetches were unreliable/noisy. Keep existing raw rows but do not schedule it unless the source quality is revalidated.
- CNVD/CNNVD-style sources can fail due anti-bot or detail-page fetch issues. Log the access limitation clearly and avoid treating that as normalizer corruption.

## Performance Checks

- Search queries like `log4j` should not be one wide `OR` over `ILIKE` and full-text predicates. Materialize matched IDs from indexed subqueries, then join/order.
- Keep trigram support on `vulnerabilities.primary_identifier` and title/search indexes current. A missing trigram index can turn common-keyword searches into multi-second scans.
- SBOM matching should prefer exact PURL/CPE/source-package paths. Broad name or CPE-product fallbacks should be restricted to components that lack stronger identities.
- Do not apply CPE-product fallback to non-CPE components. It creates broad false positives and slows candidate generation.
- For SBOM timing, test with a realistic SBOM and record both component count and match count. The June sample had 246 components and should stay around sub-second API time on a warm local DB.

## Maintenance Workflow

- Before rebuilding normalized data, snapshot local and cloud source status: total raw, active pending, active failed, disabled/manual pending, and latest run status by source.
- During rebuild, watch `pg_stat_activity` for accidental full-table `count(*)` scans and normalizer queries competing for I/O.
- Long exact status scans can time out through the API and return developer exception text in Development mode. Prefer direct SQL for audit reports.
- After changing static frontend assets in Docker, rebuild the frontend image. The dev compose file does not mount `wwwroot` into nginx.
- Bump static asset query strings in `index.html` when CSS/JS layout changes must be verified in the in-app browser.
- After API restart, browser admin sessions are invalid because sessions are in memory; re-login before testing private status/admin pages.
