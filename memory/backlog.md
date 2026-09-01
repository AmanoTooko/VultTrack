# Backlog

Only unfinished work belongs here. Order within a section is priority order. Move completed outcomes
to `current-state.md` or architecture decisions and delete their task entries.

## Performance

- Replace the broad catalog `LIKE` fallback and OFFSET pagination with a measured FTS/token index
  and keyset/search-after pagination. Preserve identifier/relation matching semantics.
- Parallelize independent vulnerability-detail reads through the managed DuckDB read pool and put
  the assembled result behind the existing cache.
- Bound the static version-comparison cache or activate the existing persistent cache table.
- Push component-version candidate filtering into SQL so popular packages are not truncated before
  ecosystem version evaluation.
- Improve EPSS ingest by merging its compact CSV in bulk rather than constructing/parsing JSON per
  row.
- Reduce fixed per-source scheduler overhead while preserving the one-writer invariant.

## AI Analysis

- The AI generation path is dead code. `AiVulnerabilitySummaryService` has no caller, and
  `admin.vulnerability.aiSummary` only re-reads the cache and returns `AI_BATCH_REQUIRED` on a
  miss, so the UI's Generate button can never produce an analysis. Either wire the service to that
  endpoint or remove the button and document the batch-import path as the only route.
- `CVE-2021-44228` carries a placeholder analysis row (`model=verification-sample`,
  `evidence_hash=deadbeef`) whose JSON uses a shallower schema than
  `prompts/vulnerability-analysis-batch.system.md`. Every canonical field is absent, so the detail
  page renders Unknown throughout. Audit `ai_vulnerability_analyses` for other sample rows and
  regenerate them. Real `mimo-v2.5-pro` rows render correctly.
- Add a schema check at import time so an analysis whose top-level keys do not match the current
  prompt version is rejected or flagged rather than stored and silently rendered as Unknown.

## Refactoring

- Decide whether to delete the legacy PostgreSQL path or isolate it behind a clear store boundary.
  Do not extend it while DuckDB remains the only supported runtime.
- Consolidate scattered environment reads into strongly typed options.
- Remove the existing CS9113 warning by using or deleting the unread Normalizer service-provider
  parameter.
- Move or mark remaining PG-first design documents as historical so they cannot be mistaken for
  implementation truth.
- Add a contract test over the `vulnerability.detail` payload. The frontend read `severities`,
  `records` and `sourceUrls` while the API sent `severityScores` and omitted the rest; nothing
  failed, the blocks just rendered empty.

## Product

- Add alerting/subscriptions for new vulnerabilities matching stored SBOM components, with webhook
  and email delivery designed around the single-writer model.
- Add VEX import/export and per-finding disposition state.
- Add API keys and a minimal role model beyond the single administrator.
- Add an audit log for administrative and data-maintenance actions.
- Add SPDX ingestion alongside CycloneDX.
- Add project/asset portfolio grouping for uploaded SBOMs.

## Operations

- Rotate any GitHub token exposed in historical terminal/agent logs and recreate API containers
  with the replacement stored only in host environment files.
- Make an explicit retention decision for accepted rollback databases after a stable observation
  period.
