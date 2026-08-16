#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: restore-duckdb-ai-backup.sh [--dry-run] <duckdb-bin> <database> <ai-backup.csv.gz>

Restores preserved AI analyses into a stopped, copied DuckDB catalog. Backup identifiers are
resolved against the current canonical catalog in this order: canonical identifier, unique catalog
alias, then a terminal embedded CVE. Existing canonical evidence hashes are left untouched.
EOF
}

dry_run=false
if [[ "${1:-}" == "--dry-run" ]]; then
  dry_run=true
  shift
fi

if [[ $# -ne 3 ]]; then
  usage >&2
  exit 2
fi

duckdb_bin="$1"
database="$2"
backup="$3"

for path in "$duckdb_bin" "$database" "$backup"; do
  if [[ ! -e "$path" || "$path" == *"'"* ]]; then
    echo "Each input must exist and cannot contain a single quote: $path" >&2
    exit 2
  fi
done

if [[ ! -x "$duckdb_bin" || ! -f "$database" || ! -f "$backup" ]]; then
  echo "Expected an executable DuckDB binary and regular database/backup files." >&2
  exit 2
fi

final_statement="commit"
if [[ "$dry_run" == true ]]; then
  final_statement="rollback"
fi

"$duckdb_bin" "$database" <<SQL
begin transaction;

create or replace temp table backup_ai as
select *
from read_csv_auto('$backup', header = true, all_varchar = true, ignore_errors = false);

create or replace temp table alias_owners as
select
  upper(i.identifier) as identifier,
  min(v.id) as vulnerability_id,
  min(v.primary_identifier) as primary_identifier,
  count(distinct v.id) as owner_count
from vulnerability_identifiers i
join vulnerabilities v on v.id = i.vulnerability_id
group by upper(i.identifier);

create or replace temp table ai_candidates as
select
  b.*,
  coalesce(direct_match.id, alias_match.vulnerability_id, embedded_match.id) as vulnerability_id,
  coalesce(direct_match.primary_identifier, alias_match.primary_identifier, embedded_match.primary_identifier) as canonical_identifier,
  case
    when direct_match.id is not null then 'canonical'
    when alias_match.vulnerability_id is not null then 'alias'
    when embedded_match.id is not null then 'embedded-cve'
    else 'unmatched'
  end as mapping_type
from backup_ai b
left join vulnerabilities direct_match
  on upper(direct_match.primary_identifier) = upper(b.primary_identifier)
left join alias_owners alias_match
  on alias_match.identifier = upper(b.primary_identifier)
 and alias_match.owner_count = 1
left join vulnerabilities embedded_match
  on upper(embedded_match.primary_identifier) = regexp_extract(upper(b.primary_identifier), '(CVE-[0-9]{4}-[0-9]+)$', 1);

create or replace temp table restored_ai as
select * exclude (row_number)
from (
  select
    c.vulnerability_id,
    c.canonical_identifier as primary_identifier,
    c.model,
    c.prompt_version,
    c.evidence_hash,
    c.analysis_json,
    c.input_json,
    try_cast(nullif(c.input_chars, '') as integer) as input_chars,
    try_cast(nullif(c.output_chars, '') as integer) as output_chars,
    c.source_url,
    c.created_at,
    c.updated_at,
    c.usage_json,
    try_cast(nullif(c.prompt_tokens, '') as bigint) as prompt_tokens,
    try_cast(nullif(c.completion_tokens, '') as bigint) as completion_tokens,
    try_cast(nullif(c.total_tokens, '') as bigint) as total_tokens,
    try_cast(nullif(c.cached_tokens, '') as bigint) as cached_tokens,
    row_number() over (
      partition by c.vulnerability_id, c.evidence_hash
      order by c.updated_at desc nulls last, c.created_at desc nulls last
    ) as row_number
  from ai_candidates c
  where c.vulnerability_id is not null
    and not exists (
      select 1
      from ai_vulnerability_analyses existing
      where existing.vulnerability_id = c.vulnerability_id
        and existing.evidence_hash = c.evidence_hash
    )
)
where row_number = 1;

select 'backup_rows' as metric, count(*)::varchar as value from backup_ai
union all
select 'mapped_canonical', count(*)::varchar from ai_candidates where mapping_type = 'canonical'
union all
select 'mapped_alias', count(*)::varchar from ai_candidates where mapping_type = 'alias'
union all
select 'mapped_embedded_cve', count(*)::varchar from ai_candidates where mapping_type = 'embedded-cve'
union all
select 'unmatched', count(*)::varchar from ai_candidates where mapping_type = 'unmatched'
union all
select 'pending_insert', count(*)::varchar from restored_ai
union all
select 'existing_ai_rows', count(*)::varchar from ai_vulnerability_analyses;

select primary_identifier, mapping_type, canonical_identifier
from ai_candidates
where upper(primary_identifier) = 'DEBIAN-CVE-2025-49844'
   or upper(primary_identifier) = 'CVE-2025-49844'
order by primary_identifier;

select primary_identifier
from ai_candidates
where mapping_type = 'unmatched'
order by primary_identifier
limit 20;

insert into ai_vulnerability_analyses (
  vulnerability_id, primary_identifier, model, prompt_version, evidence_hash, analysis_json,
  input_json, input_chars, output_chars, source_url, created_at, updated_at, usage_json,
  prompt_tokens, completion_tokens, total_tokens, cached_tokens
)
select
  vulnerability_id, primary_identifier, model, prompt_version, evidence_hash, analysis_json,
  input_json, input_chars, output_chars, source_url, created_at, updated_at, usage_json,
  prompt_tokens, completion_tokens, total_tokens, cached_tokens
from restored_ai;

select 'final_ai_rows' as metric, count(*)::varchar as value from ai_vulnerability_analyses
union all
select 'restored_cve_2025_49844', count(*)::varchar
from ai_vulnerability_analyses a
join vulnerabilities v on v.id = a.vulnerability_id
where v.primary_identifier = 'CVE-2025-49844';

$final_statement;
SQL
