-- Run only while the API/scheduler writer is stopped. This file is read-only.

select 'catalog' as audit,
       count(*) as vulnerabilities,
       sum(case when nullif(trim(primary_identifier), '') is null then 1 else 0 end) as blank_primary_identifiers,
       sum(case when primary_identifier like 'MINI-%' or primary_identifier like 'CGA-%' or primary_identifier like 'ECHO-%' then 1 else 0 end) as known_projection_catalog_rows,
       sum(case when (primary_identifier like 'MINI-%' or primary_identifier like 'CGA-%' or primary_identifier like 'ECHO-%')
                     and nullif(trim(title), '') is null
                     and nullif(trim(description), '') is null
                     and max_cvss_score is null then 1 else 0 end) as empty_projection_catalog_rows,
       sum(case when nullif(trim(title), '') is null and nullif(trim(description), '') is null and max_cvss_score is null then 1 else 0 end) as content_and_severity_empty
from vulnerabilities;

select 'duplicate_primary_identifier_groups' as audit, count(*) as value
from (
  select primary_identifier
  from vulnerabilities
  group by primary_identifier
  having count(*) > 1
);

select 'duplicate_identifier_owner_groups' as audit, count(*) as value
from (
  select identifier
  from vulnerability_identifiers
  group by identifier
  having count(distinct vulnerability_id) > 1
);

select 'identifier_id_key_mismatches' as audit, count(*) as value
from vulnerability_identifiers i
join vulnerabilities v on v.id = i.vulnerability_id
where i.vulnerability_key <> v.primary_identifier;

select 'source_relation_integrity' as audit,
       sum(case when related_identifier = vulnerability_key then 1 else 0 end) as self_relations,
       count(*) - count(distinct concat_ws('|', source_code, source_record_id, relation_type, related_identifier)) as duplicate_rows,
       sum(case when nullif(trim(related_identifier), '') is null then 1 else 0 end) as blank_related_identifiers
from source_record_relations;

select coalesce(severity_label, 'UNRATED') as severity_label, count(*) as vulnerabilities
from vulnerabilities
group by severity_label
order by vulnerabilities desc, severity_label;

select 'content_gaps' as audit,
       sum(case when nullif(trim(title), '') is null then 1 else 0 end) as missing_title,
       sum(case when nullif(trim(description), '') is null then 1 else 0 end) as missing_description,
       sum(case when max_cvss_score is null then 1 else 0 end) as missing_cvss,
       sum(case when nullif(trim(description), '') is null
                     and not exists (
                       select 1 from evidence_references r
                       where r.vulnerability_key = vulnerabilities.primary_identifier
                     ) then 1 else 0 end) as no_description_or_reference
from vulnerabilities;

select 'source_content_gaps' as audit,
       source_code,
       count(*) as source_records,
       sum(case when nullif(trim(title), '') is null and nullif(trim(description), '') is null then 1 else 0 end) as title_and_description_empty,
       sum(case when nullif(trim(source_url), '') is null then 1 else 0 end) as missing_source_url
from source_records
group by source_code
order by title_and_description_empty desc, source_records desc, source_code;

select 'ai_integrity' as audit,
       count(*) as ai_rows,
       sum(case when v.id is null then 1 else 0 end) as orphan_vulnerability_ids,
       count(*) - count(distinct concat_ws('|', a.vulnerability_id, a.evidence_hash)) as duplicate_evidence_rows
from ai_vulnerability_analyses a
left join vulnerabilities v on v.id = a.vulnerability_id;

select 'source_projection_versions' as audit, coalesce(normalizer_version, '<none>') as normalizer_version, count(*) as source_records
from source_records
group by normalizer_version
order by source_records desc, normalizer_version;
