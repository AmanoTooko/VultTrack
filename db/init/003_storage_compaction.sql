drop table if exists vulnerability_affected_facts_new;
drop table if exists vulnerability_affected_components_new;

-- Raw identifiers remain available in the table. Current queries do not use
-- array membership lookup, so retaining a large GIN index only adds write cost.
drop index if exists ix_raw_identifier_summary;
drop index if exists ix_raw_source_status_cover;

-- Identity normalization uses the exact btree lookup. Component search reads
-- the components table directly, so this trigram index only adds write cost.
drop index if exists ix_component_identity_trgm;

-- Superseded by ux_vulnerability_descriptions_identity, which also handles
-- nullable language values consistently.
drop index if exists ux_descriptions_dedup;
drop index if exists ix_affected_components_match;

create index if not exists ix_refs_vulnerability
  on vulnerability_references(vulnerability_id, source_id);

create index if not exists ix_identifier_group_fk
  on vulnerability_identifier_index(identifier_group_id)
  where identifier_group_id is not null;

-- Retention deletes remove raw rows in bulk. These indexes avoid a full child
-- table scan for every deleted raw object while PostgreSQL checks foreign keys.
create index if not exists ix_affected_facts_raw_index on vulnerability_affected_facts(raw_index_id);
create index if not exists ix_exploits_raw_index on vulnerability_exploits(raw_index_id);
create index if not exists ix_exploits_artifact_object on vulnerability_exploits(artifact_object_id);
create index if not exists ix_stg_exploit_pocs_artifact_object on stg_exploit_pocs(artifact_object_id);
create index if not exists ix_identifier_edges_raw_index on vulnerability_identifier_edges(raw_index_id);
create index if not exists ix_identifier_index_raw_index on vulnerability_identifier_index(raw_index_id);
create index if not exists ix_records_raw_index on vulnerability_records(raw_index_id);
create index if not exists ix_severity_scores_raw_index on vulnerability_severity_scores(raw_index_id);
create index if not exists ix_records_source_fk on vulnerability_records(source_id);
create index if not exists ix_descriptions_record_fk on vulnerability_descriptions(vulnerability_record_id);
create index if not exists ix_severity_record_fk on vulnerability_severity_scores(vulnerability_record_id);
create index if not exists ix_severity_source_fk on vulnerability_severity_scores(source_id);
create index if not exists ix_weaknesses_record_fk on vulnerability_weaknesses(vulnerability_record_id);
create index if not exists ix_weaknesses_source_fk on vulnerability_weaknesses(source_id);
create index if not exists ix_refs_record_fk on vulnerability_references(vulnerability_record_id);
create index if not exists ix_refs_source_fk on vulnerability_references(source_id);
create index if not exists ix_source_properties_record_fk on vulnerability_source_properties(vulnerability_record_id);
create index if not exists ix_detail_blocks_record_fk on vulnerability_detail_blocks(vulnerability_record_id);
create index if not exists ix_detail_blocks_source_fk on vulnerability_detail_blocks(source_id);
create index if not exists ix_descriptions_source_fk on vulnerability_descriptions(source_id);
create index if not exists ix_affected_facts_record_fk on vulnerability_affected_facts(vulnerability_record_id);
create index if not exists ix_affected_facts_source_fk on vulnerability_affected_facts(source_id);
create index if not exists ix_identifier_edges_source_fk on vulnerability_identifier_edges(source_id);
create index if not exists ix_identifier_index_source_fk on vulnerability_identifier_index(source_id);
create index if not exists ix_raw_object_fk on source_raw_index(object_id);
create index if not exists ix_raw_sync_run_fk on source_raw_index(sync_run_id);
create index if not exists ix_source_objects_sync_run_fk on source_objects(sync_run_id);
drop index if exists ix_raw_pending_by_source;
create index if not exists ix_raw_pending_by_source
  on source_raw_index(source_id, updated_at, id)
  where normalize_status in ('pending', 'failed');
create index if not exists ix_raw_normalize_latest
  on source_raw_index(
    source_id,
    external_key,
    source_modified_at desc nulls last,
    updated_at desc,
    created_at desc,
    id desc
  )
  where normalize_status in ('pending', 'failed');
create index if not exists ix_stg_cve_list_normalize_order on stg_cve_list_records(updated_at nulls last, cve_id, raw_index_id);
create index if not exists ix_stg_nvd_cpe_normalize_order on stg_nvd_cpe_dictionary(cpe23_uri, raw_index_id);
create index if not exists ix_stg_nvd_cves_normalize_order on stg_nvd_cves(modified_at nulls last, cve_id, raw_index_id);
create index if not exists ix_stg_threat_intel_normalize_order on stg_threat_intel_records(observed_at nulls last, identifier, raw_index_id);
create index if not exists ix_stg_registry_normalize_order on stg_registry_packages(ecosystem, namespace, name, raw_index_id);
create index if not exists ix_stg_exploit_normalize_order on stg_exploit_pocs(modified_at desc nulls last, raw_index_id);

-- The projection hook uses this identity for conflict resolution. Existing
-- installs may contain duplicates created before the constraint existed.
do $$
begin
  if to_regclass('ux_affected_components_identity_match_v3') is null then
    with ranked as (
      select id,
             first_value(id) over identity_partition as keeper_id,
             row_number() over identity_partition as rank,
             sum(evidence_count) over identity_partition as total_evidence_count
      from vulnerability_affected_components
      window identity_partition as (
        partition by vulnerability_id,
                     coalesce(ecosystem, ''),
                     coalesce(display_name, ''),
                     coalesce(primary_purl, ''),
                     coalesce(primary_cpe23_uri, ''),
                     coalesce(normalized_range, ''),
                     coalesce(range_type, '')
        order by created_at, id
      )
    )
    update vulnerability_affected_components c
    set evidence_count = greatest(c.evidence_count, ranked.total_evidence_count::integer)
    from ranked
    where c.id = ranked.keeper_id and ranked.rank = 1;

    with ranked as (
      select id,
             first_value(id) over identity_partition as keeper_id,
             row_number() over identity_partition as rank
      from vulnerability_affected_components
      window identity_partition as (
        partition by vulnerability_id,
                     coalesce(ecosystem, ''),
                     coalesce(display_name, ''),
                     coalesce(primary_purl, ''),
                     coalesce(primary_cpe23_uri, ''),
                     coalesce(normalized_range, ''),
                     coalesce(range_type, '')
        order by created_at, id
      )
    )
    update vulnerability_affected_evidence e
    set affected_component_id = ranked.keeper_id
    from ranked
    where e.affected_component_id = ranked.id and ranked.rank > 1;

    with ranked as (
      select id,
             row_number() over identity_partition as rank
      from vulnerability_affected_components
      window identity_partition as (
        partition by vulnerability_id,
                     coalesce(ecosystem, ''),
                     coalesce(display_name, ''),
                     coalesce(primary_purl, ''),
                     coalesce(primary_cpe23_uri, ''),
                     coalesce(normalized_range, ''),
                     coalesce(range_type, '')
        order by created_at, id
      )
    )
    delete from vulnerability_affected_components c
    using ranked
    where c.id = ranked.id and ranked.rank > 1;
  end if;
end
$$;

create unique index if not exists ux_affected_components_identity_match_v3
  on vulnerability_affected_components(
    vulnerability_id,
    coalesce(ecosystem, ''),
    coalesce(display_name, ''),
    coalesce(primary_purl, ''),
    coalesce(primary_cpe23_uri, ''),
    coalesce(normalized_range, ''),
    coalesce(range_type, '')
  );

drop index if exists ix_affected_components_identity_match_v2;
