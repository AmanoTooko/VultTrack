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
