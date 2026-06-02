drop table if exists vulnerability_affected_facts_new;
drop table if exists vulnerability_affected_components_new;

-- Raw identifiers remain available in the table. Current queries do not use
-- array membership lookup, so retaining a large GIN index only adds write cost.
drop index if exists ix_raw_identifier_summary;

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

create index if not exists ix_affected_components_identity_match_v2
  on vulnerability_affected_components(
    vulnerability_id,
    coalesce(ecosystem, ''),
    coalesce(display_name, ''),
    coalesce(primary_purl, ''),
    coalesce(primary_cpe23_uri, ''),
    coalesce(normalized_range, ''),
    coalesce(range_type, '')
  );
