create extension if not exists pg_trgm;
create extension if not exists unaccent;
create extension if not exists btree_gin;
create extension if not exists pgcrypto;

create table if not exists sources (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,
  name text not null,
  kind text not null,
  homepage_url text,
  license text,
  enabled boolean not null default true,
  plugin_name text not null,
  plugin_version text,
  config_json jsonb not null default '{}'::jsonb,
  schedule_cron text,
  rate_limit_json jsonb not null default '{}'::jsonb,
  checkpoint_json jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists source_sync_runs (
  id uuid primary key default gen_random_uuid(),
  source_id uuid not null references sources(id),
  status text not null,
  trigger text not null,
  checkpoint_before jsonb,
  checkpoint_after jsonb,
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  fetched_count integer not null default 0,
  changed_count integer not null default 0,
  parsed_count integer not null default 0,
  normalized_count integer not null default 0,
  error_count integer not null default 0,
  log_summary text
);

create table if not exists source_task_errors (
  id uuid primary key default gen_random_uuid(),
  sync_run_id uuid references source_sync_runs(id),
  source_id uuid references sources(id),
  stage text not null,
  external_key text,
  error_code text not null,
  error_message text not null,
  error_detail jsonb not null default '{}'::jsonb,
  retry_count integer not null default 0,
  next_retry_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists source_objects (
  id uuid primary key default gen_random_uuid(),
  source_id uuid not null references sources(id),
  sync_run_id uuid references source_sync_runs(id),
  object_uri text not null,
  content_type text not null,
  compression text not null default 'gzip',
  sha256 text not null,
  size_bytes bigint not null,
  compressed_size_bytes bigint not null,
  schema_hint text,
  fetched_at timestamptz not null default now(),
  retention_class text not null default 'hot',
  unique (source_id, sha256)
);

create table if not exists source_raw_index (
  id uuid primary key default gen_random_uuid(),
  source_id uuid not null references sources(id),
  sync_run_id uuid references source_sync_runs(id),
  object_id uuid references source_objects(id),
  external_key text not null,
  external_id text,
  source_url text,
  etag text,
  last_modified_header text,
  source_published_at timestamptz,
  source_modified_at timestamptz,
  content_hash text not null,
  record_hash text not null,
  record_offset jsonb,
  identifier_summary text[] not null default '{}',
  status text not null default 'new',
  parse_status text not null default 'pending',
  normalize_status text not null default 'pending',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index if not exists ux_raw_source_external_hash
  on source_raw_index(source_id, external_key, record_hash);
create index if not exists ix_raw_source_modified
  on source_raw_index(source_id, source_modified_at desc);
create index if not exists ix_raw_source_status_cover
  on source_raw_index(source_id) include(parse_status, normalize_status, updated_at);
create index if not exists ix_raw_pending_by_source
  on source_raw_index(source_id, updated_at, id)
  where normalize_status <> 'succeeded';

create table if not exists stg_nvd_cves (
  raw_index_id uuid primary key references source_raw_index(id) on delete cascade,
  cve_id text not null,
  vuln_status text,
  descriptions jsonb not null default '[]'::jsonb,
  metrics jsonb not null default '{}'::jsonb,
  weaknesses jsonb not null default '[]'::jsonb,
  configurations jsonb not null default '[]'::jsonb,
  references_json jsonb not null default '[]'::jsonb,
  published_at timestamptz,
  modified_at timestamptz,
  cisa_exploit_add text,
  cisa_action_due text,
  payload jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists stg_nvd_cpe_dictionary (
  raw_index_id uuid primary key references source_raw_index(id) on delete cascade,
  cpe23_uri text not null,
  part text,
  vendor text,
  product text,
  version text,
  target_sw text,
  titles jsonb not null default '[]'::jsonb,
  refs jsonb not null default '[]'::jsonb,
  deprecated boolean not null default false,
  last_modified_at timestamptz,
  payload jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists stg_ghsa_advisories (
  raw_index_id uuid primary key references source_raw_index(id) on delete cascade,
  ghsa_id text not null,
  cve_id text,
  identifiers jsonb not null default '[]'::jsonb,
  summary text,
  description text,
  ecosystem text,
  package_name text,
  vulnerable_ranges jsonb not null default '[]'::jsonb,
  patched_versions jsonb not null default '[]'::jsonb,
  cvss jsonb not null default '{}'::jsonb,
  cwes jsonb not null default '[]'::jsonb,
  references_json jsonb not null default '[]'::jsonb,
  published_at timestamptz,
  updated_at timestamptz,
  payload jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists stg_osv_vulnerabilities (
  raw_index_id uuid primary key references source_raw_index(id) on delete cascade,
  osv_id text not null,
  aliases text[] not null default '{}',
  related text[] not null default '{}',
  summary text,
  details text,
  affected jsonb not null default '[]'::jsonb,
  severity jsonb not null default '[]'::jsonb,
  references_json jsonb not null default '[]'::jsonb,
  published_at timestamptz,
  modified_at timestamptz,
  payload jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists stg_cve_list_records (
  raw_index_id uuid primary key references source_raw_index(id) on delete cascade,
  cve_id text not null,
  cve_metadata jsonb not null default '{}'::jsonb,
  containers_cna jsonb not null default '{}'::jsonb,
  containers_adp jsonb not null default '[]'::jsonb,
  state text,
  published_at timestamptz,
  updated_at timestamptz,
  payload jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists stg_threat_intel_records (
  raw_index_id uuid primary key references source_raw_index(id) on delete cascade,
  provider text not null,
  identifier text not null,
  epss_score numeric(8,7),
  epss_percentile numeric(8,7),
  observed_at timestamptz,
  payload jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists stg_alpine_secdb (
  raw_index_id uuid primary key references source_raw_index(id) on delete cascade,
  distro_release text not null,
  package_name text not null,
  identifiers text[] not null default '{}',
  secfixes jsonb not null default '{}'::jsonb,
  payload jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists stg_debian_security_tracker (
  raw_index_id uuid primary key references source_raw_index(id) on delete cascade,
  cve_id text not null,
  packages jsonb not null default '{}'::jsonb,
  payload jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists stg_ubuntu_osv (
  raw_index_id uuid primary key references source_raw_index(id) on delete cascade,
  osv_id text not null,
  aliases text[] not null default '{}',
  affected jsonb not null default '[]'::jsonb,
  payload jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists stg_registry_packages (
  raw_index_id uuid primary key references source_raw_index(id) on delete cascade,
  registry text not null,
  ecosystem text not null,
  namespace text,
  name text not null,
  version text,
  purl text,
  repository_url text,
  homepage_url text,
  metadata jsonb not null default '{}'::jsonb,
  payload jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists stg_ecosystem_advisories (
  raw_index_id uuid primary key references source_raw_index(id) on delete cascade,
  provider text not null,
  ecosystem text,
  advisory_id text not null,
  identifiers text[] not null default '{}',
  package_name text,
  purl text,
  vulnerable_ranges jsonb not null default '[]'::jsonb,
  patched_versions jsonb not null default '[]'::jsonb,
  severity_label text,
  cvss jsonb not null default '{}'::jsonb,
  references_json jsonb not null default '[]'::jsonb,
  published_at timestamptz,
  modified_at timestamptz,
  payload jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists stg_exploit_pocs (
  raw_index_id uuid primary key references source_raw_index(id) on delete cascade,
  provider text not null,
  source_key text not null,
  identifiers text[] not null default '{}',
  title text,
  source_url text,
  artifact_url text,
  artifact_object_id uuid references source_objects(id),
  artifact_sha256 text,
  artifact_type text not null,
  exploit_type text,
  maturity text not null default 'poc',
  verification_status text not null default 'unreviewed',
  requires_auth boolean,
  requires_user_interaction boolean,
  language text,
  platform text,
  author text,
  published_at timestamptz,
  modified_at timestamptz,
  tags text[] not null default '{}',
  payload jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists stg_external_advisories (
  raw_index_id uuid primary key references source_raw_index(id) on delete cascade,
  provider text not null,
  advisory_id text not null,
  identifiers text[] not null default '{}',
  title text,
  summary text,
  description text,
  severity_label text,
  references_json jsonb not null default '[]'::jsonb,
  affected_products jsonb not null default '[]'::jsonb,
  affected_vendors jsonb not null default '[]'::jsonb,
  poc_available boolean,
  detail_available boolean,
  published_at timestamptz,
  modified_at timestamptz,
  payload jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists vulnerabilities (
  id uuid primary key default gen_random_uuid(),
  canonical_key text not null unique,
  primary_identifier text not null,
  title text,
  description text,
  status text not null default 'active',
  published_at timestamptz,
  modified_at timestamptz,
  withdrawn_at timestamptz,
  max_cvss_score numeric(3,1),
  max_cvss_version text,
  max_cvss_vector text,
  max_cvss_source_id uuid references sources(id),
  severity_label text,
  severity_source text,
  severity_confidence numeric(4,3),
  epss_score numeric(8,7),
  epss_percentile numeric(8,7),
  kev_date_added date,
  known_ransomware boolean,
  risk_score numeric(6,2),
  source_count integer not null default 0,
  affected_component_count integer not null default 0,
  affected_ecosystems text[] not null default '{}',
  affected_component_names text[] not null default '{}',
  identifiers text[] not null default '{}',
  aliases text[] not null default '{}',
  search_text tsvector,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists vulnerability_records (
  id uuid primary key default gen_random_uuid(),
  vulnerability_id uuid references vulnerabilities(id),
  source_id uuid not null references sources(id),
  raw_index_id uuid not null references source_raw_index(id),
  source_record_id text not null,
  title text,
  description text,
  status text,
  source_specific jsonb not null default '{}'::jsonb,
  confidence numeric(4,3) not null default 1.0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(source_id, source_record_id, raw_index_id)
);

create table if not exists vulnerability_identifier_groups (
  id uuid primary key default gen_random_uuid(),
  canonical_vulnerability_id uuid references vulnerabilities(id),
  group_key text not null unique,
  primary_identifier text not null,
  identifiers text[] not null default '{}',
  source_count integer not null default 0,
  strong_edge_count integer not null default 0,
  weak_edge_count integer not null default 0,
  merge_version bigint not null default 1,
  updated_at timestamptz not null default now()
);

create table if not exists vulnerability_identifier_index (
  id uuid primary key default gen_random_uuid(),
  identifier_type text not null,
  identifier_value text not null,
  normalized_value text not null,
  identifier_group_id uuid references vulnerability_identifier_groups(id),
  canonical_vulnerability_id uuid references vulnerabilities(id),
  source_id uuid references sources(id),
  raw_index_id uuid references source_raw_index(id),
  evidence_type text not null default 'source_record',
  evidence_strength text not null default 'strong',
  confidence numeric(4,3) not null default 1.0,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now()
);

create unique index if not exists ux_identifier_normalized_source
  on vulnerability_identifier_index(identifier_type, normalized_value, source_id, raw_index_id);
create index if not exists ix_identifier_lookup
  on vulnerability_identifier_index(normalized_value, canonical_vulnerability_id);
create index if not exists ix_identifier_canonical_group
  on vulnerability_identifier_index(canonical_vulnerability_id)
  where canonical_vulnerability_id is not null;
create index if not exists ix_identifier_group_fk
  on vulnerability_identifier_index(identifier_group_id)
  where identifier_group_id is not null;
create index if not exists ix_vuln_primary_identifier
  on vulnerabilities(primary_identifier);

create table if not exists vulnerability_identifier_edges (
  id uuid primary key default gen_random_uuid(),
  from_identifier text not null,
  to_identifier text not null,
  edge_type text not null,
  strength text not null,
  source_id uuid references sources(id),
  raw_index_id uuid references source_raw_index(id),
  evidence_json jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists vulnerability_severity_scores (
  id uuid primary key default gen_random_uuid(),
  vulnerability_id uuid references vulnerabilities(id),
  vulnerability_record_id uuid references vulnerability_records(id),
  source_id uuid references sources(id),
  raw_index_id uuid references source_raw_index(id),
  scoring_system text not null,
  scoring_version text,
  score_type text,
  vector_string text,
  score numeric(4,1),
  severity_label text,
  normalized_severity text,
  source_severity_label text,
  metric_json jsonb not null default '{}'::jsonb,
  source_json_path text,
  is_primary boolean not null default false,
  is_selected boolean not null default false,
  confidence numeric(4,3) not null default 1.0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists vulnerability_descriptions (
  id uuid primary key default gen_random_uuid(),
  vulnerability_id uuid references vulnerabilities(id),
  vulnerability_record_id uuid references vulnerability_records(id),
  source_id uuid references sources(id),
  lang text,
  description_type text,
  value text not null,
  source_json_path text,
  is_selected boolean not null default false
);

create unique index if not exists ux_vulnerability_descriptions_identity
  on vulnerability_descriptions(vulnerability_id, source_id, lang, description_type) nulls not distinct;

create table if not exists vulnerability_weaknesses (
  id uuid primary key default gen_random_uuid(),
  vulnerability_id uuid references vulnerabilities(id),
  vulnerability_record_id uuid references vulnerability_records(id),
  source_id uuid references sources(id),
  weakness_type text not null,
  weakness_id text,
  description text,
  source_json_path text
);

create unique index if not exists ux_weaknesses_dedup
  on vulnerability_weaknesses(vulnerability_id, source_id, coalesce(weakness_id, ''));

create table if not exists vulnerability_references (
  id uuid primary key default gen_random_uuid(),
  vulnerability_id uuid references vulnerabilities(id),
  vulnerability_record_id uuid references vulnerability_records(id),
  source_id uuid references sources(id),
  url text not null,
  normalized_url text,
  ref_type text,
  tags text[] not null default '{}',
  source_json_path text
);

create table if not exists vulnerability_exploits (
  id uuid primary key default gen_random_uuid(),
  vulnerability_id uuid not null references vulnerabilities(id),
  source_id uuid not null references sources(id),
  raw_index_id uuid not null references source_raw_index(id),
  source_key text not null,
  source_url text,
  artifact_url text,
  artifact_object_id uuid references source_objects(id),
  artifact_sha256 text,
  title text,
  artifact_type text not null,
  exploit_type text,
  maturity text not null default 'poc',
  verification_status text not null default 'unreviewed',
  requires_auth boolean,
  requires_user_interaction boolean,
  language text,
  platform text,
  author text,
  published_at timestamptz,
  modified_at timestamptz,
  tags text[] not null default '{}',
  source_specific jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index if not exists ux_vulnerability_exploits_source_key
  on vulnerability_exploits(source_id, source_key, vulnerability_id);
create index if not exists ix_vulnerability_exploits_vuln
  on vulnerability_exploits(vulnerability_id, maturity, verification_status);

create table if not exists vulnerability_source_properties (
  id uuid primary key default gen_random_uuid(),
  vulnerability_id uuid references vulnerabilities(id),
  vulnerability_record_id uuid references vulnerability_records(id),
  source_id uuid references sources(id),
  property_namespace text not null,
  property_key text not null,
  value_type text not null,
  value_text text,
  value_number numeric,
  value_bool boolean,
  value_date timestamptz,
  value_json jsonb,
  source_json_path text,
  is_queryable boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists vulnerability_detail_blocks (
  id uuid primary key default gen_random_uuid(),
  vulnerability_id uuid references vulnerabilities(id),
  vulnerability_record_id uuid references vulnerability_records(id),
  source_id uuid references sources(id),
  plugin_name text not null,
  plugin_version text,
  block_key text not null,
  block_title text not null,
  block_type text not null,
  display_order integer not null default 0,
  payload_json jsonb not null,
  source_hash text not null,
  generated_at timestamptz not null default now(),
  expires_at timestamptz
);

create table if not exists components (
  id uuid primary key default gen_random_uuid(),
  component_key text not null unique,
  canonical_name text not null,
  component_type text not null,
  primary_purl text,
  primary_cpe23_uri text,
  primary_repository_url text,
  identities text[] not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists component_identity_index (
  id uuid primary key default gen_random_uuid(),
  component_id uuid references components(id),
  identity_type text not null,
  identity_value text not null,
  normalized_value text not null,
  ecosystem text,
  source_id uuid references sources(id),
  evidence_type text,
  confidence numeric(4,3) not null default 1.0,
  status text not null default 'candidate',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists component_mapping_edges (
  id uuid primary key default gen_random_uuid(),
  from_identity text not null,
  to_identity text not null,
  edge_type text not null,
  method text not null,
  confidence numeric(4,3) not null default 1.0,
  status text not null default 'candidate',
  evidence_json jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists cpe_entries (
  id uuid primary key default gen_random_uuid(),
  cpe23_uri text not null unique,
  part text,
  vendor text,
  product text,
  version text,
  update_value text,
  edition text,
  language_value text,
  sw_edition text,
  target_sw text,
  target_hw text,
  other text,
  titles_json jsonb not null default '[]'::jsonb,
  refs_json jsonb not null default '[]'::jsonb,
  deprecated boolean not null default false,
  last_modified_at timestamptz
);

create table if not exists registry_packages (
  id uuid primary key default gen_random_uuid(),
  ecosystem text not null,
  registry_url text,
  namespace text,
  name text not null,
  normalized_name text not null,
  purl_type text,
  purl_without_version text,
  latest_version text,
  description text,
  homepage_url text,
  repository_url text,
  issue_url text,
  metadata_json jsonb not null default '{}'::jsonb,
  last_seen_at timestamptz not null default now()
);

create table if not exists purl_name_mappings (
  id uuid primary key default gen_random_uuid(),
  purl_type text not null,
  registry text,
  namespace text,
  name text not null,
  normalized_name text not null,
  package_manager_name text,
  package_manager_namespace text,
  ruleset_version text,
  confidence numeric(4,3) not null default 1.0
);

create table if not exists vulnerability_affected_facts (
  id uuid primary key default gen_random_uuid(),
  vulnerability_id uuid references vulnerabilities(id),
  vulnerability_record_id uuid references vulnerability_records(id),
  source_id uuid references sources(id),
  raw_index_id uuid references source_raw_index(id),
  fact_type text not null,
  ecosystem text,
  package_namespace text,
  package_name text,
  normalized_package_name text,
  purl text,
  purl_without_version text,
  cpe23_uri text,
  component_id uuid references components(id),
  version_range_raw text,
  range_type text,
  introduced text,
  fixed text,
  last_affected text,
  limit_version text,
  affected_versions jsonb not null default '[]'::jsonb,
  fixed_versions jsonb not null default '[]'::jsonb,
  vulnerable boolean,
  source_confidence numeric(4,3) not null default 1.0,
  source_json_path text,
  source_specific jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists vulnerability_affected_components (
  id uuid primary key default gen_random_uuid(),
  vulnerability_id uuid not null references vulnerabilities(id),
  component_id uuid references components(id),
  ecosystem text,
  package_name text,
  display_name text not null,
  primary_purl text,
  primary_cpe23_uri text,
  normalized_range text,
  range_type text,
  introduced text,
  fixed text,
  last_affected text,
  affected_versions jsonb not null default '[]'::jsonb,
  fixed_versions jsonb not null default '[]'::jsonb,
  confidence numeric(4,3) not null default 1.0,
  resolution_status text not null default 'candidate',
  conflict_flag boolean not null default false,
  evidence_count integer not null default 0,
  evidence_summary text,
  selected_by_rule text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists vulnerability_affected_evidence (
  id uuid primary key default gen_random_uuid(),
  affected_component_id uuid not null references vulnerability_affected_components(id) on delete cascade,
  affected_fact_id uuid references vulnerability_affected_facts(id),
  source_id uuid references sources(id),
  evidence_kind text not null,
  evidence_value jsonb not null default '{}'::jsonb,
  confidence numeric(4,3) not null default 1.0,
  supports_conclusion boolean,
  conflict_reason text,
  created_at timestamptz not null default now()
);

create table if not exists version_match_cache (
  id uuid primary key default gen_random_uuid(),
  ecosystem text not null,
  package_identity text,
  version text not null,
  range_hash text not null,
  resolver_plugin text not null,
  result boolean,
  explanation_json jsonb not null default '{}'::jsonb,
  expires_at timestamptz
);

create table if not exists plugin_manifests (
  id uuid primary key default gen_random_uuid(),
  plugin_name text not null unique,
  plugin_version text not null,
  manifest_json jsonb not null,
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists plugin_runs (
  id uuid primary key default gen_random_uuid(),
  plugin_name text not null,
  capability text not null,
  operation text not null,
  status text not null,
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  duration_ms integer,
  input_hash text,
  output_hash text,
  error_message text
);

create index if not exists ix_vuln_search_text on vulnerabilities using gin(search_text);
create index if not exists ix_vuln_identifiers on vulnerabilities using gin(identifiers);
create index if not exists ix_vuln_affected_names on vulnerabilities using gin(affected_component_names);
create index if not exists ix_vuln_title_trgm on vulnerabilities using gin(title gin_trgm_ops);
create index if not exists ix_vuln_modified on vulnerabilities(modified_at desc nulls last);
create index if not exists ix_vuln_published on vulnerabilities(published_at desc nulls last);
create index if not exists ix_vuln_sort on vulnerabilities((coalesce(max_cvss_score, 0)) desc, modified_at desc nulls last);
create index if not exists ix_vuln_cvss_identifier_filter on vulnerabilities((coalesce(max_cvss_score, 0)) desc, modified_at desc nulls last, primary_identifier);
create index if not exists ix_records_vulnerability_detail on vulnerability_records(vulnerability_id, source_id, updated_at desc);
create index if not exists ix_severity_vuln_system_version on vulnerability_severity_scores(vulnerability_id, scoring_system, scoring_version);
create index if not exists ix_severity_selected on vulnerability_severity_scores(vulnerability_id) where is_selected = true;
create index if not exists ix_weaknesses_vulnerability on vulnerability_weaknesses(vulnerability_id, source_id);
create index if not exists ix_refs_vulnerability on vulnerability_references(vulnerability_id, source_id);
create index if not exists ix_vuln_source_property_key on vulnerability_source_properties(source_id, property_namespace, property_key);
create index if not exists ix_vuln_detail_blocks on vulnerability_detail_blocks(vulnerability_id, display_order);
create index if not exists ix_stg_exploit_pocs_identifiers on stg_exploit_pocs using gin(identifiers);
create index if not exists ix_stg_exploit_pocs_provider on stg_exploit_pocs(provider, modified_at desc);
create index if not exists ix_stg_external_advisories_identifiers on stg_external_advisories using gin(identifiers);
create index if not exists ix_stg_external_advisories_provider on stg_external_advisories(provider, modified_at desc);
create index if not exists ix_component_identity_lookup on component_identity_index(identity_type, normalized_value);
create index if not exists ix_components_canonical_trgm on components using gin(canonical_name gin_trgm_ops);
create index if not exists ix_components_primary_purl_trgm on components using gin(primary_purl gin_trgm_ops) where primary_purl is not null;
create index if not exists ix_components_primary_cpe_trgm on components using gin(primary_cpe23_uri gin_trgm_ops) where primary_cpe23_uri is not null;
create index if not exists ix_components_identities_gin on components using gin(identities);
create index if not exists ix_registry_packages_name_trgm on registry_packages using gin(name gin_trgm_ops);
create index if not exists ix_registry_packages_namespace_trgm on registry_packages using gin(namespace gin_trgm_ops) where namespace is not null;
create index if not exists ix_registry_packages_purl_trgm on registry_packages using gin(purl_without_version gin_trgm_ops) where purl_without_version is not null;
create index if not exists ix_registry_packages_ecosystem_seen on registry_packages(lower(ecosystem), last_seen_at desc);
create index if not exists ix_affected_components_vuln on vulnerability_affected_components(vulnerability_id, ecosystem, display_name);
create index if not exists ix_affected_components_component on vulnerability_affected_components(component_id, vulnerability_id);
create index if not exists ix_affected_components_package_lower on vulnerability_affected_components(lower(package_name), lower(ecosystem), vulnerability_id) where package_name is not null;
create index if not exists ix_affected_components_display_lower on vulnerability_affected_components(lower(display_name), lower(ecosystem), vulnerability_id);
create index if not exists ix_affected_components_purl_prefix on vulnerability_affected_components(primary_purl text_pattern_ops, lower(ecosystem), vulnerability_id) where primary_purl is not null;
create index if not exists ix_affected_components_cpe_prefix on vulnerability_affected_components(primary_cpe23_uri text_pattern_ops, vulnerability_id) where primary_cpe23_uri is not null;
create index if not exists ix_affected_components_identity_match_v2 on vulnerability_affected_components(
  vulnerability_id,
  coalesce(ecosystem, ''),
  coalesce(display_name, ''),
  coalesce(primary_purl, ''),
  coalesce(primary_cpe23_uri, ''),
  coalesce(normalized_range, ''),
  coalesce(range_type, '')
);
create index if not exists ix_affected_facts_vuln on vulnerability_affected_facts(vulnerability_id, ecosystem, normalized_package_name);
create table if not exists stg_android_osv (
  raw_index_id uuid primary key references source_raw_index(id) on delete cascade,
  osv_id text not null,
  aliases text[] not null default '{}',
  affected jsonb not null default '[]'::jsonb,
  severity jsonb not null default '[]'::jsonb,
  summary text,
  details text,
  references_json jsonb not null default '[]'::jsonb,
  published_at timestamptz,
  modified_at timestamptz,
  payload jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists stg_npm_advisories (
  raw_index_id uuid primary key references source_raw_index(id) on delete cascade,
  ghsa_id text not null,
  cve_id text,
  ecosystem text not null default 'npm',
  package_name text,
  severity text,
  summary text,
  description text,
  vulnerable_ranges jsonb not null default '[]'::jsonb,
  patched_versions jsonb not null default '[]'::jsonb,
  cvss jsonb not null default '{}'::jsonb,
  cwes jsonb not null default '[]'::jsonb,
  references_json jsonb not null default '[]'::jsonb,
  published_at timestamptz,
  updated_at timestamptz,
  payload jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists stg_pypi_advisories (
  raw_index_id uuid primary key references source_raw_index(id) on delete cascade,
  pysec_id text not null,
  aliases text[] not null default '{}',
  ecosystem text not null default 'PyPI',
  package_name text,
  summary text,
  details text,
  affected jsonb not null default '[]'::jsonb,
  severity jsonb not null default '[]'::jsonb,
  references_json jsonb not null default '[]'::jsonb,
  published_at timestamptz,
  modified_at timestamptz,
  payload jsonb not null,
  created_at timestamptz not null default now()
);

insert into sources (code, name, kind, homepage_url, plugin_name, schedule_cron)
values
  ('nvd-cve', 'NVD CVE API/Data Feed', 'vulnerability', 'https://nvd.nist.gov/vuln/data-feeds', 'nvd', '0 */6 * * *'),
  ('nvd-cve-init', 'NVD CVE Mirror Baseline', 'vulnerability', 'https://github.com/fkie-cad/nvd-json-data-feeds', 'nvd', null),
  ('nvd-cpe', 'NVD CPE Dictionary', 'cpe', 'https://nvd.nist.gov/products/cpe', 'nvd', '0 2 * * *'),
  ('ghsa', 'GitHub Security Advisories', 'vulnerability', 'https://github.com/advisories', 'ghsa', '0 */6 * * *'),
  ('osv', 'OSV.dev Modified IDs', 'vulnerability', 'https://osv.dev', 'osv', '0 */6 * * *'),
  ('osv-init', 'OSV.dev Full Baseline', 'vulnerability', 'https://osv.dev', 'osv', null),
  ('cve-list-v5', 'CVE List v5', 'vulnerability', 'https://github.com/CVEProject/cvelistV5', 'cve-list', null),
  ('cisa-kev', 'CISA Known Exploited Vulnerabilities', 'threat_intel', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'threat-intel', '0 */12 * * *'),
  ('first-epss', 'FIRST EPSS', 'threat_intel', 'https://www.first.org/epss/', 'threat-intel', '0 4 * * *'),
  ('exploitdb', 'Exploit-DB Public Exploits', 'exploit', 'https://www.exploit-db.com/', 'exploit-intel', '0 */12 * * *'),
  ('metasploit', 'Metasploit Framework Modules', 'exploit', 'https://github.com/rapid7/metasploit-framework', 'exploit-intel', '0 */12 * * *'),
  ('nuclei-templates', 'ProjectDiscovery Nuclei Templates', 'exploit', 'https://github.com/projectdiscovery/nuclei-templates', 'exploit-intel', '0 */12 * * *'),
  ('poc-in-github', 'PoC-in-GitHub CVE Repository Index', 'exploit', 'https://github.com/nomi-sec/PoC-in-GitHub', 'exploit-intel', '0 */12 * * *'),
  ('trickest-cve', 'Trickest CVE PoC Index', 'exploit', 'https://github.com/trickest/cve', 'exploit-intel', '0 */12 * * *'),
  ('cnnvd', 'CNNVD 国家信息安全漏洞库', 'vulnerability', 'https://www.cnnvd.org.cn/home/loophole', 'china-advisory', '0 */6 * * *'),
  ('cnvd', 'CNVD 国家信息安全漏洞共享平台', 'vulnerability', 'https://www.cnvd.org.cn/flaw/list', 'china-advisory', null),
  ('seebug', 'Seebug 漏洞平台', 'vulnerability', 'https://www.seebug.org/vuldb/vulnerabilities', 'china-advisory', null),
  ('aliyun-avd', '阿里云漏洞库 AVD', 'vulnerability', 'https://avd.aliyun.com/', 'china-advisory', null),
  ('nsfocus-vulndb', '绿盟科技 NSFOCUS 漏洞库', 'vulnerability', 'https://www.nsfocus.net/index.php?act=sec_bug', 'china-advisory', null),
  ('chaitin-vuldb', '长亭漏洞库', 'vulnerability', 'https://stack.chaitin.com/vuldb/index', 'china-advisory', null),
  ('cert-360', '360CERT 安全通告', 'threat_intel', 'https://cert.360.cn/warning', 'china-advisory', null),
  ('alpine-secdb', 'Alpine SecDB', 'vulnerability', 'https://secdb.alpinelinux.org/', 'alpine', '0 4 * * *'),
  ('debian-security-tracker', 'Debian Security Tracker', 'vulnerability', 'https://security-tracker.debian.org/', 'debian', '0 4 * * *'),
  ('ubuntu-osv', 'Ubuntu OSV', 'vulnerability', 'https://documentation.ubuntu.com/security/security-updates/osv/', 'ubuntu', '0 4 * * *'),
  ('android-osv', 'Android Security Bulletins (OSV)', 'vulnerability', 'https://source.android.com/docs/security/bulletin', 'android', '0 6 * * *'),
  ('android-osv-init', 'Android OSV Baseline', 'vulnerability', 'https://osv.dev', 'android', null),
  ('npm-advisory', 'npm Advisory Database', 'vulnerability', 'https://github.com/advisories?query=ecosystem:npm', 'npm', '0 */6 * * *'),
  ('npm-audit', 'npm Registry Audit Advisory API', 'vulnerability', 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk', 'npm', '0 */6 * * *'),
  ('pypi-advisory', 'PyPI Advisory Database (PyPA)', 'vulnerability', 'https://github.com/pypa/advisory-database', 'pypi', '0 6 * * *'),
  ('go-advisory', 'Go Vulnerability Database', 'vulnerability', 'https://github.com/golang/vulndb', 'go', '0 6 * * *'),
  ('cargo-advisory', 'RustSec Advisory DB', 'vulnerability', 'https://github.com/rustsec/advisory-db', 'cargo', '0 6 * * *'),
  ('nuget-advisory', 'NuGet VulnerabilityInfo', 'vulnerability', 'https://api.nuget.org/v3/vulnerabilities/index.json', 'nuget', '0 6 * * *'),
  ('maven-advisory', 'Maven Vulnerability Lookup', 'vulnerability', 'https://ossindex.sonatype.org/', 'maven', '0 6 * * *'),
  ('maven-osv', 'Maven OSV Modified IDs', 'vulnerability', 'https://osv.dev', 'maven', '0 6 * * *'),
  ('maven-osv-init', 'Maven OSV Baseline', 'vulnerability', 'https://osv.dev', 'maven', null),
  ('google-osv', 'Google OSV Ecosystems', 'vulnerability', 'https://osv.dev', 'google', '0 6 * * *'),
  ('google-osv-init', 'Google OSV Baseline', 'vulnerability', 'https://osv.dev', 'google', null),
  ('redhat-csaf', 'Red Hat Security Data CSAF', 'vulnerability', 'https://access.redhat.com/security/data/csaf', 'redhat', '0 4 * * *'),
  ('suse-csaf', 'SUSE Security CSAF', 'vulnerability', 'https://ftp.suse.com/pub/projects/security/csaf/', 'suse', '0 4 * * *'),
  ('npm-registry', 'npm Registry Metadata', 'registry', 'https://registry.npmjs.org/', 'registry', null),
  ('pypi-registry', 'PyPI Package Metadata', 'registry', 'https://pypi.org/pypi/', 'registry', null),
  ('maven-registry', 'Maven Central Metadata', 'registry', 'https://search.maven.org/', 'registry', null),
  ('nuget-registry', 'NuGet Package Metadata', 'registry', 'https://api.nuget.org/v3/', 'registry', null),
  ('rubygems-registry', 'RubyGems Package Metadata', 'registry', 'https://rubygems.org/api/v1/gems/', 'registry', null),
  ('packagist-registry', 'Packagist Package Metadata', 'registry', 'https://repo.packagist.org/p2/', 'registry', null),
  ('crates-registry', 'crates.io Package Metadata', 'registry', 'https://crates.io/api/v1/crates/', 'registry', null)
on conflict (code) do update set
  name = excluded.name,
  kind = excluded.kind,
  homepage_url = excluded.homepage_url,
  plugin_name = excluded.plugin_name,
  schedule_cron = excluded.schedule_cron,
  config_json = case
    when sources.code in ('cve-list-v5', 'nvd-cve-init', 'osv-init', 'android-osv-init', 'maven-osv-init', 'google-osv-init') then jsonb_set(sources.config_json, '{runMode}', '"init"', true)
    else sources.config_json
  end,
  updated_at = now();

update sources
set config_json = jsonb_set(config_json, '{runMode}', '"init"', true),
    schedule_cron = null,
    updated_at = now()
where code in ('cve-list-v5', 'nvd-cve-init', 'osv-init', 'android-osv-init', 'maven-osv-init', 'google-osv-init');

update sources
set config_json = config_json - 'runMode',
    updated_at = now()
where code in ('osv', 'maven-osv');

update sources
set enabled = false,
    schedule_cron = null,
    config_json = jsonb_set(config_json, '{runMode}', '"manual"', true),
    updated_at = now()
where code in ('cnvd', 'seebug', 'aliyun-avd', 'nsfocus-vulndb', 'chaitin-vuldb', 'cert-360');
