-- SBOM Management Tables

create table if not exists sbom_uploads (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  format text not null default 'cyclonedx',
  version text,
  metadata jsonb not null default '{}',
  component_count int not null default 0,
  matched_count int not null default 0,
  uploaded_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists sbom_components (
  id uuid primary key default gen_random_uuid(),
  sbom_id uuid not null references sbom_uploads(id) on delete cascade,
  purl text,
  name text,
  version text,
  ecosystem text,
  group_name text,
  vendor text,
  product text,
  cpe23_uri text,
  source_package_name text,
  source_package_version text,
  component_type text,
  metadata jsonb not null default '{}',
  vuln_count int not null default 0,
  created_at timestamptz not null default now()
);

create index if not exists ix_sbom_components_sbom on sbom_components(sbom_id);
create index if not exists ix_sbom_components_purl on sbom_components(purl) where purl is not null;
create index if not exists ix_sbom_components_cpe on sbom_components(cpe23_uri) where cpe23_uri is not null;

create table if not exists sbom_vulnerabilities (
  id uuid primary key default gen_random_uuid(),
  sbom_component_id uuid not null references sbom_components(id) on delete cascade,
  vulnerability_id uuid not null references vulnerabilities(id),
  purl text,
  display_name text,
  ecosystem text,
  normalized_range text,
  version_matched boolean,
  match_basis text,
  matched_version text,
  created_at timestamptz not null default now(),
  unique(sbom_component_id, vulnerability_id)
);

create index if not exists ix_sbom_vulns_component on sbom_vulnerabilities(sbom_component_id);
create index if not exists ix_sbom_vulns_vuln on sbom_vulnerabilities(vulnerability_id);
