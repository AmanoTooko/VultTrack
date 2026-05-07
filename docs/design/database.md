# 数据库初始化和 Schema 设计

## 1. 初始化顺序

PostgreSQL 初始化必须按以下顺序执行:

1. 创建数据库和用户。
2. 启用扩展。
3. 创建基础 schema 和 enum lookup 表。
4. 创建 source/raw/staging 表。
5. 创建 normalized fact 表。
6. 创建 identifier/component/affected 表。
7. 创建索引。
8. seed 内置 source 和插件 manifest。

## 2. 必需扩展

```sql
create extension if not exists pg_trgm;
create extension if not exists unaccent;
create extension if not exists btree_gin;
create extension if not exists pgcrypto;
```

## 3. Schema 分层

| schema | 内容 |
|---|---|
| `app` | 用户、权限、审计、系统配置 |
| `ingest` | source、sync run、raw object、raw index、staging |
| `vuln` | canonical vulnerability 和 normalized facts |
| `component` | component identity、PURL/CPE/repo 映射 |
| `plugin` | plugin manifest、plugin run、plugin error |

MVP 可以先使用单 schema `public`，但表名前缀需保持清晰。生产建议拆 schema。

## 4. 必备表清单

### 4.1 Ingestion

```text
sources
source_sync_runs
source_task_errors
source_objects
source_raw_index
stg_nvd_cves
stg_nvd_cpe_dictionary
stg_ghsa_advisories
stg_osv_vulnerabilities
stg_cve_list_records
stg_threat_intel_records
```

### 4.2 Vulnerability

```text
vulnerabilities
vulnerability_records
vulnerability_identifier_index
vulnerability_identifier_groups
vulnerability_identifier_edges
vulnerability_severity_scores
vulnerability_descriptions
vulnerability_weaknesses
vulnerability_references
vulnerability_source_properties
vulnerability_detail_blocks
vulnerability_affected_facts
vulnerability_affected_components
vulnerability_affected_evidence
normalization_schemas
source_field_mappings
```

### 4.3 Component

```text
components
component_identity_index
component_mapping_edges
cpe_entries
registry_packages
purl_name_mappings
version_match_cache
```

### 4.4 Plugin

```text
plugin_manifests
plugin_runs
plugin_run_logs
```

## 5. 核心索引

```sql
create unique index ux_raw_source_external_hash
  on source_raw_index(source_id, external_key, record_hash);

create index ix_raw_identifier_summary
  on source_raw_index using gin(identifier_summary);

create unique index ux_identifier_normalized_source
  on vulnerability_identifier_index(identifier_type, normalized_value, source_id, raw_index_id);

create index ix_identifier_lookup
  on vulnerability_identifier_index(normalized_value, canonical_vulnerability_id);

create index ix_vuln_search_text
  on vulnerabilities using gin(search_text);

create index ix_vuln_identifiers
  on vulnerabilities using gin(identifiers);

create index ix_vuln_affected_names
  on vulnerabilities using gin(affected_component_names);

create index ix_affected_components_vuln
  on vulnerability_affected_components(vulnerability_id, ecosystem, display_name);

create index ix_affected_components_component
  on vulnerability_affected_components(component_id, vulnerability_id);

create index ix_component_identity_lookup
  on component_identity_index(identity_type, normalized_value);

create index ix_component_identity_trgm
  on component_identity_index using gin(normalized_value gin_trgm_ops);
```

## 6. Seed 数据

MVP seed sources:

```text
nvd-cve
nvd-cpe
ghsa
osv
cve-list-v5
cisa-kev
first-epss
```

每个 source seed 字段:

```json
{
  "code": "nvd-cve",
  "name": "NVD CVE API/Data Feed",
  "kind": "vulnerability",
  "enabled": true,
  "plugin_name": "nvd",
  "schedule_cron": "0 */6 * * *",
  "config_json": {}
}
```

## 7. Migration 规则

- 只允许向前迁移。
- migration 必须可重复运行到空库。
- staging schema 变化优先增加列或 JSONB，不删除旧列。
- source-specific 字段默认不迁移进核心表。
- 所有 projection 字段必须有 rebuild job。

