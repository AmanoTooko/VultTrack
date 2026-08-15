# VulTrack 数据库参考

> **历史文档（PG-first）**：本文记录已移除的 PostgreSQL/Adminer/staging 方案，
> 不能用于当前部署或运维。当前数据库事实以
> `docs/design/duckdb-first-architecture.md` 和 `DuckDbEvidenceStore.Schema.cs` 为准。

## 连接信息

| 参数 | 值 |
|------|-----|
| Host | `localhost` |
| Port | `5432` |
| Database | `vultrack` |
| User | `vultrack` |
| Password | `vultrack` |
| URL | `postgres://vultrack:vultrack@localhost:5432/vultrack` |

## Docker 启动

```bash
docker compose up -d postgres
```

PostgreSQL 容器名: `vultrack-postgres`

## 表结构 (共 38 张表)

### 1. 采集层 (Ingest)

| 表名 | 说明 | 关键字段 |
|------|------|---------|
| `sources` | 数据源定义 (11 个源) | `code`, `kind`, `plugin_name`, `schedule_cron`, `enabled` |
| `source_sync_runs` | 同步运行记录 | `source_id`, `status`, `fetched_count`, `log_summary` |
| `source_task_errors` | 任务错误日志 | `stage`, `error_code`, `error_message` |
| `source_objects` | 压缩后的原始对象索引 | `object_uri`, `sha256`, `compression`, `size_bytes` |
| `source_raw_index` | 原始记录索引 (去重键: source_id+external_key+record_hash) | `external_key`, `external_id`, `identifier_summary`, `normalize_status` |

### 2. Staging 表 (按来源分)

| 表名 | 来源 | 关键字段 |
|------|------|---------|
| `stg_nvd_cves` | NVD CVE API | `cve_id`, `descriptions`, `metrics`, `configurations`, `payload` |
| `stg_nvd_cpe_dictionary` | NVD CPE Dict | `cpe23_uri`, `vendor`, `product`, `version`, `payload` |
| `stg_ghsa_advisories` | GitHub Advisories | `ghsa_id`, `cve_id`, `ecosystem`, `package_name`, `payload` |
| `stg_osv_vulnerabilities` | OSV.dev | `osv_id`, `aliases`, `affected`, `severity`, `payload` |
| `stg_cve_list_records` | CVE List v5 | `cve_id`, `cve_metadata`, `containers_cna`, `containers_adp`, `payload` |
| `stg_threat_intel_records` | CISA KEV + FIRST EPSS | `provider`, `identifier`, `epss_score`, `epss_percentile`, `payload` |
| `stg_alpine_secdb` | Alpine Linux | `distro_release`, `package_name`, `identifiers`, `secfixes`, `payload` |
| `stg_debian_security_tracker` | Debian | `cve_id`, `packages`, `payload` |
| `stg_ubuntu_osv` | Ubuntu | `osv_id`, `aliases`, `affected`, `payload` |
| `stg_registry_packages` | Registry (npm 等) | `registry`, `ecosystem`, `name`, `purl`, `payload` |

### 3. 漏洞规范化表

| 表名 | 说明 |
|------|------|
| `vulnerabilities` | Canonical 漏洞投影表 (查询用) |
| `vulnerability_records` | 各来源的漏洞记录 |
| `vulnerability_identifier_index` | Identifier 查找索引 (CVE/GHSA/OSV → canonical vuln) |
| `vulnerability_identifier_groups` | Identifier 合并组 |
| `vulnerability_identifier_edges` | Identifier 关联边 (strong/medium/weak) |
| `vulnerability_severity_scores` | CVSS/vendor 严重性评分 |
| `vulnerability_descriptions` | 多来源描述 |
| `vulnerability_weaknesses` | CWE 弱点 |
| `vulnerability_references` | 参考链接 |
| `vulnerability_source_properties` | 来源特有属性 (typed key-value) |
| `vulnerability_detail_blocks` | 详情页渲染块 (JSON, 无 HTML) |

### 4. 受影响组件表

| 表名 | 说明 |
|------|------|
| `vulnerability_affected_facts` | 来源级受影响事实 |
| `vulnerability_affected_components` | Canonical 受影响组件聚合 |
| `vulnerability_affected_evidence` | 受影响组件证据链 |

### 5. 组件表

| 表名 | 说明 |
|------|------|
| `components` | 统一组件 |
| `component_identity_index` | 组件身份索引 (PURL/CPE/repo) |
| `component_mapping_edges` | 组件映射边 (CPE↔PURL↔repo) |
| `cpe_entries` | CPE 条目 |
| `registry_packages` | 包管理器元数据 |
| `purl_name_mappings` | PURL 名称映射规则 |
| `version_match_cache` | 版本比对缓存 |

### 6. 插件表

| 表名 | 说明 |
|------|------|
| `plugin_manifests` | 插件注册 |
| `plugin_runs` | 插件运行记录 |

## Seeds (11 个内置数据源)

| code | kind | plugin |
|------|------|--------|
| `nvd-cve` | vulnerability | nvd |
| `nvd-cpe` | cpe | nvd |
| `ghsa` | vulnerability | ghsa |
| `osv` | vulnerability | osv |
| `cve-list-v5` | vulnerability | cve-list |
| `cisa-kev` | threat_intel | threat-intel |
| `first-epss` | threat_intel | threat-intel |
| `alpine-secdb` | vulnerability | alpine |
| `debian-security-tracker` | vulnerability | debian |
| `ubuntu-osv` | vulnerability | ubuntu |
| `npm-registry` | registry | registry |

## 常用查询

```sql
-- 查看所有同步运行记录
select s.code, r.status, r.fetched_count, r.error_count, r.started_at, r.finished_at
from source_sync_runs r join sources s on s.id = r.source_id
order by r.started_at desc;

-- 查看各 staging 表记录数
select 'stg_nvd_cves' as t, count(*) from stg_nvd_cves union all
select 'stg_nvd_cpe_dict', count(*) from stg_nvd_cpe_dictionary union all
select 'stg_ghsa', count(*) from stg_ghsa_advisories union all
select 'stg_osv', count(*) from stg_osv_vulnerabilities union all
select 'stg_cve_list', count(*) from stg_cve_list_records union all
select 'stg_threat_intel', count(*) from stg_threat_intel_records union all
select 'stg_alpine', count(*) from stg_alpine_secdb union all
select 'stg_debian', count(*) from stg_debian_security_tracker union all
select 'stg_ubuntu', count(*) from stg_ubuntu_osv;

-- 查看存储使用
select count(*), sum(size_bytes)/1024/1024 as mb from source_objects;

-- 查看任务错误
select * from source_task_errors order by created_at desc limit 20;

-- 查看 running 同步
select s.code, r.status from source_sync_runs r join sources s on s.id=r.source_id where r.status='running';
```

## Web UI 访问

Adminer: http://localhost:8081
- System: PostgreSQL
- Server: postgres
- Username: vultrack
- Password: vultrack
- Database: vultrack
