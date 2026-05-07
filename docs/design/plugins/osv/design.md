# 插件设计: OSV

## 1. 范围

插件名: `osv`  
source: `osv`

capabilities:

- `source-fetcher`
- `source-parser`
- `source-detail-renderer`

## 2. 输出 staging

`stg_osv_vulnerabilities`:

```text
osv_id
aliases
related
summary
details
affected
severity
references_json
published_at
modified_at
```

## 3. 解析逻辑

- `id` 和 `aliases[]` 进入 identifier index，aliases edge strength = strong。
- `related[]` 进入 identifier edge，strength = medium。
- `affected[].package.purl` 进入 affected fact。
- `affected[].ranges` 进入 version range raw。
- `affected[].versions` 进入 affected_versions。
- `severity[]` 进入 severity scores。
- `references[]` 进入 reference facts。

## 4. Detail Blocks

- `osv.affected`: table block。
- `osv.references`: table block。

## 5. 独立测试

冒烟:

- fixture OSV 生成 OSV ID、aliases、affected purl。

集成:

- OSV alias 和 NVD CVE 合并。

