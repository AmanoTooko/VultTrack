# 插件设计: NVD

## 1. 范围

插件名: `nvd`  
sources:

- `nvd-cve`
- `nvd-cpe`

capabilities:

- `source-fetcher`
- `source-parser`
- `source-detail-renderer`

## 2. 输入

环境变量:

```text
NVD_API_KEY
```

source config:

```json
{
  "mode": "api-or-feed",
  "baseUrl": "https://services.nvd.nist.gov/rest/json",
  "useApiKey": true,
  "pageSize": 2000
}
```

## 3. 输出 staging

`stg_nvd_cves`:

```text
cve_id
vuln_status
descriptions
metrics
weaknesses
configurations
references_json
published_at
modified_at
cisa_exploit_add
cisa_action_due
```

`stg_nvd_cpe_dictionary`:

```text
cpe23_uri
part
vendor
product
version
target_sw
titles
refs
deprecated
last_modified_at
```

## 4. 解析逻辑

- CVE ID 进入 identifier。
- `metrics.cvssMetricV40/V31/V30/V2` 全部进入 severity scores。
- `weaknesses` 进入 CWE facts。
- `references` 进入 reference facts。
- `configurations.nodes[].cpeMatch` 进入 affected facts，`fact_type = cpe`。
- CISA 字段进入 vulnerability projection 和 source property。

## 5. Detail Blocks

生成:

- `nvd.configurations`: tree block。
- `nvd.cvss`: table block。
- `nvd.references`: table block。

## 6. 独立测试

冒烟:

- fixture CVE 解析出 CVE identifier、CVSS、CPE affected fact。

集成:

- NVD CVE + GHSA 同 CVE 合并到一个 vulnerability。

