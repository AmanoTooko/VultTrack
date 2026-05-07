# 插件设计: GHSA

## 1. 范围

插件名: `ghsa`  
source: `ghsa`

capabilities:

- `source-fetcher`
- `source-parser`
- `source-detail-renderer`

## 2. 输入

环境变量:

```text
GITHUB_TOKEN
```

source config:

```json
{
  "mode": "api-or-advisory-database",
  "ecosystems": ["maven", "npm", "pip", "rubygems", "nuget", "go", "rust", "composer"]
}
```

## 3. 输出 staging

`stg_ghsa_advisories`:

```text
ghsa_id
cve_id
identifiers
summary
description
ecosystem
package_name
vulnerable_ranges
patched_versions
cvss
cwes
references_json
published_at
updated_at
```

## 4. 解析逻辑

- GHSA ID 和 CVE ID 进入 identifier，edge strength = strong。
- `vulnerabilities[].package` 进入 affected fact，优先生成 PURL。
- `vulnerable_version_range` 保留 raw，并交给对应 resolver 规范化。
- patched versions 进入 fixed versions。
- CVSS 进入 severity scores，source = ghsa。
- CWE 进入 weakness facts。

## 5. Detail Blocks

- `ghsa.package_ranges`: table block。
- `ghsa.cvss`: key_value block。
- `ghsa.references`: table block。

## 6. 独立测试

冒烟:

- fixture GHSA 生成 GHSA identifier、CVE alias、PURL affected fact。

集成:

- GHSA package range 经 resolver 判断 PURL version 命中。

