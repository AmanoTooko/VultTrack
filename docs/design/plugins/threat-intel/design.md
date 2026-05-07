# 插件设计: Threat Intel

## 1. 范围

插件名: `threat-intel`  
sources:

- `cisa-kev`
- `first-epss`

capabilities:

- `source-fetcher`
- `source-parser`

## 2. CISA KEV

staging:

```text
stg_threat_intel_records
- provider = cisa-kev
- identifier = CVE-...
- payload_json
- observed_at
```

解析:

- CVE 进入 identifier index。
- `dateAdded` -> `vulnerabilities.kev_date_added`。
- `knownRansomwareCampaignUse` -> `known_ransomware`。
- `requiredAction` -> source property。

## 3. FIRST EPSS

staging:

```text
stg_threat_intel_records
- provider = first-epss
- identifier = CVE-...
- epss_score
- epss_percentile
- observed_at
```

解析:

- CVE 进入 identifier index。
- 最新 EPSS 投影到 `vulnerabilities.epss_score`。
- 历史可选写 time-series 表，MVP 只保留 latest。

## 4. 独立测试

冒烟:

- KEV fixture 设置 kev flag。
- EPSS fixture 设置 epss score。

集成:

- NVD CVE ingest 后，Threat Intel 更新同一 vulnerability risk projection。

