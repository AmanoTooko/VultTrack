# 模块设计: Normalization

## 1. 职责

Normalization 把 source-specific staging rows 转换为统一事实表。

负责:

- 创建/更新 `vulnerability_records`。
- 提取 identifiers。
- 提取 severity/CVSS。
- 提取 descriptions/CWE/references。
- 提取 affected facts。
- 写入 source-specific typed properties。
- 触发 identifier linking 和 affected aggregation。

## 2. 对外接口

```csharp
public interface INormalizationService
{
    Task<NormalizeResult> NormalizeRawIndexAsync(Guid rawIndexId, CancellationToken ct);
    Task<NormalizeBatchResult> NormalizePendingAsync(string sourceCode, int limit, CancellationToken ct);
}

public interface INormalizer
{
    string SourceCode { get; }
    Task<NormalizedEnvelope> NormalizeAsync(StagingRecord record, CancellationToken ct);
}
```

## 3. Normalized Envelope

```json
{
  "record": {
    "sourceRecordId": "GHSA-xxxx",
    "title": "...",
    "description": "...",
    "status": "active"
  },
  "identifiers": [],
  "severityScores": [],
  "descriptions": [],
  "weaknesses": [],
  "references": [],
  "affectedFacts": [],
  "properties": []
}
```

## 4. 核心逻辑

```text
load staging record
select normalizer by source_code/schema_version
build normalized envelope
validate envelope
upsert vulnerability_record
upsert fact tables
mark raw_index normalize_status = succeeded
enqueue identifier-link task
enqueue affected-aggregate task
enqueue detail-block task
```

## 5. 兼容策略

- 未识别字段进入 `vulnerability_records.source_specific`。
- 可查询但非核心字段进入 `vulnerability_source_properties`。
- 大型展示结构通过 detail block 插件生成。
- 任何来源字段不得直接导致 `vulnerabilities` 加列。

## 6. 独立测试

冒烟测试:

- GHSA fixture normalizes into one record, one identifier, one affected fact。

模块测试:

- CVSS v4/v3/v2 都写入 severity scores。
- 同一 rawIndex 重跑不重复写 facts。
- 未识别字段保留在 source_specific。

集成测试:

- OSV fixture -> normalized facts -> identifier-link task queued。

