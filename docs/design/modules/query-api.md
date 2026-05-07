# 模块设计: Query API

## 1. 职责

Query API 负责将 normalized 表聚合成前端可用的 DTO。API 使用 RPC 风格路径，只允许 `GET` 和 `POST`。

## 2. 对外接口

HTTP API 详见 [../contracts/api-rpc.md](../contracts/api-rpc.md)。

内部接口:

```csharp
public interface IVulnerabilityQueryService
{
    Task<PagedResult<VulnerabilityListItemDto>> SearchAsync(VulnerabilitySearchRequest request, CancellationToken ct);
    Task<VulnerabilityDetailDto?> GetAsync(Guid id, CancellationToken ct);
    Task<VulnerabilityDetailDto?> GetByIdentifierAsync(string identifier, CancellationToken ct);
    Task<IReadOnlyList<AffectedComponentDto>> GetAffectedComponentsAsync(Guid vulnerabilityId, CancellationToken ct);
    Task<IReadOnlyList<AffectedEvidenceDto>> GetAffectedEvidenceAsync(Guid affectedComponentId, CancellationToken ct);
}
```

## 3. 详情页 DTO

```json
{
  "id": "uuid",
  "primaryIdentifier": "CVE-2024-0001",
  "title": "...",
  "description": "...",
  "severity": {},
  "identifiers": [],
  "affectedComponents": [],
  "detailBlocks": [],
  "sources": []
}
```

## 4. 查询策略

- identifier 精确查询走 `vulnerability_identifier_index.normalized_value`。
- 列表搜索走 `vulnerabilities.search_text` 和 trigram。
- 详情受影响组件读 `vulnerability_affected_components`。
- 展开证据时才读 `vulnerability_affected_evidence`。
- raw payload 必须单独权限检查。

## 5. 独立测试

冒烟测试:

- `vulnerability.search` 返回分页。
- `vulnerability.get` 返回 affected components。

模块测试:

- 无权限用户不能读取 raw payload。
- identifier 查询 CVE/GHSA 命中同一漏洞。
- detail blocks 按 display_order 排序。

集成测试:

- 从 fixture ingest 到 API 查询全链路。

