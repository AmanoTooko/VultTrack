# 模块设计: Identifier Linker

## 1. 职责

Identifier Linker 将 CVE、GHSA、OSV、BDSA、USN、RHSA 等 identifier 预计算为 canonical vulnerability。

目标:

- 查询时不递归遍历图。
- 任意 identifier 一次 lookup 找到 canonical vulnerability。
- 保留 merge evidence，支持人工拆分和重算。

## 2. 对外接口

```csharp
public interface IIdentifierLinker
{
    Task<LinkResult> LinkRecordAsync(Guid vulnerabilityRecordId, CancellationToken ct);
    Task<RebuildResult> RebuildGroupsAsync(CancellationToken ct);
    Task<VulnerabilityId?> ResolveAsync(string identifier, CancellationToken ct);
}
```

## 3. 核心逻辑

```text
extract identifiers from vulnerability_record facts
normalize identifier values
create identifier_index rows
create identifier_edges with strength
run union-find for strong edges
assign identifier_group_id
upsert vulnerabilities canonical row
write canonical_vulnerability_id back to identifier_index
```

## 4. Edge 强度规则

strong:

- OSV aliases。
- GHSA identifiers 中 GHSA/CVE。
- NVD 和 CVE List 同 CVE ID。
- 发行版 advisory 明确列出的 CVE。

medium:

- reference URL 指向另一个 advisory。
- BDSA 引用 GHSA 但没有明确 same vulnerability。

weak:

- description 抽取出的 ID。
- 外部网页互链。

只有 strong 自动合并。medium/weak 只作为证据和搜索辅助。

## 5. 独立测试

冒烟测试:

- 输入 GHSA + CVE，查询 CVE 返回同一个 vulnerability。

模块测试:

- medium edge 不自动合并。
- union-find 重跑结果稳定。
- 人工拆分后不会被 weak edge 合并。

集成测试:

- NVD CVE + GHSA alias + OSV alias 三源合并为一个 canonical row。

