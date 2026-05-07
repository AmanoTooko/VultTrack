# 模块设计: Component Matcher

## 1. 职责

Component Matcher 负责将 PURL、CPE、包名、repo、发行版包映射到统一 component，并聚合受影响组件。

## 2. 对外接口

```csharp
public interface IComponentMatcher
{
    Task<ComponentMatchResult> MatchAffectedFactAsync(Guid affectedFactId, CancellationToken ct);
    Task<AggregateAffectedResult> AggregateAffectedAsync(Guid vulnerabilityId, CancellationToken ct);
    Task<IReadOnlyList<ComponentCandidateDto>> SearchComponentAsync(ComponentSearchQuery query, CancellationToken ct);
}
```

## 3. 核心逻辑

### 3.1 identity 匹配

```text
normalize purl/cpe/name/repo
exact lookup component_identity_index
if no exact:
  create candidate component
  create component_mapping_edge
score by evidence
write component_id back to affected_fact when approved/high confidence
```

### 3.2 affected 聚合

```text
load affected_facts for vulnerability
group by component_id/ecosystem/package
call version resolver when range needs normalization
collect evidence
resolve canonical range:
  trusted source
  resolver-compatible merge
  majority/strictest only if no conflict
  llm evidence as supporting signal
write vulnerability_affected_components
write vulnerability_affected_evidence
update vulnerabilities affected projection
```

## 4. 冲突处理

- `<1.11` + `=1.11` 不自动变 `<=1.11`。
- LLM `<=1.11` 只能作为 evidence。
- 冲突时 `resolution_status = conflicted`。
- 人工确认后 `selected_by_rule = manual`，后续自动重算不能覆盖，只能提示 conflict。

## 5. 独立测试

冒烟测试:

- PURL affected fact 匹配到 component。
- vulnerability affected projection 更新。

模块测试:

- CPE/PURL 同 CVE 重叠生成 candidate edge。
- LLM evidence 不会单独 confirm。
- conflicted range 正确标记。

集成测试:

- GHSA affected package + NVD CPE + LLM evidence 聚合为一个 affected component with evidence。

