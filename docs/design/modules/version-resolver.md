# 模块设计: Version Resolver

## 1. 职责

Version Resolver 对不同生态版本进行规范化、比较和范围判断。

Resolver 是插件化的，因为 npm、PyPI、Maven、RPM、Debian 版本规则不同。

## 2. 对外接口

```csharp
public interface IVersionResolverCore
{
    Task<NormalizedVersionDto> NormalizeAsync(string ecosystem, string version, CancellationToken ct);
    Task<VersionCompareResult> CompareAsync(string ecosystem, string left, string right, CancellationToken ct);
    Task<VersionContainsResult> ContainsAsync(VersionContainsRequest request, CancellationToken ct);
}
```

插件接口:

```ts
export interface VersionResolverPlugin {
  normalizeVersion(input: string): Promise<NormalizedVersion>;
  compare(a: string, b: string): Promise<-1 | 0 | 1>;
  contains(range: VersionRange, version: string): Promise<boolean>;
  explain?(range: VersionRange, version: string): Promise<ResolverExplanation>;
}
```

## 3. 缓存键

```text
ecosystem + package_identity + version + range_hash + resolver_plugin_version
```

## 4. 降级策略

- resolver 插件失败: 标记 `resolver_failed`，不静默确认。
- semver-like 生态可降级 generic-semver。
- RPM/Debian/Maven 禁止错误降级为 semver confirmed。

## 5. 独立测试

冒烟测试:

- npm resolver 判断 `1.2.0` in `<2.0.0`。

模块测试:

- PyPI normalize 遵守 PEP 440 fixture。
- Maven snapshot/prerelease 比较 fixture。
- resolver 超时返回 retryable plugin error。

集成测试:

- affected aggregation 调用 resolver 并写入 cache。

