# 模块设计: Plugin Runtime

## 1. 职责

Plugin Runtime 负责执行 Node.js/TypeScript 插件，并保护核心服务:

- 读取插件 manifest。
- 校验插件类型和版本。
- 将请求 JSON 写入 stdin。
- 读取 stdout JSON response。
- 收集 stderr structured logs。
- 限制超时、并发、输出大小、临时目录。
- 失败隔离和错误分类。

## 2. 插件类型

```text
source-fetcher
source-parser
source-detail-renderer
version-resolver
component-matcher
llm-matcher
```

## 3. 插件 manifest

```json
{
  "name": "nvd",
  "version": "0.1.0",
  "entry": "dist/index.js",
  "runtime": "node",
  "capabilities": ["source-fetcher", "source-parser", "source-detail-renderer"],
  "sources": ["nvd-cve", "nvd-cpe"],
  "timeoutSeconds": 120,
  "maxStdoutBytes": 10485760
}
```

## 4. 对外接口

```csharp
public interface IPluginRuntime
{
    Task<PluginResult<TResponse>> ExecuteAsync<TRequest, TResponse>(
        PluginCall<TRequest> call,
        CancellationToken ct);
}

public sealed record PluginCall<TRequest>(
    string PluginName,
    string Capability,
    string Operation,
    TRequest Payload,
    TimeSpan Timeout);
```

## 5. stdin/stdout 协议

请求:

```json
{
  "protocolVersion": "1.0",
  "operation": "fetch",
  "source": "nvd-cve",
  "checkpoint": {},
  "config": {},
  "payload": {}
}
```

响应:

```json
{
  "protocolVersion": "1.0",
  "status": "ok",
  "items": [],
  "warnings": [],
  "checkpoint": {},
  "detailBlocks": [],
  "metrics": {}
}
```

## 6. 安全要求

- 插件目录只读。
- 临时目录按 run id 隔离，结束后清理。
- 只传白名单环境变量。
- stdout 必须是单个 JSON object。
- detail renderer 不允许输出 HTML/JS。
- 大 payload 通过 object uri 传递，不通过 stdin 传递。

## 7. 独立测试

冒烟测试:

- 执行 echo fixture 插件，返回 ok。
- 执行超时插件，返回 timeout error。

模块测试:

- stdout 超限被截断并失败。
- 非 JSON stdout 被识别为 protocol error。
- stderr structured log 被保存。

集成测试:

- 调用 NVD fixture 插件，生成 staging envelope。

