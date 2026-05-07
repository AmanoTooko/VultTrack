# 模块设计: Core App

## 1. 职责

Core App 是 `.NET 10` 单服务宿主，负责:

- API 路由、认证、授权。
- Hosted background services。
- Redis 队列/锁适配。
- 统一配置、日志、审计、健康检查。
- 模块 DI 注册和事务边界。
- 插件运行时生命周期管理。

Core App 不直接实现来源解析、版本比对、LLM 判断；这些通过插件或子模块接口实现。

## 2. 对外接口

### 2.1 .NET 内部接口

```csharp
public interface IAppClock
{
    DateTimeOffset UtcNow { get; }
}

public interface IDistributedLock
{
    Task<IAsyncDisposable?> TryAcquireAsync(string key, TimeSpan ttl, CancellationToken ct);
}

public interface IBackgroundTaskQueue
{
    ValueTask EnqueueAsync(BackgroundTaskEnvelope task, CancellationToken ct);
    ValueTask<BackgroundTaskEnvelope> DequeueAsync(CancellationToken ct);
}

public interface IAuditWriter
{
    Task WriteAsync(AuditEvent evt, CancellationToken ct);
}
```

### 2.2 HTTP 对外接口

详见 [../contracts/api-rpc.md](../contracts/api-rpc.md)。Core App 只暴露 `GET` 和 `POST`。

## 3. 核心逻辑

### 3.1 启动流程

1. 加载环境变量。
2. 校验必填配置。
3. 初始化日志。
4. 连接 PostgreSQL/Redis。
5. 执行 migration 或等待外部 migration 完成。
6. 注册插件 manifest。
7. 启动 API server。
8. 启动 Scheduler 和 Worker hosted services。

### 3.2 后台任务循环

```text
while app is running:
  task = queue.dequeue()
  create execution scope
  check cancellation
  dispatch by task.type
  write task status
  on failure:
    classify retryable/non-retryable
    schedule retry or dead-letter
```

## 4. 错误处理

- 配置错误: 启动失败。
- PostgreSQL 不可用: readiness unhealthy，后台任务暂停。
- Redis 不可用: scheduler 暂停，API 只读接口可继续。
- 插件失败: 不影响进程，进入 task error。

## 5. 独立测试

冒烟测试:

- `GET /api/v1/system.health` 返回 healthy。
- PostgreSQL 连接失败时 readiness 返回 unhealthy。
- Redis lock 能获取并释放。

模块测试:

- `IBackgroundTaskQueue` enqueue/dequeue 顺序。
- `IDistributedLock` 同 key 互斥。
- 审计事件写入。

集成测试:

- 启动 app + postgres + redis。
- 执行 migration。
- seed sources。
- 调用 source list API。

