# 模块设计: Ingestion

## 1. 职责

Ingestion 负责从插件接收外部数据，写入 raw object、raw index 和 staging 表。

不负责:

- 漏洞合并。
- 组件匹配。
- 版本范围判断。
- canonical 投影。

## 2. 输入和输出

输入:

- `SourceSyncCommand`
- 插件返回的 `FetchedObject`
- 插件返回的 `StagingEnvelope`

输出:

- `source_objects`
- `source_raw_index`
- `stg_*`
- `source_sync_runs`
- `source_task_errors`

## 3. 对外接口

```csharp
public interface ISourceSyncService
{
    Task<Guid> StartSyncAsync(string sourceCode, SyncTrigger trigger, CancellationToken ct);
    Task<SourceSyncRunDto> GetRunAsync(Guid runId, CancellationToken ct);
}

public interface IRawObjectStore
{
    Task<RawObjectWriteResult> WriteAsync(RawObjectWriteRequest request, CancellationToken ct);
    Task<Stream> OpenReadAsync(string objectUri, CancellationToken ct);
}

public interface IStagingWriter
{
    Task WriteAsync(StagingEnvelope envelope, CancellationToken ct);
}
```

## 4. 核心逻辑

### 4.1 同步流程

```text
start sync
  acquire source lock
  create source_sync_run
  execute source-fetcher plugin
  for each object:
    compress payload
    write object store
    upsert source_objects
    upsert source_raw_index
  execute source-parser plugin if needed
  validate staging envelope
  write stg_* table
  update checkpoint only after successful batch
finish sync
```

### 4.2 幂等键

- object: `sha256(content)`
- raw index: `(source_id, external_key, record_hash)`
- staging: `raw_index_id`

## 5. Staging Envelope

```json
{
  "source": "nvd-cve",
  "schema": "stg_nvd_cves",
  "schemaVersion": "2.0",
  "rawIndexId": "uuid",
  "externalKey": "CVE-2024-0001",
  "recordHash": "sha256",
  "data": {}
}
```

## 6. 错误处理

- fetch 网络错误: retryable。
- schema 校验失败: non-retryable，进入 task error。
- object store 写失败: retryable。
- staging 写失败: retryable，事务回滚。

## 7. 独立测试

冒烟测试:

- fixture payload 写入 object store。
- raw index 有一条记录。
- staging 表有一条记录。

模块测试:

- 相同 payload 重跑不重复插入。
- record_hash 变化时标记 changed。
- parser 返回非法 schema 时进入 task error。

集成测试:

- NVD fixture sync: raw object -> raw index -> stg_nvd_cves。

