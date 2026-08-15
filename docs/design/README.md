# VulTrack 设计文档索引

状态：DuckDB-first current / PG-first historical  
更新：2026-08-15

## 当前权威文档

按以下顺序阅读：

1. [`duckdb-first-architecture.md`](./duckdb-first-architecture.md)：当前运行时、
   数据流、schema ownership 与可靠性约束。
2. [`../implementation-status.md`](../implementation-status.md)：当前实现范围、
   endpoint 与验证状态。
3. [`../deployment/oracle-arm.md`](../deployment/oracle-arm.md)：生产 ARM 部署、
   迁移、回滚与资源门禁。
4. [`contracts/api-rpc.md`](./contracts/api-rpc.md)：仍有效的 GET/POST RPC 风格
   与响应 envelope；其中 PostgreSQL 存储描述已过时。
5. [`../reference/fetchers.md`](../reference/fetchers.md) 与
   [`../../plugins/fetchers/README.md`](../../plugins/fetchers/README.md)：source
   行为、checkpoint 与 spool 协议。

代码中的最终事实来源：

- schema：`src/VulTrack.App/DuckDbEvidenceStore.Schema.cs`
- runtime options：`src/VulTrack.App/VulTrackOptions.cs`
- scheduler：`src/VulTrack.App/DuckDbFirstScheduler.cs`
- endpoints：`src/VulTrack.App/Endpoints/` 与 `SbomEndpoints.cs`
- fetchers：`plugins/fetchers/sources/`

## 历史文档

下列文档描述已移除的 PostgreSQL/Redis/staging/plugin-sandbox 方案，只保留为
设计演进记录，不能用于实现或部署：

- `architecture.md`
- `database.md`
- `environment.md`
- `development-skills.md`
- `modules/*`
- `plugins/*`
- `testing/test-plan.md`

历史文档中的 `DATABASE_URL`、`stg_*`、PG normalizer、Redis、Adminer、独立
plugin protocol、Kubernetes 等内容均不属于当前架构。若历史文档与代码或
DuckDB-first 文档冲突，以当前代码和 `duckdb-first-architecture.md` 为准。

## 当前设计原则

- 单进程、单写者、单 DuckDB 文件。
- fetcher 通过 `.partial` → `.ready` 原子发布 spool。
- 原始 source facts 不互相覆盖；projection 可重建。
- AI 结果是 evidence，不是最终漏洞判定。
- 版本比较必须使用生态 resolver，禁止字符串排序。
- health 只表示进程存活；ready 必须真实访问 DuckDB。
- fatal storage error 必须 fail-stop，不能持续重试写入。
- 显式 ART 索引在 DuckDB 1.5.x 上保持关闭，直到上游修复并通过生产规模
  churn benchmark。
