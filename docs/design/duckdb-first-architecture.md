# DuckDB-First 架构（当前实际架构）

本文档描述 VulTrack **当前**的架构。除本文档与 `docs/proposals/affected-duckdb-migration.md` 之外，`docs/design/` 下其余文档描述的是已被取代的 PostgreSQL-first 设计，仅具历史参考价值。

## 总览

VulTrack 是一个 DuckDB-first 的单体单进程应用：

- 唯一的运行时是一个 .NET 10 服务 `VulTrack.App`（API、`DuckDbFirstScheduler`、归一化、匹配、详情快照）。
- 唯一的存储是一个内嵌 DuckDB 文件（默认 `data/duckdb/vultrack-evidence.duckdb`）：目录、证据、受影响组件、exploit、威胁评分、AI 分析、SBOM 全部存在其中。
- **没有** PostgreSQL 服务器、Redis、OpenSearch、Temporal、RabbitMQ、NATS、Kubernetes。Redis 未来仅可在性能分析证明有需要时作为可选缓存/队列重新引入，永远不作为事实来源。
- 部署为 `docker-compose.yml`：api + frontend 两个容器。

## Spool 抓取管线

1. `plugins/fetchers/sources/*.mjs`（约 46 个源）是普通 Node.js ESM 脚本，由 .NET 调度器以子进程方式执行。没有沙箱、没有 `plugin.json`、没有 stdin/stdout 插件协议；共享辅助代码在 `plugins/fetchers/lib/`。
2. 每个 fetcher 将记录写成 gzip 压缩的 NDJSON 文件放入 `data/spool/incoming/`，写完后通过改名为 `*.ndjson.ready` 后缀原子性地发布。调度器**只**消费带 `.ready` 后缀的文件。
3. `DuckDbFirstScheduler` 串行运行 fetcher（同一时间只有一个抓取周期），把 ready 文件直接导入 DuckDB 的 `source_records`，成功后删除临时 spool 文件。失败按源隔离，不会拖垮 API 进程。
4. FIRST EPSS 是例外：走原生 gzip CSV 快照管线（`DuckDbEvidenceStore.Epss.cs` / `DuckDbEvidenceNormalizer.Epss.cs`），不走 NDJSON spool。
5. 空库时调度器自动运行/恢复 NVD 与 OSV 基线；基线检查点完成后，后续周期只跑增量 fetcher。

## DuckDB Schema 归属

- Schema 全部在代码中创建：`src/VulTrack.App/DuckDbEvidenceStore.cs` 用 `create table if not exists` 与受保护的 alter 演进 schema。**不**新增 SQL 迁移文件。
- 主要表：
  - `source_records` / `source_record_identifiers` / `source_record_relations`：所有源的原始事实与别名，永不被互相覆盖。
  - `vulnerabilities`、`vulnerability_identifiers`：规范目录。
  - `vulnerability_latest`：5000 行的"最新"物化表，只是渲染缓存，不是完整目录。
  - `affected_facts`：源级受影响事实；`affected_components`：查询投影（大批量用整表 swap 重建，小批量用 delete-and-append）。
  - `severity_scores`、`evidence_references`、`weaknesses`、`cpe_entries`、`exploits`、`threat_scores`、`ai_vulnerability_analyses`。
  - `sbom_uploads`、`sbom_components`、`sbom_matches`。
- `db/init/*.sql` 是遗留 PostgreSQL schema，不再扩展。

## 搜索 / 目录重建流程

1. Spool 导入后，归一化逻辑在 DuckDB **内部**从 `source_records` 重建规范目录（`vulnerabilities`、别名、严重程度、引用等）；没有外部 staging 库。
2. `vulnerability_latest` 在重建后刷新（5000 行上限）。
3. 搜索/详情 API 直接查询 DuckDB；详情快照由 `VulnerabilityDetailSnapshotBuilder`/`VulnerabilityDetailSnapshotStore` 生成，属于缓存渲染数据而非事实来源。
4. 冲突的受影响范围（如 `<1.11` vs `=1.11` vs LLM `<=1.11`）必须保持可见，不得静默合并。AI 输出只作为证据存于 `ai_vulnerability_analyses`。

## SBOM 匹配流程

1. SBOM 上传写入 `sbom_uploads` / `sbom_components`。
2. 匹配读取 DuckDB 中规范的 `affected_components` 投影（不在查询时回扫原始事实）。
3. 版本比较必须经过 `EcosystemVersionComparer` / 生态特定的解析器，禁止用字符串排序比较版本。
4. 匹配结果写入 `sbom_matches`。

## 已被取代的文档

以下 `docs/design/` 文档描述旧的 PG-first 设计，已被本文档取代，仅作历史参考：

- `docs/design/architecture.md`
- `docs/design/database.md`
- `docs/design/environment.md`
- `docs/design/development-skills.md`
- `docs/design/modules/` 全部（`core-app.md`、`ingestion.md`、`normalization.md`、`plugin-runtime.md`、`query-api.md`、`identifier-linker.md`、`component-matcher.md`、`version-resolver.md`）
- `docs/design/plugins/` 全部
- `docs/design/testing/test-plan.md`
- `docs/design/contracts/api-rpc.md`（API 风格约定仍有效，但其中 PG 相关存储描述已过时）

仍具时效性：`docs/proposals/affected-duckdb-migration.md`（迁移理由与风险说明）。

## 关键约束（Gotchas）

- DuckDB 每个文件只有一个写入者：所有写入必须经调度器/EvidenceStore 串行化，读者共享托管连接。
- DuckDB 1.5.x 的 ART 索引状态可能在增量 UPDATE/DELETE 后持久化损坏并使数据库 invalidated（上游 [duckdb/duckdb#23645](https://github.com/duckdb/duckdb/issues/23645)）。当前 schema 初始化会移除所有显式 ART 索引；在上游问题关闭且生产规模 churn benchmark 通过前不得重新启用。
- Spool 的原子发布依赖 `.ready` 后缀：绝不消费无后缀文件，绝不重命名未写完的文件。
- `vulnerability_latest` 与详情快照是缓存，不是事实来源；目录只能从 `source_records` 重建，禁止手工编辑投影表。
