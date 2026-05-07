# VulTrack 模块化设计文档

状态: draft  
日期: 2026-05-08  
目标读者: 后端开发 agent、插件开发 agent、测试 agent、前端开发 agent

## 1. 文档结构

```text
docs/design/
- README.md                         # 本文件，总览和模块边界
- architecture.md                   # 整体工作流和业务数据流
- database.md                       # PostgreSQL 初始化、schema 分层、迁移顺序
- environment.md                    # 环境变量、Docker Compose、目录约定
- contracts/api-rpc.md              # 对外 API，禁止 PUT/PATCH/DELETE，只使用 GET/POST
- development-skills.md             # 开发可用技能和 agent 分工建议
- modules/
  - core-app.md                     # .NET 10 单服务宿主
  - ingestion.md                    # 采集、raw object、staging
  - normalization.md                # 规范化事实表和投影
  - identifier-linker.md            # CVE/GHSA/OSV 等 identifier 合并
  - component-matcher.md            # PURL/CPE/repo/package 组件映射
  - version-resolver.md             # 版本比对插件接口
  - plugin-runtime.md               # 插件沙盒、协议、执行模型
  - query-api.md                    # 查询聚合、详情页视图模型
- plugins/
  - README.md                       # 插件通用规范
  - nvd/design.md                   # NVD CVE/CPE 插件设计
  - ghsa/design.md                  # GHSA 插件设计
  - osv/design.md                   # OSV 插件设计
  - cve-list/design.md              # CVE List v5 插件设计
  - threat-intel/design.md          # CISA KEV/FIRST EPSS 插件设计
- testing/
  - test-plan.md                    # 冒烟测试、模块测试、集成测试定义
```

## 2. 系统边界

VulTrack MVP 是一个模块化单体:

- 一个 `.NET 10 LTS` 服务进程: `vultrack-app`。
- 一个 PostgreSQL: 事实库、搜索、任务元数据。
- 一个 Redis: 队列、锁、短期缓存、任务状态。
- raw object 存储: 默认本地 volume，可切换 MinIO/S3。
- Node.js/TypeScript 插件运行时打包进同镜像，通过受限子进程调用。

## 3. 核心模块

| 模块 | 职责 | 拥有的数据 |
|---|---|---|
| Core App | 进程宿主、DI、配置、健康检查、任务循环、权限 | app settings, audit logs |
| Plugin Runtime | 插件加载、沙盒执行、协议校验、超时和失败隔离 | plugin manifests, plugin runs |
| Ingestion | source sync、raw object、raw index、staging 写入 | sources, source_sync_runs, source_objects, source_raw_index, stg_* |
| Normalization | staging 到 normalized facts、投影重算 | vulnerabilities, records, facts |
| Identifier Linker | identifier index、edge、group、canonical vulnerability | vulnerability_identifier_* |
| Component Matcher | component identity、PURL/CPE/repo 映射、affected 聚合 | components, component_identity_index, affected_* |
| Version Resolver | 版本规范化、范围判断、resolver 缓存 | version_match_cache |
| Query API | RPC API、列表查询、详情聚合、权限过滤 | 无独占数据，读模型聚合 |

## 4. 开发原则

- 每个模块必须能独立单元测试。
- 每个插件必须能离线 fixture 测试。
- 核心业务表不保存不可控大 payload。
- `vulnerabilities` 只保存最大公约数和查询投影。
- 来源特殊字段通过 `source_specific`、typed properties、detail blocks 表达。
- LLM 只作为 evidence，不直接确认漏洞影响范围。
- 所有外部接口只使用 `GET` 和 `POST`。
- 所有后台任务必须幂等，可重试，可从阶段恢复。

## 5. 交付约定

开发 agent 应优先从以下文件开始:

1. [architecture.md](./architecture.md)
2. [database.md](./database.md)
3. [contracts/api-rpc.md](./contracts/api-rpc.md)
4. 对应模块文件
5. 对应插件文件
6. [testing/test-plan.md](./testing/test-plan.md)

