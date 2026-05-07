# 测试设计: 冒烟测试、模块测试和集成测试

## 1. 测试分层

| 层级 | 目的 | 运行频率 | 依赖 |
|---|---|---|---|
| Smoke | 验证服务能启动、核心链路未断 | 每次提交 | app + postgres + redis |
| Unit | 验证单模块纯逻辑 | 每次提交 | 无外部依赖或 test double |
| Module | 验证模块和数据库交互 | 每次提交 | test postgres/redis |
| Plugin Fixture | 验证插件协议和 staging 输出 | 每次插件变更 | node runtime |
| Integration | 验证跨模块链路 | 每次合并前 | app + postgres + redis + fixtures |
| E2E | 验证业务场景 | 发布前 | docker compose |

## 2. 全局冒烟测试

### SMK-001 服务启动

步骤:

1. 启动 PostgreSQL。
2. 启动 Redis。
3. 启动 `vultrack-app`。
4. 调用 `GET /api/v1/system.health`。
5. 调用 `GET /api/v1/system.ready`。

期望:

- health = healthy。
- ready = healthy。
- 日志无 fatal。

### SMK-002 数据库初始化

步骤:

1. 空库启动 app。
2. 执行 migration。
3. 查询 seed sources。

期望:

- 必需扩展存在。
- sources 包含 nvd-cve、ghsa、osv、cve-list-v5、cisa-kev、first-epss。

### SMK-003 插件运行时

步骤:

1. 调用 fixture echo plugin。
2. 调用 timeout fixture plugin。

期望:

- echo 返回 ok。
- timeout 被分类为 plugin timeout，不导致 app 崩溃。

## 3. 模块测试

### Core App

- lock 同 key 互斥。
- queue enqueue/dequeue 正常。
- audit writer 写入成功。
- Redis 不可用时 readiness unhealthy。

### Ingestion

- raw object 写入 filesystem。
- 相同 `source_id + external_key + record_hash` 重复同步不重复插入。
- changed record 产生新 raw index。
- staging 写入失败时 sync run 标记 partial/failed。

### Normalization

- GHSA fixture 生成 vulnerability_record。
- CVSS v2/v3/v4 全部写入 severity scores。
- source-specific 字段保留。
- affected fact 写入后触发 aggregation task。

### Identifier Linker

- GHSA + CVE strong edge 自动合并。
- OSV alias strong edge 自动合并。
- medium edge 不自动合并。
- union-find 重建结果稳定。

### Component Matcher

- PURL exact match 命中 component。
- CPE/PURL overlap 生成 candidate edge。
- LLM evidence 不会单独 confirm。
- `<1.11` + `=1.11` 标记 conflicted。

### Version Resolver

- npm semver contains。
- PyPI PEP 440 fixture。
- Maven version fixture。
- RPM/Debian 不允许降级 generic-semver confirmed。

### Query API

- identifier 查询只查一次 index 即可定位 canonical vulnerability。
- vulnerability detail 返回 affected components。
- 展开 affected evidence 返回来源证据。
- Viewer 无权访问 raw payload。

## 4. 插件 Fixture 测试

每个插件必须有:

```text
fixtures/small.json
fixtures/changed.json
fixtures/invalid.json
```

通用测试:

- manifest 可解析。
- stdin 请求合法。
- stdout 是合法协议 JSON。
- invalid fixture 返回 schema error。
- small fixture 输出 staging envelope。
- changed fixture record_hash 改变。

### NVD

- CVE fixture 输出 CVE identifier。
- CVSS metrics 全部保留。
- CPE match 输出 affected fact。
- detail renderer 输出 configuration tree block。

### GHSA

- GHSA ID 和 CVE ID strong edge。
- vulnerable range 输出 affected fact。
- patched version 输出 fixed_versions。

### OSV

- aliases 输出 strong edges。
- related 输出 medium edges。
- affected package purl 输出 affected fact。

### CVE List

- CNA description 输出 description fact。
- metrics 输出 severity scores。
- rejected CVE 映射 status。

### Threat Intel

- KEV 设置 kev projection。
- EPSS 设置 epss projection。

## 5. 集成测试

### INT-001 GHSA + NVD 合并

输入:

- NVD fixture: `CVE-TEST-0001`
- GHSA fixture: `GHSA-test` aliases `CVE-TEST-0001`

步骤:

1. ingest NVD。
2. normalize NVD。
3. ingest GHSA。
4. normalize GHSA。
5. run identifier linker。
6. query by CVE and GHSA。

期望:

- 两个 identifier 返回同一个 vulnerability id。
- severity scores 包含 NVD 和 GHSA 两个来源。

### INT-002 affected conflict

输入:

- Maven/GHSA fact: `openssl < 1.11`
- NVD CPE fact: `openssl = 1.11`
- LLM evidence: `openssl <= 1.11`

步骤:

1. 写入三个 facts/evidence。
2. run component matcher aggregation。
3. query affected components。

期望:

- canonical affected component 存在。
- `resolution_status = conflicted` 或 `candidate`。
- evidence_count = 3。
- LLM evidence 不会单独 confirm。

### INT-003 PURL match

输入:

- affected component: `pkg:maven/org.example/foo`, range `<2.0.0`
- query purl: `pkg:maven/org.example/foo@1.5.0`

步骤:

1. run match.purl。

期望:

- matched = true。
- 返回 vulnerability summary。
- version_match_cache 有记录。

### INT-004 detail blocks

输入:

- NVD fixture with configurations。

步骤:

1. normalize record。
2. run detail renderer。
3. call vulnerability.get。

期望:

- detailBlocks 包含 `nvd.configurations`。
- block payload 不含 HTML/JS。

### INT-005 raw payload permission

步骤:

1. Viewer 调用 raw.payload。
2. Admin 调用 raw.payload。

期望:

- Viewer 403。
- Admin 200。
- audit log 记录下载事件。

## 6. E2E 测试

### E2E-001 Docker Compose 全链路

步骤:

1. `docker compose up`。
2. 执行 migration。
3. seed sources。
4. 运行 fixture sync。
5. 搜索 CVE。
6. 查看详情。
7. 调用 PURL match。

期望:

- 所有 API 返回 `ok = true`。
- 日志无 fatal。
- PostgreSQL 中关键表均有数据。

## 7. 覆盖率目标

- Core 纯逻辑单元测试: 80%+。
- Normalization mapping: 每个 source 至少覆盖 3 个 fixture。
- Plugin protocol: 每个插件 100% 覆盖 success/invalid/timeout。
- Integration: MVP 主链路必须全通过才能合并。

## 8. 测试数据命名

所有测试 identifier 使用:

```text
CVE-TEST-0001
GHSA-test-test-test
OSV-TEST-0001
```

避免误与真实漏洞混淆。

