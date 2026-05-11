# VulTrack Fetchers

Fetcher 是 VulTrack 的 source-fetcher 插件层。每个 fetcher 负责从一个外部来源拉取原始数据，写入 raw object、`source_raw_index` 和对应 staging 表。后续解析、合并和组件匹配由 .NET worker 处理。

## 目录约定

```text
plugins/fetchers/
  run-fetcher.mjs          # 单个 source 入口
  run-all.mjs              # 动态发现并运行所有 sources/*.mjs
  lib/
    db.mjs                 # 唯一 PostgreSQL 连接入口
    staging.mjs            # staging upsert helpers
    http.mjs               # HTTP helpers
    env.mjs                # .env / 环境变量 helpers
  sources/
    <source-code>.mjs      # 一个 source 一个模块
```

所有 fetcher 都必须通过 `lib/db.mjs` 连接数据库，不要在 source 文件中直接创建 `pg.Pool` 或硬编码连接串。

## 新增 Fetcher

1. 在 `plugins/fetchers/sources/` 新建 `<source-code>.mjs`。
2. 导出固定接口：

```js
export const sourceCode = '<source-code>';
// 可选：初始化/基线导入源使用 runMode = 'init'。
// run-all 默认跳过 init-only source，除非设置 FETCHER_INCLUDE_INIT=1。
// export const runMode = 'init';

export async function run(client, ctx) {
  // client: pg client，由 run-fetcher 注入
  // ctx.source: sources 表当前 source row
  // ctx.run: source_sync_runs 当前 run row
  return {
    fetchedCount: 0,
    parsedCount: 0,
    checkpoint: { lastFetched: new Date().toISOString() }
  };
}
```

3. 用 `writeRecord(client, ctx, record)` 写 raw object 和 `source_raw_index`。
4. 在 `lib/staging.mjs` 增加或复用 staging upsert helper。
5. 在 `db/init/001_schema.sql` seed `sources` 行，并为新 staging 表补 `create table if not exists`。
6. 运行：

```bash
npm test
npm run test:integration
FETCHER_MAX_RECORDS=1 npm run fetch -- --source <source-code>
```

## 单个 Fetcher 调试

推荐先用 bounded 模式。`FETCHER_MAX_RECORDS` 只限制真实来源处理条数，不应该让 fetcher 自动改用内置示例数据：

```bash
DATABASE_URL=postgres://vultrack:vultrack@localhost:5432/vultrack \
FETCHER_MAX_RECORDS=1 \
npm run fetch -- --source nvd-cve
```

常用环境变量：

```bash
FETCHER_TIMEOUT_MS=600000
NVD_API_KEY=...
GITHUB_TOKEN=...
OSS_INDEX_USERNAME=...
OSS_INDEX_TOKEN=...
```

需要显式 smoke 时，使用 `FETCHER_SMOKE=1`，或提供 source 专属 ID/组件环境变量，例如 `OSV_IDS`、`MAVEN_OSV_IDS`、`ANDROID_OSV_IDS`、`GOOGLE_OSV_IDS`、`UBUNTU_OSV_IDS`、`MAVEN_COMPONENTS`。这些变量表示“按指定对象查询”，不表示全量或日常增量。

初始化/基线源默认不参与日常全量或定时更新。镜像、archive、仓库全量重放类任务用 `runMode = 'init'`，通常命名为 `<source>-init`；日常 source 只做 API 或 `modified_id.csv` 等增量。

当前拆分：

```text
nvd-cve-init       # NVD JSON mirror baseline
nvd-cve            # NVD API 2.0 lastModStartDate incremental
osv-init           # OSV global all.zip baseline
osv                # OSV global modified_id.csv incremental
android-osv-init   # OSV Android all.zip baseline
android-osv        # OSV Android modified_id.csv incremental
maven-osv-init     # OSV Maven all.zip baseline
maven-osv          # OSV Maven modified_id.csv incremental
google-osv-init    # Google-maintained OSV baseline subset
google-osv         # Google-maintained OSV modified_id.csv incremental
cve-list-v5        # CVE List v5 baseline/init-only
```

`maven-advisory` 是组件定向查询 fetcher，依赖 `MAVEN_COMPONENTS`，没有独立的 Maven 全量漏洞流。Maven 生态全量/增量来源使用 `maven-osv-init` 和 `maven-osv`。

需要显式跑初始化时：

```bash
FETCHER_INCLUDE_INIT=1 CVE_LIST_INIT=1 npm run fetch -- --source cve-list-v5
FETCHER_INCLUDE_INIT=1 npm run fetch -- --source android-osv-init
```

## 运行所有 Fetcher

`run-all.mjs` 默认动态发现 `sources/*.mjs`，并跳过 `runMode = 'init'` 的初始化源：

```bash
FETCHER_MAX_RECORDS=1 node plugins/fetchers/run-all.mjs
```

包含初始化源：

```bash
FETCHER_INCLUDE_INIT=1 node plugins/fetchers/run-all.mjs
```

只跑指定 sources：

```bash
node plugins/fetchers/run-all.mjs --sources nvd-cve,ghsa,osv
```

全量/增量更新：

```bash
FETCHER_MAX_RECORDS= node plugins/fetchers/run-all.mjs
```

全量模式依赖各 source 的 checkpoint。不要用 `FETCHER_FORCE=1` 跑全量，除非你明确要忽略 checkpoint 重新抓取。

## 数据库配置

统一入口是：

```text
DATABASE_URL=postgres://vultrack:vultrack@localhost:5432/vultrack
```

`lib/db.mjs` 会读取 `DATABASE_URL`，默认值只用于本地开发。新增 fetcher 不要复制连接逻辑。

## 检查运行状态

```bash
docker exec -i vultrack-postgres psql -U vultrack -d vultrack -XAtc "
select s.code, r.status, r.fetched_count, r.parsed_count, r.error_count, r.started_at, r.finished_at
from source_sync_runs r
join sources s on s.id = r.source_id
order by r.started_at desc
limit 30;"
```

取消卡住的 run 前，先确认进程是否仍在运行：

```bash
ps -axo pid,etime,command | rg 'plugins/fetchers/run-fetcher'
```
