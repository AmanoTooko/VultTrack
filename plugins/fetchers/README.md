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
// 需要显式指定的源使用 runMode = 'manual'，run-all 始终默认跳过。

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
FETCHER_ARCHIVE_GITHUB_REPOS=0
FETCHER_GITHUB_ARCHIVE_MAX_BYTES=10485760
EXPLOITDB_ARCHIVE_ARTIFACTS=0
```

Exploit/PoC sources:

- `exploitdb`：默认同步 Exploit-DB CSV 元数据。设置 `EXPLOITDB_ARCHIVE_ARTIFACTS=1` 后才会逐条下载 exploit 文件并 gzip 归档到 `source_objects`。
- `metasploit`：浅克隆 Metasploit Framework，解析带 CVE 引用的 module，并归档 Ruby module。
- `nuclei-templates`：浅克隆 ProjectDiscovery nuclei-templates，解析 CVE 模板，并归档 YAML template。
- `poc-in-github`：浅克隆 PoC-in-GitHub 的 CVE-to-repository 索引。默认归档仓库 metadata；如果设置 `FETCHER_ARCHIVE_GITHUB_REPOS=1`，会尝试下载 GitHub repo zipball，受 `FETCHER_GITHUB_ARCHIVE_MAX_BYTES` 限制。
- `trickest-cve`：通过 GitHub Contents API 拉取 CVE markdown 索引，归档 markdown。

GitHub 公开 API 不强制要求 token，但全量跑 `poc-in-github`、`trickest-cve` 或开启 GitHub repo zipball 归档时，建议申请并配置 `GITHUB_TOKEN`，否则容易遇到 GitHub rate limit。当前 fetcher 不会自动执行任何 PoC，只保存元数据、来源 URL、hash 和压缩归档对象。

中国境内漏洞情报源：

- `cnnvd`：使用 CNNVD 的公开 JSON 列表和详情接口，抓取中文描述、厂商、影响产品、参考链接和补丁信息。
- `seebug`：抓取 Seebug 漏洞库公开列表和详情页，保留 SSV、CVE、危险等级以及 PoC 可用信号。
- `aliyun-avd`：抓取阿里云 AVD 公开列表，覆盖 CVE、非 CVE 和 PoC 已公开信号。详情页默认不抓，因为站点可能启用验证码保护；需要时设置 `ALIYUN_AVD_FETCH_DETAILS=1`。
- `nsfocus-vulndb`：抓取绿盟 NSFOCUS 漏洞库公开列表和详情页，补充中文描述、受影响系统和修复引用。
- `chaitin-vuldb`：抓取长亭漏洞库公开 API，保留 CT、CVE、CNVD、CNNVD 映射、中文摘要、修复建议和 PoC/EXP 披露信号。
- `cnvd`：CNVD 会触发反爬挑战，默认禁用。只支持在许可范围内提供 `CNVD_COOKIE`，并可用 `CNVD_IDS=CNVD-2024-...` 定向同步；不要尝试自动绕过验证码。
- `cert-360`：360CERT RSS 当前 TLS 和内容时效不稳定，默认禁用。如明确接受 TLS 风险，可设置 `CERT360_ALLOW_INSECURE_TLS=1` 后定向运行。

默认只有 `cnnvd` 启用定时抓取，每 6 小时运行一次。其余中国境内来源全部是 `manual` 且默认禁用，只能通过管理界面或显式 `npm run fetch -- --source <code>` 运行。

这些来源统一写入 `stg_external_advisories`，再由 `ExternalAdvisoryRawNormalizer` 合并。能解析出 CVE 时优先归并到 CVE；没有 CVE 时保留来源编号，例如 `CNNVD-*`、`CNVD-*`、`SSV-*`、`AVD-*` 或 `CT-*`。产品名称作为弱结构化事实保存，不会伪造 purl。

奇安信 TI 的公开 advisory 页面目前是 SPA，没有发现可稳定复用的公开 API。接入前需要向奇安信申请正式 API 地址和凭据，再按其授权接口补 fetcher，不要依赖页面脚本里出现的内部地址。

建议先用小批量真实数据 smoke：

```bash
FETCHER_MAX_RECORDS=1 npm run fetch -- --source cnnvd
FETCHER_MAX_RECORDS=1 npm run fetch -- --source chaitin-vuldb
FETCHER_MAX_RECORDS=1 npm run fetch -- --source seebug
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

`run-all.mjs` 默认动态发现 `sources/*.mjs`，并跳过 `runMode = 'init'` 的初始化源与 `runMode = 'manual'` 的手动源：

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
