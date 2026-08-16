# VulTrack Fetchers

Fetcher 是 VulTrack 的 source-fetcher 插件层。每个 fetcher 是一个 Node.js ESM 脚本，由 .NET `DuckDbFirstScheduler` 以子进程方式串行执行（也可通过 `run-fetcher.mjs` 手动运行）。fetcher 只负责拉取外部来源并写 spool 文件；后续解析、归一化、组件匹配全部由 .NET 端在摄入 spool 时完成。

## Spool 管线

fetcher 不直接写任何数据库。`writeRecord()` 把记录追加为 NDJSON 行写入：

```text
data/spool/incoming/<source>-<runId>-sNNNN.ndjson.partial
```

一个 run 成功结束时，`flushWriteBatch()` 把 `.partial` 原子 rename 为 `.ndjson.ready`；失败时 `.partial` 被删除。scheduler 只摄入 `*.ndjson.ready` 文件，摄入成功后删除该文件。checkpoint 和 run 状态保存在 `data/spool/state/<source>.json`（同样是临时文件 + 原子 rename），并且只在对应 spool segment 晋升 `.ready` 之后才提交，避免丢文件后跳过记录。

每行 spool 记录包含 `schemaVersion`、`sourceCode`、`runId`、`externalKey`、`identifiers`、`recordHash`、`payload` 等字段（见 `lib/db.mjs` 的 `writeSpoolRecord`）。

## 目录约定

```text
plugins/fetchers/
  run-fetcher.mjs          # 单个 source 入口
  run-all.mjs              # 动态发现并运行所有 sources/*.mjs（本地 smoke 用）
  lib/
    db.mjs                 # spool 写入 / checkpoint / run 状态
    http.mjs               # HTTP helpers
    env.mjs                # .env / 环境变量 helpers
    hash.mjs               # sha256 / stableJson
    advisory.mjs           # 通用 advisory helpers
    china-advisory.mjs     # 中国境内 advisory 归一 helpers
    exploit-utils.mjs      # exploit/PoC 分类与 git mirror helpers
    osv-database.mjs       # OSV 生态归档 helpers
  sources/
    <source-code>.mjs      # 一个 source 一个模块
```

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
  // client: spool client，由 run-fetcher 注入（不是数据库连接）
  // ctx.source: 来源状态（id/code/checkpoint_json/has_records）
  // ctx.run: 当前 run（id、started_at 等）
  return {
    fetchedCount: 0,
    parsedCount: 0,
    checkpoint: { lastFetched: new Date().toISOString() }
  };
}
```

3. 用 `writeRecord(client, ctx, record)` 写记录；record 至少包含 `externalKey`、`identifiers`、`payload`，可选 `sourceUrl`、`publishedAt`、`modifiedAt`、`recordHash`。
4. checkpoint 必须支持增量：从 `ctx.source.checkpoint_json` 读取，run 返回新的 checkpoint；用 `FETCHER_FORCE=1` 可忽略 checkpoint 重抓。
5. 运行：

```bash
npm test
FETCHER_MAX_RECORDS=1 npm run fetch -- --source <source-code>
```

6. 新 source 还需要在 .NET scheduler 的 source 列表中登记后才能参与定时抓取；手动 `npm run fetch` 不需要。

## 单个 Fetcher 调试

推荐先用 bounded 模式。`FETCHER_MAX_RECORDS` 只限制真实来源处理条数，不应该让 fetcher 自动改用内置示例数据：

```bash
FETCHER_MAX_RECORDS=1 npm run fetch -- --source nvd-cve
```

常用环境变量：

```bash
FETCHER_TIMEOUT_MS=600000
FETCHER_MAX_RECORDS=          # 空 = 不限制
FETCHER_FORCE=0               # 1 = 忽略 checkpoint 重抓
FETCHER_SMOKE=0               # 1 = 显式 smoke 模式
VULTRACK_SPOOL_PATH=data/spool
NVD_API_KEY=...
GITHUB_TOKEN=...
OSS_INDEX_USERNAME=...
OSS_INDEX_TOKEN=...
FETCHER_ARCHIVE_GITHUB_REPOS=0
FETCHER_GITHUB_ARCHIVE_MAX_BYTES=10485760
EXPLOITDB_ARCHIVE_ARTIFACTS=0
```

Exploit/PoC sources:

- `exploitdb`：默认同步 Exploit-DB CSV 元数据。设置 `EXPLOITDB_ARCHIVE_ARTIFACTS=1` 后才会逐条下载 exploit 文件并随 spool 记录归档。
- `metasploit`：浅克隆 Metasploit Framework，解析带 CVE 引用的 module，并归档 Ruby module。
- `nuclei-templates`：浅克隆 ProjectDiscovery nuclei-templates，解析 CVE 模板，并归档 YAML template。
- `poc-in-github`：浅克隆 PoC-in-GitHub 的 CVE-to-repository 索引。默认归档仓库 metadata；如果设置 `FETCHER_ARCHIVE_GITHUB_REPOS=1`，会尝试下载 GitHub repo zipball，受 `FETCHER_GITHUB_ARCHIVE_MAX_BYTES` 限制。
- `trickest-cve`：手动源。通过 GitHub Contents API 拉取 CVE markdown 索引，单年目录响应很大且需要逐条下载 markdown，默认禁用以避免拖慢初始化和定时任务。需要复核时显式运行 `npm run fetch -- --source trickest-cve`。

GitHub 公开 API 不强制要求 token，但全量跑 `poc-in-github`、手动复核 `trickest-cve` 或开启 GitHub repo zipball 归档时，建议申请并配置 `GITHUB_TOKEN`，否则容易遇到 GitHub rate limit。当前 fetcher 不会自动执行任何 PoC，只保存元数据、来源 URL、hash 和归档内容。

中国境内漏洞情报源：

- `cnnvd`：使用 CNNVD 的公开 JSON 列表和详情接口，抓取中文描述、厂商、影响产品、参考链接和补丁信息。
- `seebug`：抓取 Seebug 漏洞库公开列表和详情页，保留 SSV、CVE、危险等级以及 PoC 可用信号。
- `aliyun-avd`：抓取阿里云 AVD 公开列表，覆盖 CVE、非 CVE 和 PoC 已公开信号。详情页默认不抓，因为站点可能启用验证码保护；需要时设置 `ALIYUN_AVD_FETCH_DETAILS=1`。
- `nsfocus-vulndb`：抓取绿盟 NSFOCUS 漏洞库公开列表和详情页，补充中文描述、受影响系统和修复引用。
- `chaitin-vuldb`：抓取长亭漏洞库公开 API，保留 CT、CVE、CNVD、CNNVD 映射、中文摘要、修复建议和 PoC/EXP 披露信号。
- `cnvd`：CNVD 会触发反爬挑战，默认禁用。只支持在许可范围内提供 `CNVD_COOKIE`，并可用 `CNVD_IDS=CNVD-2024-...` 定向同步；不要尝试自动绕过验证码。
- `cert-360`：360CERT RSS 当前 TLS 和内容时效不稳定，默认禁用。如明确接受 TLS 风险，可设置 `CERT360_ALLOW_INSECURE_TLS=1` 后定向运行。

生产默认不启用 CNNVD 定时抓取：其详情接口当前不稳定，失败会产生大量无效重试。其余中国境内来源全部是 `manual` 且默认禁用，只能通过管理界面或显式 `npm run fetch -- --source <code>` 运行。CNNVD 仍可在受控环境中显式 smoke 或手动运行。

这些来源统一带 `schemaHint: 'external-advisory'` 写入 spool，由 .NET 端归一化合并。能解析出 CVE 时优先归并到 CVE；没有 CVE 时保留来源编号，例如 `CNNVD-*`、`CNVD-*`、`SSV-*`、`AVD-*` 或 `CT-*`。产品名称作为弱结构化事实保存，不会伪造 purl。

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
ghsa-init          # GitHub Advisory Database github-reviewed baseline
ghsa               # GitHub Advisory API incremental
android-osv-init   # OSV Android all.zip baseline
android-osv        # OSV Android modified_id.csv incremental
maven-osv-init     # OSV Maven all.zip baseline
maven-osv          # OSV Maven modified_id.csv incremental
google-osv-init    # Google-maintained OSV baseline subset
google-osv         # Google-maintained OSV modified_id.csv incremental
cve-list-v5        # Optional/manual CVE List v5 mirror; not part of default init
```

默认 CVE 主链路使用 `nvd-cve-init` 建立官方 NVD 基线，再用 `nvd-cve` 做 NVD API 2.0 增量。`cve-list-v5` 与 NVD 在 CVE 描述和元数据上高度重叠，且缺少 NVD 的 CVSS、CPE configurations 和 NVD modified 时间语义，因此只保留为手动审计/补充源，不参与默认 init、canonical rebuild 或定时抓取。

GHSA 主链路使用 `ghsa-init` 浅克隆 GitHub 官方
`github/advisory-database` 仓库，只导入 `advisories/github-reviewed` 下由 git 跟踪的 OSV
JSON；未审核目录不会进入基线。导入 checkpoint 固定仓库 revision 和文件 offset，spool
按 `GHSA_INIT_SEGMENT_SIZE`（默认 5000）分段，所以中断后可从同一 revision 继续且不会重复。
完成基线后，scheduler 把基线开始时记录的 `incrementalSince` 传给 `ghsa` REST 增量，覆盖
长时间基线执行期间发生的更新。可用 `GHSA_ADVISORY_REPOSITORY` 和
`GHSA_ADVISORY_MIRROR_PATH` 指向内部镜像；repository baseline 不依赖 GitHub API token。

`maven-advisory` 是组件定向查询 fetcher，依赖 `MAVEN_COMPONENTS`，没有独立的 Maven 全量漏洞流。Maven 生态全量/增量来源使用 `maven-osv-init` 和 `maven-osv`。

需要显式跑初始化时：

```bash
npm run fetch -- --source cve-list-v5
FETCHER_INCLUDE_INIT=1 npm run fetch -- --source android-osv-init
npm run fetch -- --source ghsa-init
```

在全量覆盖 shadow DuckDB 前，可先从同一个 OSV `all.zip` 选择真实边界样本。该命令只扫描
archive，并输出标准 `osv-init` spool 和 `manifest.json`，不会直接写 DuckDB：

```bash
npm run osv:bulk-samples -- \
  --zip=data/mirrors/osv-all.zip \
  --output=data/osv-bulk-samples \
  --concurrency=8
```

如果 zip 不存在，脚本会从官方 GCS `all.zip` 下载；`--refresh` 强制更新。manifest 包含
direct CVE alias 与 upstream CVE 的 0/1/2/最大值样本、完整分布、CVE-less GHSA、identifier
内嵌 CVE，以及同时具有 severity/references/affected 的记录。生成的 spool 必须先喂给隔离
sample DuckDB 的真实 Normalizer 验证，不能放入 live spool 目录。

## 运行所有 Fetcher

`run-all.mjs` 默认动态发现 `sources/*.mjs`，并跳过 `runMode = 'init'` 的初始化源与 `runMode = 'manual'` 的手动源（生产环境由 .NET scheduler 串行调度，不经过 run-all）：

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

## 检查运行状态

每个 source 的 checkpoint、最近 run 结果和最近错误都写在磁盘状态文件中：

```bash
ls data/spool/state/
cat data/spool/state/nvd-cve.json
```

待摄入和摄入中的 spool 文件在 `data/spool/incoming/`：只有 `*.ndjson.ready` 会被 scheduler 摄入，`.partial` 表示 fetcher 仍在写或已失败待清理。

取消卡住的 run 前，先确认进程是否仍在运行：

```bash
ps -axo pid,etime,command | rg 'plugins/fetchers/run-fetcher'
```
