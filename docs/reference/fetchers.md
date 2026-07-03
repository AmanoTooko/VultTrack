# VulTrack Fetcher 使用文档

## 概述

Fetcher 是独立的 Node.js 程序，从外部漏洞/威胁情报源采集数据，写入 PostgreSQL staging 表。每个 source 对应一个 `plugins/fetchers/sources/{source-code}.mjs` 模块。

## 运行方式

### 单个来源 (smoke 测试)

```bash
FETCHER_MAX_RECORDS=2 npm run fetch -- --source nvd-cve
```

### 单个来源 (全量)

```bash
FETCHER_MAX_RECORDS= npm run fetch -- --source nvd-cve
```

或直接运行:
```bash
FETCHER_MAX_RECORDS= node plugins/fetchers/run-fetcher.mjs --source nvd-cve
```

### 批量运行 (全量)

```bash
FETCHER_MAX_RECORDS= node plugins/fetchers/run-all.mjs
```

### 批量运行 (smoke)

```bash
npm run fetch:all:smoke
```

## 29 个数据来源

| source code | 类型 | 采集对象 | 采集方式 | 需要认证 |
|---|---|---|---|---|
| `nvd-cve` | vulnerability | NVD CVE | NVD API / git mirror | NVD_API_KEY 推荐 |
| `nvd-cpe` | cpe | NVD CPE 字典 | NVD API | NVD_API_KEY 推荐 |
| `ghsa` | vulnerability | GitHub reviewed advisories | GitHub API | GITHUB_TOKEN 推荐 |
| `npm-advisory` | vulnerability | GitHub npm advisories | GitHub API ecosystem=npm | GITHUB_TOKEN 推荐 |
| `npm-audit` | vulnerability | npm audit advisories | npm registry audit bulk API | 无需 |
| `nuget-advisory` | vulnerability | NuGet VulnerabilityInfo | NuGet V3 VulnerabilityInfo | 无需 |
| `maven-advisory` | vulnerability | Maven component vulns | OSS Index(有凭据) / OSV fallback | OSS_INDEX 可选 |
| `osv` | vulnerability | OSV.dev 聚合库 | all.zip / bounded API | 无需 |
| `maven-osv` | vulnerability | Maven OSV 子集 | OSV querybatch / all.zip filter | 无需 |
| `google-osv` | vulnerability | Android/Chromium/Fuchsia/linux OSV 子集 | OSV API / all.zip filter | 无需 |
| `android-osv` | vulnerability | Android Security Bulletin OSV | OSV API / all.zip filter | 无需 |
| `cve-list-v5` | vulnerability | CVE 官方记录 | GitHub raw / git clone | 无需 |
| `cisa-kev` | threat_intel | CISA KEV | CISA JSON feed | 无需 |
| `first-epss` | threat_intel | FIRST EPSS | CSV.gz | 无需 |
| `alpine-secdb` | vulnerability | Alpine SecDB | release/repo JSON | 无需 |
| `debian-security-tracker` | vulnerability | Debian Security Tracker | JSON feed | 无需 |
| `ubuntu-osv` | vulnerability | Ubuntu OSV | OSV API / tar.xz | 无需 |
| `redhat-csaf` | vulnerability | Red Hat CSAF summaries | Red Hat securitydata CSAF JSON | 无需 |
| `suse-csaf` | vulnerability | SUSE CSAF | SUSE CSAF index/json | 无需 |
| `pypi-advisory` | vulnerability | PyPA advisory DB | Git YAML | 无需 |
| `go-advisory` | vulnerability | Go vuln DB | Git OSV JSON | 无需 |
| `cargo-advisory` | vulnerability | RustSec advisory DB | Git TOML/markdown | 无需 |
| `npm-registry` | registry | npm package metadata | npm registry JSON | 无需 |
| `pypi-registry` | registry | PyPI package metadata | PyPI JSON API | 无需 |
| `maven-registry` | registry | Maven Central metadata | Maven Central Solr API | 无需 |
| `nuget-registry` | registry | NuGet package metadata | NuGet V3 flat/registration | 无需 |
| `rubygems-registry` | registry | RubyGems metadata | RubyGems API | 无需 |
| `packagist-registry` | registry | Packagist metadata | Packagist p2 metadata | 无需 |
| `crates-registry` | registry | crates.io metadata | crates.io API | 无需 |

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DATABASE_URL` | `postgres://vultrack:vultrack@localhost:5432/vultrack` | PostgreSQL 连接 |
| `FETCHER_MAX_RECORDS` | 无限制 | 限制获取记录数 (smoke 测试用) |
| `FETCHER_TIMEOUT_MS` | `120000` | HTTP 请求超时 (ms) |
| `EXPLOITDB_ARCHIVE_ARTIFACTS` | `0` | 设置为 `1` 时才逐条下载并归档 Exploit-DB PoC 文件 |
| `FETCHER_USER_AGENT` | `VulTrack/0.1` | HTTP User-Agent |
| `NVD_API_KEY` | - | NVD API Key (避免 Cloudflare 限速) |
| `NVD_PAGE_SIZE` | `1000` | NVD API 每页条数；较小分页可降低上游 503 的重试成本 |
| `GITHUB_TOKEN` | - | GitHub Personal Access Token |
| `OSS_INDEX_USERNAME` / `OSS_INDEX_TOKEN` | - | Sonatype OSS Index 凭据，用于 Maven 独立漏洞 API |
| `OSV_IDS` | smoke 时 `GHSA-jfh8-c2jp-5v3q` | smoke 模式指定 OSV ID |
| `CVE_LIST_IDS` | smoke 时 `CVE-2024-3094` | smoke 模式指定 CVE ID |
| `ALPINE_RELEASES` | `v3.22,v3.21,...,edge` | Alpine 发行版列表 |
| `NPM_PACKAGES` | `lodash,express,react` | npm 包名列表 |
| `NPM_AUDIT_PACKAGES` | `lodash@4.17.20,...` | npm audit bulk 输入 |
| `MAVEN_COMPONENTS` | `group:artifact@version,...` | Maven advisory/metadata 输入 |
| `NUGET_PACKAGES` | `Newtonsoft.Json,...` | NuGet metadata 输入 |
| `CVE_LIST_LOCAL_PATH` | `data/mirrors/cvelistV5` | CVE List v5 本地路径 |
| `RAW_OBJECT_STORE` | `pgsql` | 原始数据存储；默认压缩写入 PostgreSQL，`filesystem` 仅用于兼容旧部署 |
| `RAW_OBJECT_PATH` | `./data/raw-objects` | 仅在 `RAW_OBJECT_STORE=filesystem/dual` 时使用 |

## 数据流程

```
source-fetcher.mjs
  → 读取 sources.checkpoint_json (增量检查点)
  → 获取外部数据 (HTTP/Git)
  → 比对检查点 hash → 如未变化则跳过 (fetchedCount=0)
  → fetchJson/fetchBuffer (HTTP 下载)
  → writeRecord (压缩+去重+写入 source_objects 和 source_raw_index)
  → upsertXxx (写入 staging 表)
  → saveCheckpoint (更新 sources.checkpoint_json)
  → finishRun (更新 source_sync_runs)
```

## 检查点机制 (Checkpoint)

每个 fetcher 在成功运行后保存检查点到 `sources.checkpoint_json`。下次运行时:

| 来源 | 检查点策略 | 跳过条件 |
|------|-----------|---------|
| `cisa-kev` | 响应体 sha256 hash | hash 相同 |
| `first-epss` | 压缩数据 sha256 hash | hash 相同 |
| `alpine-secdb` | 每 release/repo 的 JSON hash | 所有 release/repo hash 相同 |
| `debian-security-tracker` | 响应体 sha256 hash | hash 相同 |
| `ubuntu-osv` | tar.xz 文件 hash | hash 相同 |
| `ghsa` | 最新 `updated_at` 时间 | 无新更新 |
| `cve-list-v5` | Git HEAD commit hash | commit 相同 |
| `osv` | all.zip 文件 hash | hash 相同 |
| `nvd-cve` | NVD `lastModStartDate` | 无新修改 |
| `nvd-cpe` | 压缩数据 sha256 hash | hash 相同 |

检查点保存在 `sources.checkpoint_json` 列，可在 Adminer 中直接查看。

## 常见问题

### GHSA 报 HTTP 403
```
HTTP 403 for https://api.github.com/advisories
```
GitHub API 限速。设置 `GITHUB_TOKEN` 环境变量:
```bash
export GITHUB_TOKEN=<github-token>
npm run fetch -- --source ghsa
```

### NVD 报 HTTP 429 / Cloudflare 1015
NVD Cloudflare 限速。设置 `NVD_API_KEY`:
```bash
export NVD_API_KEY=<nvd-api-key>
npm run fetch -- --source nvd-cve
```
无 API key 时每页间隔 10 秒。

### OSV 内存溢出 (OOM)
all.zip 约 500MB，fetcher 通过磁盘+unzip 流式处理。
确保 `/Volumes/NekoMac/Dev/VulTrack/data/mirrors/` 有足够空间 (~1GB)。

### CVE List v5 克隆失败
```
fatal: unable to access... Error in the HTTP2 framing layer
```
Git 协议问题。已使用 `http.version=HTTP/1.1` 浅克隆。
首次运行需下载 ~350MB Git 仓库。

### 查看运行状态
```bash
node -e "
const { Pool } = require('./node_modules/pg');
(async () => {
  const p = new Pool({ connectionString: 'postgres://vultrack:vultrack@localhost:5432/vultrack' });
  const r = await p.query(\"select s.code, r.status, r.fetched_count from source_sync_runs r join sources s on s.id=r.source_id where r.status='running'\");
  console.log(r.rows);
  await p.end();
})();
"
```

### 取消所有进行中的同步
```bash
node -e "
const { Pool } = require('./node_modules/pg');
(async () => {
  const p = new Pool({ connectionString: 'postgres://vultrack:vultrack@localhost:5432/vultrack' });
  await p.query(\"update source_sync_runs set status='cancelled', finished_at=now() where status='running'\");
  console.log('所有 running 同步已取消');
  await p.end();
})();
"
```

## 后台运行 (长时间任务)

```bash
nohup node plugins/fetchers/run-fetcher.mjs --source osv > data/logs/fetch-osv.log 2>&1 &
echo $!  # 记录 PID, 后续用 kill <PID> 停止
```

查看进度:
```bash
tail -f data/logs/fetch-osv.log
```
