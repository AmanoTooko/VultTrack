# Oracle ARM（4C / 24 GiB）部署与 DuckDB 迁移

本文是 Oracle Cloud Ampere ARM 生产机的当前运行手册。VulTrack 现在是
DuckDB-first 单体应用：生产 Compose 只有 `api` 与 `frontend`，不依赖
PostgreSQL、Redis 或独立 normalizer。

## 不变量

- 唯一事实存储是一个 DuckDB 文件；生产路径必须在 `.env.production` 中
  显式设置，不能依赖默认文件名。
- API、fetcher、spool ingestion、normalizer 与 snapshot worker 都在
  `VulTrack.App` 中；同一 DuckDB 文件只能有一个写入者。
- 第一次启动以及迁移期间保持 `VULTRACK_SCHEDULER_ENABLED=false` 和
  `DUCKDB_ALLOW_AUTOMATIC_INIT=false`。
- DuckDB 1.5.x 的[持久化 ART 损坏问题](https://github.com/duckdb/duckdb/issues/23645)尚未由上游关闭。VulTrack 当前会移除
  显式 ART 索引，以列式扫描和物化 snapshot 换取写入可靠性。
- 不在 ARM 主机本地交叉编译。CI 使用 QEMU/buildx 发布
  `linux/amd64,linux/arm64` manifest，服务器只拉取匹配本机架构的镜像。
- 不执行全局 `docker system prune`，不在没有清单和回滚副本时删除旧数据库。

## 镜像

默认生产镜像：

```text
ghcr.io/amanotooko/vultrack-api:latest
ghcr.io/amanotooko/vultrack-frontend:latest
```

生产迁移应固定到通过 CI 的 commit tag，而不是直接使用浮动 `latest`：

```bash
VULTRACK_API_IMAGE=ghcr.io/amanotooko/vultrack-api:<git-sha>
VULTRACK_FRONTEND_IMAGE=ghcr.io/amanotooko/vultrack-frontend:<git-sha>
```

自动部署默认关闭。只有仓库变量 `VULTRACK_AUTO_DEPLOY=true` 时，GitHub
Actions 才会执行生产部署。

生产 Compose 故意不为镜像 tag 或 DuckDB 路径提供 fallback；直接运行时若漏掉
`--env-file .env.production` 会立即失败，不能绕过路径与固定镜像门禁。

## 1. 只读预检

任何 pull、build、停止服务或数据复制前先记录：

```bash
uname -m
nproc
free -h
df -h / /home /var/lib/docker
docker version --format '{{.Server.Os}}/{{.Server.Arch}} {{.Server.Version}}'
docker system df
docker ps -a
git -C /home/ubuntu/vultrack status --short --branch
git -C /home/ubuntu/vultrack rev-parse HEAD
```

接受门槛：

- `uname -m` 为 `aarch64`/`arm64`；
- available memory 至少 4 GiB；
- swap 没有持续增长，内核日志没有 OOM kill；
- 根分区与 Docker 分区至少保留“当前 DuckDB 文件大小 + 20 GiB”；
- 没有正在运行的 fetch、normalizer、rebuild、snapshot rebuild；
- Git worktree 没有 tracked 修改。

如果磁盘接近满：先精确列出 stopped container、dangling image 与 build cache；
仅删除已经确认可重建、且不承担回滚用途的对象。绝不删除活跃 DuckDB、WAL、
spool partial/ready、`.env.production` 或旧 PG 数据。

## 2. 生产环境配置

在 `/home/ubuntu/vultrack/.env.production` 设置：

```dotenv
VULTRACK_ENV=production
VULTRACK_ADMIN_USERNAME=admin
VULTRACK_ADMIN_PASSWORD=<strong-random-password>

VULTRACK_STORAGE_BACKEND=duckdb
VULTRACK_DUCKDB_ENABLED=true
# 2026-08-15 Oracle 实机已有文件名；每台主机必须单独核对，不能照抄。
VULTRACK_DUCKDB_PATH=/workspace/data/duckdb/vultrack.duckdb
VULTRACK_DUCKDB_MEMORY_LIMIT=3g
VULTRACK_DUCKDB_THREADS=4
VULTRACK_SPOOL_PATH=/workspace/data/spool

VULTRACK_SCHEDULER_ENABLED=false
DUCKDB_ALLOW_AUTOMATIC_INIT=false
DUCKDB_FETCH_INTERVAL_SECONDS=3600
DUCKDB_FETCH_SOURCES=nvd-cve,osv,ghsa,google-osv,cnnvd,cisa-kev,first-epss,exploitdb,nuclei-templates,metasploit,poc-in-github,cargo-advisory

VULTRACK_API_IMAGE=ghcr.io/amanotooko/vultrack-api:<verified-git-sha>
VULTRACK_FRONTEND_IMAGE=ghcr.io/amanotooko/vultrack-frontend:<verified-git-sha>
```

按需设置 `GITHUB_TOKEN`、`NVD_API_KEY` 等 source 凭据。不要把秘密写入仓库、
日志或 handoff 文档。

部署脚本默认要求配置指向一个已存在、非符号链接、位于宿主机 `data/` 下的
DuckDB 文件；这会阻止文件名拼错时静默创建空库。只有明确的新建空节点才可临时
传入 `ALLOW_EMPTY_DUCKDB_INIT=true`。迁移执行时再传入
`REQUIRE_SCHEDULER_DISABLED=true`，让脚本强制核对 scheduler 门禁。

## 3. 首次切换（scheduler 关闭）

```bash
cd /home/ubuntu/vultrack
git fetch origin main
git merge --ff-only origin/main
REQUIRE_SCHEDULER_DISABLED=true ./scripts/deploy-prod.sh
```

验证：

```bash
curl -fsS http://127.0.0.1:3000/api/v1/system.health
curl -fsS http://127.0.0.1:3000/api/v1/system.ready
docker inspect vultrack-api --format '{{.RestartCount}}'
docker logs --tail=200 vultrack-api
```

登录后还必须验证：

- `GET /api/v1/system.status` 为 200；
- `storageBackend=duckdb` 且 path 等于配置的生产文件；
- 数据计数符合迁移基线；
- `readyFiles=0`、`processingFiles=0`，或每个 backlog 都有明确处置计划；
- 日志没有 Npgsql/PostgreSQL、`invalidated`、ART、OOM 或重复 restart。

`system.health` 只证明进程存活；`system.ready` 会真实查询 DuckDB，不能用
health 代替数据库就绪检查。

## 4. 恢复 AI 核心数据

AI 分析是唯一不可从公开源重建的数据。迁移前至少保留 Oracle、Cafemini 和离线
副本，并逐份验证 SHA-256、`gzip -t` 与数据行数。当前权威导出应为 63,247 条
（压缩文件共 63,248 行，含表头）。不要为此把生产 DuckDB 或原始 1 GB CSV
下载到本地外置 SSD；服务器已有压缩副本时应原地使用。

恢复不保留生产 API。GitHub Actions 从临时的 `tools/VulTrack.AiRecovery` 发布
`linux/amd64,linux/arm64` 多架构镜像，只打 commit SHA、不打 `latest`。停止 API
写入后，以 `--network none --read-only --rm` 运行同一 manifest 对应本机架构的
镜像；数据库目录读写挂载，服务器已有 gzip 只读挂载。工具使用与应用一致的
`DuckDB.NET.Data`/`DuckDB.NET.Bindings.Full 1.5.3`，单事务完成输入 63,247 行、
目录映射、JSON/数值、stage/target 全行一致和显式索引为 0 的校验；任一步不符
必须 rollback。先在 Cafemini 验证同一 digest，再在 Oracle ARM 执行。两端恢复、
计数与固定样本抽查完成后，从仓库/CI 删除 recovery 项目和构建步骤，并删除服务器
上的恢复镜像；只保留权威压缩备份及校验清单。最终应用镜像不包含导入能力。

## 5. 从开源数据重建

新 Oracle 节点不复制本地开发库时，按 source 串行重建。先保持自动 scheduler
关闭，通过受认证的 `POST /api/v1/admin.source.fetch` 一次运行一个 baseline；
每次都观察磁盘、available memory、swap、spool 与 API restart count。

建议顺序：

1. `nvd-cve-init`
2. `osv-init`
3. `ghsa` / `google-osv-init`（需要可靠 GitHub token）
4. 小型 threat/exploit source
5. FIRST EPSS 与大型镜像 source

不要并行 baseline，不要在 baseline 期间 rebuild snapshot 或清 Docker cache。
source 成功后记录 checkpoint、fetched/parsed/error count 与 DuckDB 表计数。

## 6. 启用 scheduler

只有 baseline 完成、status/coverage 正常、spool 没有未知 backlog 时才将：

```dotenv
VULTRACK_SCHEDULER_ENABLED=true
DUCKDB_ALLOW_AUTOMATIC_INIT=false
```

应用变更后，完整监督至少一个非 init 周期。fatal DuckDB invalidation 会使
scheduler fail-stop；这时 readiness 返回 503。先停写、备份现场并重启验证，
不能让 scheduler 反复重试。

## 7. 传输预算、回滚与清理

迁移默认使用 Oracle 上已有 DuckDB 与 AI 备份，不执行数据库 rsync。若确需在服务器
之间补充公开源 payload，单次传输硬上限为 30 GiB，先确认目标端余量并避免经过本地
Mac。payload 成功导入、checkpoint/计数核对且可从公开源重建后，删除目标端临时下载
副本；AI 备份不适用“导入后删除”规则。

迁移前记录旧 API/frontend image ID，保留上一 commit tag。回滚时固定旧 tag，
不要覆盖或删除当前 DuckDB/WAL。只有下列门禁全部通过后才能按白名单清理旧
PostgreSQL container/data、stopped test container 与 unreferenced image：

- API health、ready、status、search、detail、AI、SBOM smoke 全部通过；
- fetcher 与 normalizer 完成一个监督周期；
- restart count 为 0，无 OOM/ART/lock；
- DuckDB 文件、checkpoint 和备份/重建路径已记录；
- ARM 镜像 manifest 与运行容器架构一致。
