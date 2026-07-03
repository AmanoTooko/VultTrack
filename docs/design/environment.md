# 环境变量和部署配置

## 1. 必填环境变量

```text
VULTRACK_ENV=development
VULTRACK_PUBLIC_URL=http://localhost:8080

POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=vultrack
POSTGRES_USER=vultrack
POSTGRES_PASSWORD=change-me

RAW_OBJECT_STORE=pgsql

PLUGIN_ROOT=/app/plugins
PLUGIN_NODE_BIN=/usr/local/bin/node
PLUGIN_TIMEOUT_SECONDS=60
PLUGIN_MAX_STDOUT_BYTES=10485760
PLUGIN_MAX_CONCURRENCY=4

JWT_ISSUER=vultrack
JWT_AUDIENCE=vultrack-api
JWT_SIGNING_KEY=change-me-at-least-32-bytes
```

## 2. 可选环境变量

```text
S3_ENDPOINT=
S3_BUCKET=vultrack-raw
S3_ACCESS_KEY=
S3_SECRET_KEY=
S3_FORCE_PATH_STYLE=true

NVD_API_KEY=
GITHUB_TOKEN=

LLM_MATCHER_ENABLED=false
LLM_PROVIDER=
LLM_API_KEY=

LOG_LEVEL=Information
OTEL_EXPORTER_OTLP_ENDPOINT=
```

## 3. 目录约定

```text
/app
  /VulTrack.Api
  /VulTrack.Core
  /VulTrack.Infrastructure
  /plugins
    /nvd
    /ghsa
    /osv
    /cve-list
    /threat-intel
/data
  /duckdb
  /vulnerability-details
  /logs
```

## 4. Docker Compose MVP

```text
services:
  vultrack-app:
    image: vultrack-app:local
    depends_on:
      - postgres
    ports:
      - "8080:8080"
    environment:
      POSTGRES_HOST: postgres
      RAW_OBJECT_STORE: pgsql

  postgres:
    image: postgres:16

```

raw object 默认以 gzip 压缩 bytea 写入 PostgreSQL，并通过 source hash 去重；旧部署可用迁移脚本回收 filesystem object store。
