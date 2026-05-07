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

REDIS_CONNECTION=redis:6379

RAW_OBJECT_STORE=filesystem
RAW_OBJECT_PATH=/data/raw-objects

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
  /raw-objects
  /plugin-tmp
  /logs
```

## 4. Docker Compose MVP

```text
services:
  vultrack-app:
    image: vultrack-app:local
    depends_on:
      - postgres
      - redis
    ports:
      - "8080:8080"
    volumes:
      - vultrack_raw:/data/raw-objects
    environment:
      POSTGRES_HOST: postgres
      REDIS_CONNECTION: redis:6379

  postgres:
    image: postgres:16

  redis:
    image: redis:7
```

MinIO/S3 是可选项。MVP 使用 filesystem object store 即可。

