# API 契约: RPC 风格 GET/POST

## 1. 约束

- 只允许 `GET` 和 `POST`。
- 不使用 PUT/PATCH/DELETE。
- 读操作优先 `GET`，复杂查询可用 `POST`。
- 写操作全部 `POST`。
- 路径使用动作名，不依赖 REST resource verb。
- 请求和响应都是 JSON，除健康检查外。

## 2. 通用响应

成功:

```json
{
  "ok": true,
  "data": {},
  "requestId": "string"
}
```

失败:

```json
{
  "ok": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "human readable message",
    "details": {}
  },
  "requestId": "string"
}
```

分页:

```json
{
  "items": [],
  "page": 1,
  "pageSize": 50,
  "total": 0
}
```

## 3. System

```text
GET  /api/v1/system.health
GET  /api/v1/system.ready
GET  /api/v1/system.metrics
```

## 4. Auth

```text
POST /api/v1/auth.login
POST /api/v1/auth.refresh
POST /api/v1/auth.logout
GET  /api/v1/auth.me
```

## 5. Vulnerability

```text
POST /api/v1/vulnerability.search
GET  /api/v1/vulnerability.get?id={uuid}
GET  /api/v1/vulnerability.getByIdentifier?identifier={value}
GET  /api/v1/vulnerability.identifiers?id={uuid}
GET  /api/v1/vulnerability.severityScores?id={uuid}
GET  /api/v1/vulnerability.records?id={uuid}
GET  /api/v1/vulnerability.rawIndex?id={uuid}
GET  /api/v1/vulnerability.affectedComponents?id={uuid}
POST /api/v1/vulnerability.affectedEvidence
GET  /api/v1/vulnerability.detailBlocks?id={uuid}
```

### 5.1 vulnerability.search

Request:

```json
{
  "query": "openssl",
  "identifier": "CVE-2024-0001",
  "ecosystems": ["maven", "npm"],
  "severity": ["critical", "high"],
  "kev": true,
  "epssMin": 0.5,
  "page": 1,
  "pageSize": 50,
  "sort": "risk_desc"
}
```

Response item:

```json
{
  "id": "uuid",
  "primaryIdentifier": "CVE-2024-0001",
  "title": "...",
  "severityLabel": "critical",
  "maxCvssScore": 9.8,
  "epssScore": 0.92,
  "kev": true,
  "affectedComponentCount": 3,
  "affectedComponentNames": ["openssl"],
  "publishedAt": "2024-01-01T00:00:00Z",
  "modifiedAt": "2024-01-02T00:00:00Z"
}
```

### 5.2 vulnerability.get

Response:

```json
{
  "id": "uuid",
  "primaryIdentifier": "CVE-2024-0001",
  "identifiers": [],
  "title": "...",
  "description": "...",
  "severity": {
    "label": "critical",
    "cvssScore": 9.8,
    "cvssVersion": "3.1",
    "cvssVector": "CVSS:3.1/..."
  },
  "risk": {
    "epssScore": 0.92,
    "kevDateAdded": "2024-01-01"
  },
  "affectedComponents": [],
  "detailBlocks": []
}
```

### 5.3 vulnerability.affectedEvidence

Request:

```json
{
  "affectedComponentId": "uuid"
}
```

Response:

```json
{
  "affectedComponentId": "uuid",
  "evidence": [
    {
      "kind": "source_fact",
      "source": "nvd-cve",
      "supportsConclusion": false,
      "confidence": 0.9,
      "value": {}
    }
  ]
}
```

## 6. Component

```text
POST /api/v1/component.search
GET  /api/v1/component.get?id={uuid}
GET  /api/v1/component.vulnerabilities?id={uuid}
POST /api/v1/component.vulnerabilitySearch
POST /api/v1/component.mappingCandidates
POST /api/v1/component.mappingApprove
POST /api/v1/component.mappingReject
```

### 6.1 component.vulnerabilitySearch

用于在尚未拥有完整 SBOM 的情况下，根据组件名、版本、供应商、生态或 PURL 查询匹配组件和已知漏洞。

Request:

```json
{
  "componentName": "log4j-core",
  "version": "2.14.1",
  "vendor": "org.apache.logging.log4j",
  "ecosystem": "maven",
  "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
  "pageSize": 50
}
```

Response:

```json
{
  "componentName": "log4j-core",
  "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
  "purlWithoutVersion": "pkg:maven/org.apache.logging.log4j/log4j-core",
  "items": [
    {
      "vulnerabilityId": "uuid",
      "primaryIdentifier": "CVE-2021-44228",
      "title": "Apache Log4j remote code execution",
      "severityLabel": "critical",
      "cvssScore": 10.0,
      "ecosystem": "maven",
      "packageName": "org.apache.logging.log4j:log4j-core",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core",
      "versionRange": "< 2.15.0",
      "rangeType": "SEMVER",
      "versionMatched": true
    }
  ]
}
```

## 7. Match

```text
POST /api/v1/match.purl
POST /api/v1/match.cpe
POST /api/v1/match.package
```

### 7.1 match.purl

Request:

```json
{
  "purl": "pkg:maven/org.example/foo@1.2.3"
}
```

Response:

```json
{
  "matches": [
    {
      "vulnerabilityId": "uuid",
      "primaryIdentifier": "CVE-2024-0001",
      "affectedComponentId": "uuid",
      "range": "<2.0.0",
      "matched": true,
      "confidence": 0.95
    }
  ]
}
```

## 8. Source and Sync

```text
GET  /api/v1/source.list
GET  /api/v1/source.get?code={sourceCode}
POST /api/v1/source.syncStart
GET  /api/v1/source.syncRun?id={uuid}
POST /api/v1/source.syncRuns
POST /api/v1/source.errorSearch
POST /api/v1/source.errorRetry
```

## 9. Raw

```text
POST /api/v1/raw.search
GET  /api/v1/raw.get?id={uuid}
GET  /api/v1/raw.payload?id={uuid}
```

`raw.payload` 需要 `SourceMaintainer` 或 `Admin` 权限，并写审计日志。

## 10. Admin

```text
POST /api/v1/admin.sourceEnable
POST /api/v1/admin.sourceDisable
POST /api/v1/admin.pluginReload
POST /api/v1/admin.identifierMerge
POST /api/v1/admin.identifierSplit
GET  /api/v1/admin.auditLogs
```
