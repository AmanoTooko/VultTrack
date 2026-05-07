# 插件通用设计规范

## 1. 插件目录

```text
plugins/{plugin-name}/
- plugin.json
- package.json
- src/
- fixtures/
- tests/
- README.md
```

## 2. plugin.json

```json
{
  "name": "nvd",
  "version": "0.1.0",
  "runtime": "node",
  "entry": "dist/index.js",
  "capabilities": ["source-fetcher", "source-parser"],
  "sources": ["nvd-cve"],
  "protocolVersion": "1.0"
}
```

## 3. 标准操作

```text
fetch.plan
fetch.execute
parse.execute
detail.render
version.normalize
version.compare
version.contains
llm.match
```

## 4. 测试要求

每个插件必须提供:

- `fixtures/small.json`
- `fixtures/changed.json`
- `fixtures/invalid.json`
- 协议测试。
- staging schema 测试。
- 幂等 hash 测试。

