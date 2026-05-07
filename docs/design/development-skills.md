# 开发可用 Skills 和 Agent 分工

本文件记录当前 Codex 环境中对开发有帮助的技能，以及建议创建的项目内开发约定。

## 1. 当前可用 Skills

| Skill | 用途 | 建议使用场景 |
|---|---|---|
| `browser-use:browser` | 打开、测试、截图本地 Web 页面 | 前端项目或 Swagger/UI 冒烟测试 |
| `plugin-creator` | 创建 Codex 插件目录结构 | 后续如果把 VulTrack 插件做成 Codex 插件时使用 |
| `skill-creator` | 创建新的 Codex skill | 为项目沉淀开发流程、测试流程、代码审查流程 |
| `openai-docs` | 查询 OpenAI 官方 API 文档 | LLM matcher 插件需要对接 OpenAI 时使用 |
| `spreadsheets` | 处理 xlsx/csv | 大规模源清单、漏洞字段映射表导入导出 |
| `documents` | 处理 docx | 需要输出正式设计文档或评审材料时使用 |

## 2. 建议新增项目内 Skills

这些不是当前已安装 skill，而是建议后续创建到项目中的开发辅助规则:

```text
vultrack-db-migration
- 生成 EF Core migration
- 检查 migration 是否包含 destructive change
- 运行空库初始化和重复初始化测试

vultrack-plugin-fixture
- 为 source 插件创建 fixture
- 运行插件 stdin/stdout 协议测试
- 对 staging 输出做 schema 校验

vultrack-api-contract
- 检查 API 只使用 GET/POST
- 校验请求/响应 JSON schema
- 生成客户端类型

vultrack-ingest-test
- 构造 source sync run
- 验证 raw object、raw index、staging、normalize 状态流转

vultrack-security-review
- 检查插件沙盒、raw payload 下载权限、XSS block 渲染风险
```

## 3. Agent 分工建议

| Agent | 负责文件 | 输出 |
|---|---|---|
| DB Agent | `database.md` | migration、seed、索引、初始化脚本 |
| API Agent | `contracts/api-rpc.md`, `modules/query-api.md` | .NET controller/minimal API、DTO、鉴权 |
| Ingestion Agent | `modules/ingestion.md` | source sync、raw object、staging writer |
| Plugin Agent | `plugins/*/design.md`, `modules/plugin-runtime.md` | Node.js 插件和 fixture |
| Matching Agent | `modules/component-matcher.md`, `modules/version-resolver.md` | component/affected/resolver |
| Test Agent | `testing/test-plan.md` | smoke/integration test suite |

