# 规格即代码 MCP 服务

让 AI 通过 MCP 读取、校验、**预演**资源规格——但**不写仓库**。所有改动以 diff 形式
交给人看，走 PR + 独立审核。

> 设计原则（`docs/release/v0.4.0-iteration-plan.md` §5）：AI 只改规格、只出 diff，
> 不直接改运行时。本服务属**第一层（元操作）**的只读部分；第二层（对运行时数据的
> 增删改）在后续版本实现，且必须复用同一 RBAC/CSRF 栈。

## 工具

| 工具 | 作用 | 写盘 |
|---|---|---|
| `list_resources` | 列出 `specs/` 下的资源与字段摘要 | 否 |
| `describe_resource` | 返回规格全文、生成物路径、权限点 | 否 |
| `validate_spec` | pydantic 校验规格文本，错误带字段路径 | 否 |
| `preview_generate` | 临时目录生成，返回与仓库现状的 unified diff | **否（临时目录用后即删）** |
| `check` | 生成物与规格是否一致（等价 `specgen check`） | 否 |

### 安全边界

- **只读**：不改任何文件。`preview_generate` 先在仓库生成物哈希快照，返回前复核
  未变；一旦发现被改动会直接报错而不是静默通过。
- **临时目录**：位于系统临时区，`shutil.rmtree` 清理；测试断言不残留。
- **白名单**：资源名必须匹配 `^[a-z][a-z0-9_]*$`；显式拒绝 `/`、`\`、`..` 与绝对路径，
  并在拼接后再校验结果确实落在 `specs/` 内（双重防护）。
- **不暴露**环境变量、数据库连接与密钥：工具只回规格与生成物本身（有测试断言）。

## 安装

```bash
pip install "mcp==2.3.0"
```

> **版本说明**：mcp 2.x 把 `FastMCP` 改名为 `MCPServer`
> （`from mcp.server.mcpserver import MCPServer`）。本服务按 2.x API 编写；
> 若需 1.x，须改用 `mcp.server.fastmcp.FastMCP`（接口不同）。

依赖已写入 `requirements-dev.txt`（MCP 服务用于开发期与 AI 协作，不属运行时依赖）。

## 在 Claude Code 中配置

在仓库根的 `.mcp.json`（或用户级 MCP 配置）中加入：

```json
{
  "mcpServers": {
    "sanic-admin-specgen": {
      "command": "python",
      "args": ["-m", "tools.mcp_server"],
      "cwd": "/absolute/path/to/Sanic-Admin"
    }
  }
}
```

`cwd` 必须是仓库根（服务据此定位 `specs/` 与生成物）。也可显式指定：

```json
{ "command": "python", "args": ["-m", "tools.mcp_server", "--root", "/absolute/path"] }
```

## 在 Codex 中配置

Codex 的 MCP 配置同样接受 stdio 子进程，形如（字段名以 Codex 当前版本为准）：

```toml
[mcp_servers.sanic-admin-specgen]
command = "python"
args = ["-m", "tools.mcp_server"]
cwd = "/absolute/path/to/Sanic-Admin"
```

## 典型用法

```
AI: list_resources()                      → 看到 customer / order 及其字段
AI: describe_resource("customer")         → 拿到规格全文与权限点
AI: validate_spec(改后的 yaml)            → 字段级错误（若有）
AI: preview_generate(改后的 yaml)         → unified diff
人: 审 diff → 同意后由人执行 generate + 提 PR
```

AI **不会**直接调用 `generate` 写盘——那一步由人确认后执行，或由 CI 在 PR 上校验
（`specgen check` 已在 CI 的 test job 里）。

## 验证

```bash
pytest tests/test_mcp_server.py -q
```

覆盖：每个工具的正例与反例、路径穿越拒绝（9 种变体）、preview 前后仓库哈希不变、
临时目录清理、不泄露环境变量/密钥。
