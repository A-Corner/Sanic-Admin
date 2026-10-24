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

- **只读**：不改任何文件。`preview_generate` 先对仓库相关文件取哈希快照
  （`specs/*.yaml`、`amis/pages/site.json`、其余 `amis/pages/*-list.json`、
  `app/auth/permissions.py`、`app/generated/**` 与各生成包的 `__init__.py`、
  `tests/generated/*.py`），返回前复核未变；一旦发现被改动会直接报错并列出
  有差异的路径，而不是静默通过。
- **快照是事后检测**：它只负责**发现**改动，不负责**阻止**改动。真正的只读保障
  是实现本身——生成全部发生在系统临时目录，仓库只被读取。
- **输入上限**：`validate_spec` / `preview_generate` 的 spec 文本上限 64KB；
  YAML 拒绝锚点（`&`）与别名（`*`）（防 billion laughs 别名炸弹），并限制嵌套
  深度（`tools.specgen.schema.SpecLoader`）。超限/命中的输入在校验阶段即报错。
- **临时目录**：位于系统临时区，`shutil.rmtree` 清理；测试断言不残留。
- **白名单**：资源名必须匹配 `^[a-z][a-z0-9_]*$`（整串匹配，末尾换行会被拒）；
  显式拒绝 `/`、`\`、`..` 与绝对路径，并在拼接后再校验结果确实落在 `specs/` 内
  （双重防护）。
- **不暴露**环境变量、数据库连接与密钥：工具只回规格与生成物本身。错误信息里的
  本机绝对路径、HOME 与临时目录前缀统一脱敏为 `<path>`（有测试断言）。

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

覆盖：

- 每个工具的正例与反例；路径穿越拒绝（含末尾换行等 11 种变体）
- 输入上限：超长文本、billion laughs 别名炸弹、深嵌套——`validate_spec` 与
  `preview_generate` 两条入口都各有用例，且都断言被拒
- preview 前后仓库文件哈希不变；快照范围（specs / site.json / permissions.py /
  各包 `__init__`）逐项断言；**正向对照**：快照后篡改文件，比对必须报出差异
- 错误与预览输出不泄露环境变量/密钥，也不含绝对路径、HOME、临时目录前缀
- 已注册工具名与本文档契约一致（公开 API）；以及对子进程发 `initialize` +
  `tools/list` 的真实 stdio 握手冒烟

> `mcp` 装在 `requirements-dev.txt`，CI 的 test job 用
> `pip install -r requirements.txt -r requirements-dev.txt` 安装后运行 `pytest tests/`。
