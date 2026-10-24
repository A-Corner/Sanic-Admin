# 规格即代码 MCP 服务

让 AI 通过 MCP 读取、校验、**预演**资源规格——但**不写仓库**。所有改动以 diff 形式
交给人看，走 PR + 独立审核。

> 设计原则：AI 只改规格、只出 diff，不直接改运行时。本服务属**第一层（元操作）**
> 的只读部分；第二层（对运行时数据的增删改）在后续版本实现，且必须复用同一
> RBAC/CSRF 栈。

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
- **已知限制（快照误报）**：快照是「前后各取一次哈希再比对」，因此**在 preview
  执行期间由别人（或你另一个窗口）改动被覆盖的文件，也会被报成
  `preview 修改了仓库文件`**。它无法区分「本服务写坏」与「第三方并发改动」。
  遇到这类报错时：先看报错里列出的路径是不是你自己刚改的（`git status` / `git diff`
  一眼可辨），是则重新跑一次即可；若无人改动却反复报同一路径，那才是真问题。
  需要彻底消除误报，得改成「写入拦截」式保障（如只读挂载/文件锁），本版本未做。
- **输入上限**：`validate_spec` / `preview_generate` 的 spec 文本上限 64KB；
  YAML 拒绝锚点（`&`）与别名（`*`）（防 billion laughs 别名炸弹），并限制嵌套
  深度（`tools.specgen.schema.SpecLoader`）。超限/命中的输入在校验阶段即报错。
- **临时目录**：位于系统临时区，`shutil.rmtree` 清理；测试断言不残留。
- **白名单**：资源名必须匹配 `^[a-z][a-z0-9_]*$`（整串匹配，末尾换行会被拒）；
  显式拒绝 `/`、`\`、`..` 与绝对路径，并在拼接后再校验结果确实落在 `specs/` 内
  （双重防护）。
- **不暴露**环境变量、数据库连接与密钥：工具只回规格与生成物本身。错误信息里的
  本机绝对路径、HOME 与临时目录前缀统一脱敏为 `<path>`（有测试断言）。脱敏发生在
  **工具层统一出口**：五个工具（含 `list_resources`、`describe_resource`、`check`）
  抛出的异常都会先脱敏再回到客户端，未预料的底层异常也会转成脱敏后的可读原因；
  兜底路径正则只匹配「至少两段」的绝对路径，不会把 `a/b`、`string/int` 这类普通
  文本误当路径抹掉（同样有测试断言）。

## 安装

```bash
pip install "mcp==2.3.0"
```

> **版本说明**：mcp 2.x 把 `FastMCP` 改名为 `MCPServer`
> （`from mcp.server.mcpserver import MCPServer`）。本服务按 2.x API 编写；
> 若需 1.x，须改用 `mcp.server.fastmcp.FastMCP`（接口不同）。
>
> **Python 版本**：mcp 2.3.0 的 `Requires-Python` 是 `>=3.10`（PyPI JSON API 与
> wheel `METADATA` 均是此值，classifiers 明确列出 3.10–3.14），因此 CI 矩阵里的
> Python 3.10 **受支持**，无需跳过 MCP 测试。**但**它的传递依赖 `httpx2` 在
> 2.15.0 起把 `Requires-Python` 抬到 `>=3.11`（2.14.0 及以前是 `>=3.10`）。
> 解析器会为 3.10 自动回退到 2.14.x，但仍建议在 CI 上锁一下：
> `httpx2<2.15; python_version < "3.11"`，避免将来解析行为变化或低版本缺少修复。

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

## 写入工具的启用与身份（spec:write，v0.4.2 起）

写入工具（`propose_spec_change` / `list_proposals` / `discard_proposal`）默认不注册，
启用与可用要**同时**满足两个门槛（AND，设计见 `docs/mcp-write-path.md` §10.6）：

1. **部署门槛**：启动参数加 `--allow-write`——不加，三个工具不出现在 `tools/list`。
2. **身份门槛**：环境变量 `SANIC_ADMIN_MCP_TOKEN` 配置为有效的会话 JWT，且该账户
   拥有 `spec:write` 权限（admin 默认拥有；普通角色在角色管理里显式授予）。

每次调用写入工具都会实时调 `GET /auth/whoami` 校验（走与 HTTP API 相同的鉴权栈），
任何失败——token 缺失、无效、过期、2FA 未完成、需要改密、没有 `spec:write`、
Sanic 服务不可达——一律拒绝且零副作用（不建 clone、不建分支）。

环境变量：

| 变量 | 说明 |
|---|---|
| `SANIC_ADMIN_MCP_TOKEN` | 会话 JWT（登录接口 `Authorization` 头下发的同一个 token）。缺失时写入工具可见但调用被拒。**换 token = 重启 MCP 进程**；吊销 = 在服务端作废该会话，下一次调用即失效 |
| `SANIC_ADMIN_MCP_API_URL` | 可选。whoami 服务地址，默认 `http://127.0.0.1:22222`（本机回环，token 默认不出本机）。指向别的主机必须显式配置 |

安全约定：token 只经环境变量进入进程，不写入日志、审计与错误消息；回调超时 5 秒，
失败不重试（fail-closed）。会话 JWT 有过期时间，过期后重新登录取新 token 并重启
进程；专用的长期 API token 是后续项，本版不提供。

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
- 错误与预览输出不泄露环境变量/密钥，也不含绝对路径、HOME、临时目录前缀；
  **三个额外出口**（`list_resources` / `describe_resource` / `check`）各有一条
  「读坏规格触发底层异常」的脱敏用例，另有「兜底正则不得误伤 `a/b` 类文本」的
  正向对照
- 已注册工具名与本文档契约一致（公开 API）；以及对子进程发 `initialize` +
  `tools/list` 的真实 stdio 握手冒烟（读响应带超时，服务端挂起时判失败而不是
  把 CI 拖到 job 超时；「超时机制本身有效」另有正向对照）

> `mcp` 装在 `requirements-dev.txt`，CI 的 test job 用
> `pip install -r requirements.txt -r requirements-dev.txt` 安装后运行 `pytest tests/`。
