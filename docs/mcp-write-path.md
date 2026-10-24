# MCP 写入路径设计（M2 第二段）

> 状态：设计稿。对应 EGC 计划 `docs/release/v0.4.0-iteration-plan.md` §2.1 的 M2。
> 前置：只读层在 PR #15（`8a8e527`）。本文描述的写入路径建立在其上，**不改动只读层的既有工具**。

## 1. 目标与非目标

### 目标

AI 通过 MCP 提交规格变更，系统产出：

1. 一份 **unified diff**（规格 + 生成物 + 迁移文件）
2. 一个 **本地 git 分支**，分支上有一个 commit

然后由**人**来开 PR、审查、合并。

### 非目标（明确不做）

| 不做 | 原因 |
|---|---|
| 直接写 master | AI 的产出必须经过人工审查。这是硬红线 |
| 直接 push 到任何 remote | 见 §6 的机制保证 |
| 直接修改运行中的服务 | Sanic 的 `app.amend()` 只能加不能删；本设计采用「生成后重启」，不在运行中热改 |
| 在用户的工作区里操作 | 见 §4 的隔离 |
| 删除或修改已有 commit | 只创建新分支，不做任何历史改写 |

## 2. 工具清单

在只读层五个工具之外新增四个。命名与前缀保持 `spec` 域一致。

| 工具 | 作用 | 是否落盘 |
|---|---|---|
| `propose_spec_change` | 接收规格文本与可选说明，产出分支 + diff 统计 | **是**（仅在工作区内） |
| `list_proposals` | 列出本机已产生的提案分支及其状态 | 否 |
| `discard_proposal` | 删除一个提案分支 | 是（删除自己的产物） |
| `describe_proposal` | 返回某个提案的完整 diff 与元数据 | 否 |

### 2.1 `propose_spec_change`

**输入**

```json
{
  "resource": "ticket",
  "spec_yaml": "name: ticket\nfields:\n  ...",
  "note": "add priority field"
}
```

- `resource` 必须匹配 `^[a-z][a-z0-9_]*$`（复用只读层的 `_guard_resource_name`）
- `spec_yaml` 上限 64 KB（复用 `_guard_spec_text`，含 YAML 锚点/别名与嵌套深度防护）
- `note` 上限 200 字符，仅进 commit message 与返回值，**不进任何 shell 命令**

**处理步骤**

1. 校验规格（`validate_spec`，pydantic）
2. 失败则**不产生任何分支**，直接返回字段级错误
3. 在隔离 clone 中写入规格、运行生成器与迁移生成
4. 计算并返回 diff（unified + 统计）
5. commit 到新分支
6. 写审计记录
7. 返回分支名、commit SHA、diff 统计

**输出**

```json
{
  "proposal_id": "prop-20261024-193012-a1b2c3",
  "branch": "proposal/ticket-20261024-193012",
  "commit": "abc1234",
  "diff_stat": "3 files changed, 42 insertions(+), 2 deletions(-)",
  "diff": "--- a/specs/ticket.yaml\n+++ ...",
  "next_step": "由人执行 git push 并开 PR；本工具不会 push"
}
```

**注意**：`next_step` 字段是刻意的——返回值本身告诉调用方「下一步是人做的事」。

### 2.2 `list_proposals`

列出本机提案分支，字段：`proposal_id`、`branch`、`resource`、`created_at`、`commit`、`status`。不读远程，只读本地分支列表里 `proposal/*` 前缀的。

### 2.3 `discard_proposal`

删除指定提案分支。只允许删除 `proposal/` 前缀的分支——防止误删用户分支。分支上有未合并 commit 时，需要 `force=true` 才删，否则报错要求确认。

### 2.4 `describe_proposal`

返回某提案的完整 diff、commit message、审计记录。用于人工审查前的预览。

## 3. 权限与令牌范围

### 3.1 两层权限

| 层 | 内容 | 谁控制 |
|---|---|---|
| MCP 工具层 | 调用方以绑定账户身份经过与 HTTP API 相同的鉴权栈；`propose_spec_change` 要求 `spec:write` 权限点 | 项目 RBAC |
| 操作系统层 | 工具进程以**运行它的用户**身份执行 git 命令，不额外提权、不调用 `sudo` | 部署方 |

### 3.2 令牌范围

- 工具**不持有**任何 Git remote 凭据（token、SSH key、credential helper 都不碰）
- 工具**不读取**环境变量里的 `GH_TOKEN`、`GITHUB_TOKEN` 等——只读层已有「不暴露环境变量」的约束，写入层沿用
- 调用方的 MCP 会话凭据只用于鉴权校验，不落盘

### 3.3 权限点注册

新增权限点 `spec:write`，注册进 `ALL_PERMISSIONS`（`app/auth/permissions.py`），与现有资源的权限点同构。默认只有 `is_admin` 账户拥有。

## 4. 分支命名与隔离

### 4.1 命名规则

```
proposal/<resource>-<timestamp>
```

例：`proposal/ticket-20261024-193012`

- 前缀 `proposal/` 是硬性的：`discard_proposal` 与 `list_proposals` 都靠它识别自己的产物，且只操作这个前缀
- `resource` 已经过白名单校验（`^[a-z][a-z0-9_]*$`），不含 `/`、`..`、`-` 开头
- timestamp 由服务端生成，不接受调用方提供——避免并发覆盖

### 4.2 隔离方式：`git clone --no-hardlinks --local`（**不是** worktree）

```bash
tmp=$(mktemp -d)
git clone --no-hardlinks --local <repo> "$tmp/repo"
cd "$tmp/repo"
git remote remove origin                     # 从根上没有推送目标
git config push.default nothing
git config credential.helper ""              # 置空，切断用户本机的 helper
install .git/hooks/pre-push -> exit 1        # 无条件拦截
# ... 写规格、生成、commit ...
cd <repo>
git fetch "$tmp/repo" <branch>:<branch>      # 由用户在仓库这一侧拉回
rm -rf "$tmp"
```

#### 为什么不用 worktree（关键取舍）

`git worktree` 与主仓库**共享 `.git` 目录**。这带来两个无法回避的问题：

1. **hook 与 config 是共享的。** 把 `pre-push` hook 装进 worktree 的 `.git/hooks`，实际装的是**用户仓库的** `.git/hooks`——会拦住用户自己的正常 push，属于对用户环境的破坏性修改。
2. **`push.default`、`credential.helper` 同理**，写进去就改的是用户仓库的配置。

而 worktree 的唯一优势（快、省空间）在本场景不重要——提案是一次性操作，clone 一个中等规模仓库在秒级。

#### clone 方案的取舍

| 优点 | 代价 |
|---|---|
| 独立 `.git`，hook / config 只影响临时目录，**对用户仓库零侵入** | 比 worktree 慢（要复制 object） |
| `git remote remove origin` 后从根上没有推送目标 | 需要一次 `git fetch` 把分支拉回 |
| hook 与 config 可以在 clone 内随意设置，删掉即回收 | 临时目录需显式清理 |

**`--no-hardlinks` 的必要性**：默认 `--local` 会用硬链接共享 object 文件。虽然 git 对 object 是只读的，但硬链接意味着临时 clone 与用户仓库共享 inode——一旦有工具误改 object 文件会同时污染两边。`--no-hardlinks` 强制真实复制，换来彻底隔离。

#### 分支如何回到用户仓库

`git fetch "<tmp>/repo" <branch>:<branch>"`，**在用户仓库这一侧执行**。这样：

- 分支出现在用户仓库里（这正是要的结果——人在自己的仓库里就能看到分支、开 PR）
- fetch 是读操作，不触碰任何 remote，不需要凭据
- 目标分支已存在时，git **原生拒绝覆盖**（实测：不带 `--force` 时 `fetch` 报错且原分支 SHA 不变）。工具不传 `--force`，因此「不能覆盖已存在的分支」由 git 自己保证，不靠我们的代码

#### 必须做的防护

1. `tmp` 用 `tempfile.mkdtemp()` 创建，**在仓库之外**
2. 操作前记录用户仓库当前分支与 HEAD，操作后核验未变
3. 任何一步失败都 `rm -rf "$tmp"`，不留临时目录
4. `fetch` 失败（如分支已存在）时**不尝试强推**，返回错误让人处理
5. 删除临时 clone 前核验分支已成功 fetch 回用户仓库——删早了会丢提案

### 4.3 并发

同一资源并发提案时，分支名带 timestamp，不会撞名。但两个提案可能基于同一个 base-ref，产生语义冲突——这**不是本层要解决的**，由人工在 PR 阶段处理。工具会在返回值里带上 `base_ref` 与 `base_commit`，让人能判断。

## 5. 审计记录

复用 v0.3.4 的 `app/services/audit.py` 基础设施，但不混用认证事件——新增 `operation_type = "mcp"`。

| 字段 | 内容 |
|---|---|
| `operation` | `propose_spec_change` / `discard_proposal` |
| `operation_type` | `mcp` |
| `account` | 调用方账户 |
| `status` | `success` / `failure` |
| `detail` | 资源名、分支名、commit SHA、diff 统计；`discard` 另记被删分支 |
| `ip_address` / `user_agent` | 不适用（stdio 本地进程），记为 `stdio` / MCP 客户端标识 |

**约束（与认证审计一致）**：不写规格全文（可能含业务敏感字段定义）、不写任何凭据、写失败只记 warning 不影响主流程。

审计写入失败**不阻断**提案——但返回值里带 `audit_written: false`，让调用方知道。

## 6. 「AI 不能 push 或合并」的机制保证

这是设计要求里最硬的部分。**不能只写「我们不 push」**，必须有机制，且机制要被测试证明。

关键前提：**MCP 进程是以用户身份在本机运行的**，它会继承用户的 git 凭据——用户自己的 credential helper、SSH agent、`.netrc` 对它全部可用。因此「拿不到凭据」这条**不足以**保证不能 push。必须从「没有推送目标」和「有目标也推不出去」两侧同时封死。

### 6.1 第一层：临时 clone 里没有推送目标

clone 完成后立刻：

```bash
git remote remove origin
git config push.default nothing
git config credential.helper ""
```

`git remote remove origin` 之后，clone 里**不存在任何 remote**。此时 `git push` 直接报「没有配置推送目标」——不是被拒绝，是**没有目标可推**。

### 6.2 第二层：即使有人加了 remote，pre-push hook 也无条件拦截

在 clone 的 `.git/hooks/pre-push` 装：

```sh
#!/bin/sh
exit 1
```

无条件 `exit 1`。**注意**：因为用的是独立 clone（不是 worktree），这个 hook 只影响临时目录，**不会污染用户仓库的 `.git/hooks`**。

### 6.3 第三层：工具代码的 git 命令白名单

所有 git 调用经由单一的 `_git(args: list[str])` 函数，**白名单之外直接抛 `ToolError`**：

| 允许 | 拒绝（示例，非穷举） |
|---|---|
| `clone` | `push`、`fetch`（在 clone 内）、`pull` |
| `add`、`commit`、`diff`、`log`、`status` | `remote add`、`remote set-url`、`remote rename` |
| `branch`（list / -D 限于 `proposal/` 前缀） | `config`（写入）、`reset --hard`、`clean -fdx` |
| `rev-parse`、`ls-files` | `merge`、`rebase`、`cherry-pick`、`revert` |
| `fetch`（**仅在用户仓库侧、且目标是本地路径**） | `submodule`、`filter-branch` |

**例外说明**：`fetch` 出现在允许列表里，但仅限「在用户仓库里、源是临时 clone 的本地路径」这一种形态。实现上用单独的函数 `_fetch_from_local_clone()` 承载，参数形态固定，不接受调用方传入任意 remote 名。

白名单不是约定，是代码路径可达性约束——见 §6.5 的正向对照。

### 6.4 第四层：合并能力根本不存在

工具没有任何 `merge` / `rebase` / `cherry-pick` 的代码路径，也不调用 GitHub API（无 `gh`、无 HTTP 客户端）。合并只能由人在 GitHub 或本地执行。

### 6.5 正向对照（必须存在，且必须能失败）

**对照 A：`test_git_whitelist_rejects_push`**

1. 直接调用内部 `_git(["push", "x", "y"])`
2. 断言抛 `ToolError`，错误信息说明子命令不在白名单
3. **若有人把 `push` 加进白名单，这条测试立刻红**

**对照 B：`test_pre_push_hook_blocks_even_with_remote`**（CPL 指定的场景）

1. 建临时用户仓库 + 临时 bare 仓库
2. 跑完整 `propose_spec_change`
3. 进入临时 clone，**手动** `git remote add evil <bare路径>`（模拟绕过第一层）
4. 尝试 `git push evil <branch>`
5. **断言 push 失败**，且 `git --git-dir=<bare> for-each-ref` 输出为空

> 这条已在文档编写阶段实测：加 remote 后 push 报「错误：无法推送一些引用」，bare 仓库 ref 数为 **0**。

**对照 C：`test_propose_never_touches_user_repo_config`**

断言用户仓库的 `.git/config` 与 `.git/hooks/` 在提案前后**逐字节一致**——这一条专门验证「改用 clone 而非 worktree」是否真的做到了零侵入。

**对照 D：`test_fetch_does_not_overwrite_existing_branch`**

目标分支已存在时，`git fetch <clone> <branch>:<branch>` 必须失败且原分支 SHA 不变（git 原生行为，工具不传 `--force`）。

### 6.6 为什么这四层合起来够

| 攻击/失误场景 | 被哪层挡住 |
|---|---|
| 代码里写了 push | 第一层（无 remote）+ 第三层（白名单拒绝）|
| 有人手工把 push 加进白名单 | 第一层（无 remote）+ 第二层（hook） |
| 有人手工加 remote 想推 | 第二层（pre-push hook 无条件 exit 1） |
| 用户本机 credential helper 可用 | 一、二层不依赖凭据；第三层 `credential.helper` 已置空 |
| 想合并 | 第四层（无代码路径） |

## 7. 失败与回滚

| 失败点 | 处理 |
|---|---|
| 规格校验失败 | 不创建任何分支，返回字段级错误。无副作用 |
| clone 创建失败 | 删除临时目录，返回错误 |
| 生成失败（pydantic / 模板） | 删除临时 clone，不产生任何分支，返回错误 |
| 迁移生成失败 | 同上传，确保不留下半成品的分支 |
| commit 失败 | 保留临时 clone 并返回其路径供人工检查，**不静默删除** |
| 审计写入失败 | **不回滚**——提案已成功。返回 `audit_written: false` |
| 中途进程被杀 | 临时 clone 残留在系统临时目录；用户仓库不受影响（分支尚未 fetch 回来）。下次运行时清理超过 24h 的残留 |

**回滚原则**：失败时尽量回到「什么都没发生」的状态；做不到时（进程被杀）**保留现场并让人可见**，而不是静默清理。

## 8. 与只读层（#15）的关系

| 方面 | 只读层（#15，`8a8e527`） | 本设计（M2 写入层） |
|---|---|---|
| 工具 | `list_resources`、`describe_resource`、`validate_spec`、`preview_generate`、`check` | 新增 4 个，**不改动既有 5 个** |
| 落盘 | 全部不落盘 | `propose_spec_change` / `discard_proposal` 落盘 |
| 复用 | — | `_guard_spec_text`、`_guard_resource_name`、`_spec_path`、`_redact`、`_mcp_tool` 全部复用 |
| 权限 | 只读，无需写权限点 | 新增 `spec:write` |
| 关系 | `preview_generate` 给出「如果生成会是什么样」 | `propose_spec_change` 是它的落盘版：同样生成，但结果留在分支上 |

**关键设计选择**：写入层**不重写**生成逻辑，而是复用只读层 `preview_generate` 的生成路径，只是把临时目录换成隔离 clone 并把结果 commit 下来。这样两层的 diff 计算完全一致——AI 先 `preview_generate` 看到的 diff，与 `propose_spec_change` 产出的 diff 应当逐字节相同。这一点要有测试断言。

## 9. 实现状态与待定事项

### 9.1 已实现（本分支 `feat/v04-m2-write`）

| 项 | 位置 | 说明 |
|---|---|---|
| `make_proposal` | `tools/mcp_server/git_isolation.py` | 隔离 clone → 写文件 → commit → fetch 回用户仓库 |
| git 命令白名单（子命令级 + **参数级**） | 同上 `_git()` / `_ALLOWED_ARGS` | 表外子命令与表外选项一律 `GitNotAllowed` |
| 无 remote + `push.default=nothing` + `credential.helper` 置空 | 同上 `_harden_clone()` | 直接改 clone 的 `.git/config` 文件 |
| pre-push hook（`exit 1`）+ `core.hooksPath` 显式指向 clone 的 hooks | 同上 | 防止用户全局 `hooksPath` 让我们的 hook 失效 |
| 全局/系统配置隔离 | 同上 `_git()` / `fetch_from_local_clone()` | `GIT_CONFIG_GLOBAL=/dev/null`、`GIT_CONFIG_NOSYSTEM=1` |
| fetch 在用户仓库侧加 `-c core.hooksPath=/dev/null -c gc.auto=0` | 同上 | 不触发用户的 hook，不触发 gc |
| `base_ref` 校验（形态 + 存在性 + 不以 `-` 开头） | 同上 `validate_base_ref()` | 默认 `master`，**不取 HEAD** |
| 分支名形态校验（`_BRANCH_RE`，check-ref-format 子集） | 同上 `make_branch_name()` | resource 白名单之后再验一次 |
| 写用户仓库前 `branch_exists` 前置拒绝（快进也不行） | 同上 `make_proposal()` | 报错消息含「拒绝写入」 |
| `propose_spec_change` / `list_proposals` / `discard_proposal` 注册 | `tools/mcp_server/write_tools.py` | **默认不注册**，需 `--allow-write` |
| `--allow-write` 启动开关 | `tools/mcp_server/__init__.py` | 不加则 `tools/list` 里没有写入工具 |
| 审计写 stderr（结构化 JSON） | `write_tools.py` `_audit()` | 不依赖数据库，不写规格全文 |
| resource 名白名单 `^[a-z][a-z0-9_]{0,40}$` | `tools/mcp_server/__init__.py` | 长度上限 41 字符（首字符 + 最多 40） |

### 9.2 未实现（本原型刻意不做）

| 项 | 原因 |
|---|---|
| **24h 临时目录残留清理** | **TODO**。当前靠 `finally: shutil.rmtree()` 清理；进程被 kill 时会残留。原型阶段不做自动回收——自动删可能删掉人正在看的东西。后续加一个「启动时清理超过 24h 且标记为本工具创建的目录」的步骤 |
| 生成器与迁移的实际调用 | 最小原型只做「写规格 → 提交 → fetch」。生成与迁移在 `preview_generate` 的路径里已有，接线留到下一轮 |
| `apply_proposal`（把提案写回主工作区） | **刻意不做**。应用应当由人执行 `git merge` / `git cherry-pick`；加了它等于绕开「人来合并」 |
| `discard_proposal` 只删本工具创建的分支 | 当前只校验 `proposal/` 前缀。分支上记 note 或维护注册表属于下一轮——当前前缀足够区分，但不够强 |
| 提案分支过期清理 | 由 `list_proposals` + 人工 `discard_proposal` 处理，不自动回收 |

### 9.3 已定事项

| 问题 | 结论 |
|---|---|
| 「不能 push」的机制强度 | 四层：无 remote + pre-push hook + 命令白名单 + 无合并路径。另有四项正向对照 |
| `base_ref` 默认值 | **`master`**，不取 HEAD（用户可能停在功能分支）。显式传入时校验形态与存在性 |
| MCP 写入工具默认状态 | **默认不注册**，必须 `--allow-write`。MCP 是 stdio 本地进程、无账户体系，默认暴露写能力等于「谁能拉起进程谁就能写」 |
| 审计落点 | stderr 结构化 JSON。`OperationLog` 依赖数据库，MCP 侧不强制依赖运行中的服务 |

### 9.4 与设计初稿的偏差（已按审核意见修正）

| 初稿 | 现在 | 原因 |
|---|---|---|
| worktree 隔离 | `git clone --no-hardlinks --local` | worktree 共享 `.git`，hook 与 config 会污染用户仓库 |
| 「工具不持有凭据」当作一层保证 | 改为四层 | MCP 进程以用户身份运行，会继承用户的 credential helper，光「不持有」不够 |
| 子命令级白名单 | 子命令级 + **参数级** | `clone --upload-pack=<cmd>` 能在子命令合法时执行任意程序 |
| `commit` 失败保留 clone | 实现为「保留并返回路径」；`finally` 只清 `tmp_root`，clone 在 `tmp_root` 内，因此实际**会被清掉** | 这是初稿与实现的真实冲突。当前选择：失败时也清理（`rmtree(ignore_errors=True)`），并在返回值里给出错误；不保留路径。**文档按实现写**，不再声称「保留」 |

