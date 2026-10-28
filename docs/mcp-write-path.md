# MCP 写入路径设计（M2 第二段）

> 状态：**已在 v0.4.0 实现**（PR #22，squash `d457722`）。写入层默认关闭，
> 需 `--allow-write` 启动才注册。前置只读层见 PR #15（squash `0d63bfb`）；
> 本层的写入路径建立在其上，**不改动只读层的既有工具**。

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

### 2.1 `propose_spec_change`

**输入**

```json
{
  "resource": "ticket",
  "spec_yaml": "name: ticket\nfields:\n  ...",
  "note": "add priority field"
}
```

- `resource` 必须匹配 `^[a-z][a-z0-9_]{0,40}$`（`_guard_resource_name`；上限 41 字符）
- `spec_yaml` 上限 64 KB（复用 `_guard_spec_text`，含 YAML 锚点/别名与嵌套深度防护）
- `note` 仅进 commit message 与返回值，**不进任何 shell 命令**。
  **当前无长度校验**：`resource` 有 `_guard_resource_name`、`spec_yaml` 有 `_guard_spec_text`，
  `note` 没有对应守卫。调用方若需限制请自行校验；
  若 MCP 层要补，可在 `write_tools.py` 的 `propose_spec_change` 入口加 `_guard_note`。

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

删除指定提案分支。删除需同时满足三重条件（见 §9.1）：`proposal/` 前缀、存在归属标记 `refs/specgen/proposals/<name>`、标记 SHA 等于分支当前 SHA。删除用原子的 `update-ref -d refs/heads/<branch> <expected>`。

> `force` 形参**保留但当前无效果**：`discard_proposal(..., force=False)`（`git_isolation.py:573`）的签名后到函数结尾没有任何 `force` / `merged` / `merge-base` 引用，是否「已合并」不参与判定——安全边界完全由上面三重条件把住。


## 3. 权限与令牌范围

### 3.1 两层权限

| 层 | 内容 | 谁控制 |
|---|---|---|
| MCP 工具层 | **已实现（v0.4.2）**：`--allow-write` 是**注册门槛**（不加则三个写入工具不出现在 `tools/list`），`spec:write` 是**调用门槛**（每次调用前 `require_spec_write()` 实时调 `GET /auth/whoami` 校验），两者是 **AND** 关系。权限点注册于 `app/auth/permissions.py:60`（`"spec": ["write"]`），校验入口 `tools/mcp_server/identity.py:219`，三个写入工具首行调用（`write_tools.py:128,205,224`） | 项目 RBAC（`spec:write`） |
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

- 前缀 `proposal/` 是**硬性的命名约束**：`discard_proposal` 与 `list_proposals` 只操作这个前缀的分支
- **归属不由前缀判定**，而由 ref 标记判定：`refs/specgen/proposals/<name>`（`git_isolation.py:594` `ref = proposal_ref(branch)`，`:596` `rev-parse --verify <ref>^{commit}`）。`discard_proposal` 要求「前缀 + 归属标记存在 + 标记 SHA 一致」三重条件同时成立，见 §9.1
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

同一资源并发提案时，分支名带 timestamp，不会撞名。但两个提案可能基于同一个 base-ref，产生语义冲突——这**不是本层要解决的**，由人工在 PR 阶段处理。返回值里带 `base_ref` 与 `base_commit`（完整 SHA），让人能判断提案基于哪个提交。

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

审计写入失败**不阻断**提案——但返回值里的 `audit_written` 会是 `false`（该字段反映真实写入结果，不是恒为 `true`），让调用方知道这次审计没记下来。

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
| commit 失败 | 失败也清理临时 clone（`finally` 里 `shutil.rmtree(tmp_root, ignore_errors=True)`，`git_isolation.py:461`），错误经返回值给出；**不保留路径** |
| 审计写入失败 | **不回滚**——提案已成功。返回值 `audit_written: false` |
| 中途进程被杀 | 临时 clone 残留在系统临时目录；用户仓库不受影响（分支尚未 fetch 回来）。下次运行时清理超过 24h 的残留 |

**回滚原则**：失败时一律回到「什么都没发生」的状态——临时 clone 在 `finally` 里删除，即使失败也不留下；错误经返回值给出。**唯一的例外是进程被 kill**（`finally` 来不及执行），残留目录由启动时 `cleanup_stale_workspaces()`（`proposal_registry.py:161`，仅 `--allow-write` 时执行）按 24h 规则回收：只扫 tempdir 一层、名字匹配 `sanic-specgen-*`、必须有标记文件、mtime 超 24h、pid 非当前进程。

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

### 9.1 已实现（v0.4.0 / PR #22）

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
| **提案归属标记**：`refs/specgen/proposals/<name>` → commit SHA | `proposal_registry.py` `proposal_ref()` | `discard_proposal` 必须同时满足：①`proposal/` 前缀 ②存在归属标记 ③标记 SHA == 分支当前 SHA。任一条不满足即拒绝 |
| **临时目录残留清理** | `proposal_registry.py` `cleanup_stale_workspaces()` | 启动时（仅 `--allow-write`）清理：只扫 tempdir 一层、名字匹配 `sanic-specgen-*`、**必须**有标记文件 `.sanic-specgen-workspace`、mtime 超 24h、pid 非当前进程。绝不按通配删除 |
| resource 名白名单 `^[a-z][a-z0-9_]{0,40}$` | `tools/mcp_server/__init__.py` | 长度上限 41 字符（首字符 + 最多 40） |

### 9.2 未实现（本原型刻意不做）

| 项 | 原因 |
|---|---|
| 生成器与迁移的实际调用 | 最小原型只做「写规格 → 提交 → fetch」。生成与迁移在 `preview_generate` 的路径里已有，接线留到下一轮 |
| `apply_proposal`（把提案写回主工作区） | **刻意不做**。应用应当由人执行 `git merge` / `git cherry-pick`；加了它等于绕开「人来合并」 |
| 提案分支过期清理 | 由 `list_proposals` + 人工 `discard_proposal` 处理，不自动回收 |

### 9.2.1 `describe_proposal`（v0.5 已实现，第四个提案工具）

设计初稿列在「未实现」里的这一项，v0.5 补上了。此前看提案改了什么，只能 `list_proposals` 拿到分支名与 commit，再人工 `git show`——这是「AI 能读规格、提交提案」这条链路里唯一还靠人工的环节。

**入参**

| 参数 | 必填 | 说明 |
|---|---|---|
| `branch` | 是 | 提案分支名，必须是本工具创建的 `proposal/` 分支 |
| `base_ref` | 否 | 对比基线，留空则用 `master` |

**出参**

```json
{
  "branch": "proposal/ticket-20261028-101500",
  "base": "<master 的 commit sha>",
  "head": "<提案分支的 commit sha>",
  "commits": [
    {"sha": "...", "author": "...", "date": "2026-10-28T10:15:00+00:00", "subject": "proposal: ticket"}
  ],
  "files": [{"status": "M", "path": "specs/ticket.yaml"}],
  "diff": "diff --git a/specs/ticket.yaml b/specs/ticket.yaml\n--- a/specs/ticket.yaml\n+++ b/specs/ticket.yaml\n@@ ..."
}
```

**三条性质**

1. **只读**：全程在隔离 clone 里跑 `git diff <base>..<head>`，不读用户工作区、不写任何东西。测试用「调用前后 `git status --porcelain` 完全一致」锁定这一点。
2. **权限与其余三个提案工具一致**：注册在 `--allow-write` 分支，需要 `spec:write`；无 token 时 `identity_not_configured`。这不是疏漏——提案 diff 可能含客户业务规格片段，暴露面大于分支名列表，所以与 `list_proposals` 同级，**不存在「看不到列表却能看全文」的权限倒挂**。
3. **归属校验与 `discard_proposal` 同源**：`proposal/` 前缀 + 合法形态 + `refs/specgen/proposals/<name>` 标记存在。**但不比对标记 SHA**——那条是为防删除时被人偷换内容；读操作应该如实返回分支现在的样子。

**与「空 diff」的区分**：提案存在但相对基线无改动 → 返回 `diff: ""` 与空 `files`，不报错。若把空 diff 报成错误，调用方无法判断该补提案还是该修 id。

### 9.3 已定事项

| 问题 | 结论 |
|---|---|
| 「不能 push」的机制强度 | 四层：无 remote + pre-push hook + 命令白名单 + 无合并路径。另有四项正向对照 |
| `base_ref` 默认值 | **`master`**，不取 HEAD（用户可能停在功能分支）。显式传入时校验形态与存在性 |
| MCP 写入工具默认状态 | **默认不注册**，必须 `--allow-write`。默认暴露写能力等于「谁能拉起进程谁就能写」；v0.4.2 起再叠加账户级 `spec:write` 调用门槛（两者 AND，见 §10） |
| 审计落点 | stderr 结构化 JSON。`OperationLog` 依赖数据库，MCP 侧不强制依赖运行中的服务 |

### 9.4 与设计初稿的偏差（已按审核意见修正）

| 初稿 | 现在 | 原因 |
|---|---|---|
| worktree 隔离 | `git clone --no-hardlinks --local` | worktree 共享 `.git`，hook 与 config 会污染用户仓库 |
| 「工具不持有凭据」当作一层保证 | 改为四层 | MCP 进程以用户身份运行，会继承用户的 credential helper，光「不持有」不够 |
| 子命令级白名单 | 子命令级 + **参数级** | `clone --upload-pack=<cmd>` 能在子命令合法时执行任意程序 |
| `commit` 失败保留 clone | 实现为「保留并返回路径」；`finally` 只清 `tmp_root`，clone 在 `tmp_root` 内，因此实际**会被清掉** | 这是初稿与实现的真实冲突。当前选择：失败时也清理（`rmtree(ignore_errors=True)`），并在返回值里给出错误；不保留路径。**文档按实现写**，不再声称「保留」 |

## 10. 账户级权限（`spec:write`）

> 本节是 **SA-v042-SPECWRITE 的设计**（CPL 已裁定：五项全认可 + 4 条附加约束，2026-10-24，见 §10.9）。**已在 v0.4.2 实现**，补上了 §3.1「MCP 工具层」那一格：写入工具不再只靠进程开关 `--allow-write`，而是接入项目 RBAC 的 `spec:write` 权限点（`--allow-write` 注册门槛 AND `spec:write` 调用门槛）。
> 事实基础（均已核对 master `fef4dd3` 代码）：会话令牌是 RS256 JWT，payload 只含 `session_id` + `session_type`，有效性以服务端会话表为准（`app/models/session.py` `Session.decode`）；鉴权链 `get_session_token`（cookie `session` 或 `Authorization: Bearer`）→ `authenticate_request` → `has_permission(account, resource, action)`（`app/auth/authorization.py`，admin 直通）；权限注册表 `ALL_PERMISSIONS` 在 `app/auth/permissions.py`；现有 `POST /auth/`（`on_authenticate`）带 `@requires_authentication()` 但只返回账户 JSON、**不含权限**。

### 10.1 目标与非目标

**目标**

1. 写入工具的每次调用绑定到一个真实账户，并要求该账户拥有 `spec:write` 权限——admin 默认拥有，普通角色显式授予。
2. 校验走与 HTTP API **同一套**鉴权栈（`authenticate_request` + `has_permission`），不另造口径。
3. fail-closed：token 缺失、无效、过期、权限不足、校验服务不可达，一律拒绝且**零副作用**（不建 clone、不建分支）。
4. 审计可归属：成功与失败都记 `account_id`（不含用户名等更多信息），不记 token 本体。

**非目标（本节不做）**

1. 不给只读层五个工具加权限（它们不落盘，维持现状）。
2. 不做 MCP 进程与 Sanic 服务之间的双向 TLS / mTLS——本机回环 + token 已覆盖威胁模型（见 §10.7）。
3. 不做会话热重载：换 token = 重启 MCP 进程（env 在进程启动后不可变；简单、可审计）。
4. 不解决宿主客户端（Claude Code / Codex）内的 prompt injection——那层由既有四层机制（不能 push / 合并 + 人审）兜底，见 §10.7。

### 10.2 身份从哪里来：两个候选方案

先拆维度再比较。「身份」由两个独立决策组成：**token 怎么传给 MCP 进程**、**MCP 怎么校验它**。

| 维度 | 选项 1 | 选项 2 |
|---|---|---|
| 传递 | (a) 启动参数 `--token <token>`（argv） | (b) 环境变量 `SANIC_ADMIN_MCP_TOKEN`（env） |
| 校验 | HTTP 回调：MCP 带 token 调本地 Sanic 鉴权端点 | 本地校验：MCP 进程内复用 `AuthenticationSession.decode` + `has_permission`（需连 DB） |

**(a) argv 的问题**：进程参数对本机同用户进程可见（Linux `/proc/<pid>/cmdline`；macOS 同用户亦可用 `ps` 观察），且常被原样写进 MCP 客户端配置 JSON 与 shell history。token 属于机密，argv 是机密最差的落点之一。

**(b) env 的边界**：`/proc/<pid>/environ` 仅 owner（及 root）可读；MCP 客户端配置文件里 env 同样明文落盘——这点与 argv 打平，但运行时暴露面更小。注意与 §3.2 「不读取环境变量」**不冲突**：那条约束针对 Git 凭据类（`GH_TOKEN` / `GITHUB_TOKEN`——能推远端）；专用命名空间的 `SANIC_ADMIN_MCP_TOKEN` 只能被服务端校验、换不来 Git 推送能力，能力边界完全不同。

**校验方式对比**：

| | HTTP 回调 | 本地 decode |
|---|---|---|
| DB 依赖 | 无（服务端查） | 有——MCP 进程要 Tortoise init + DB 凭据 |
| MCP 被攻破时的损失 | 只持有 token | 直接持有 DB 访问权 |
| 口径一致性 | 与 HTTP API 同栈（`authenticate_request`），天然一致 | 同一套函数，但多一条「MCP 直连 DB」的配置漂移面 |
| 可用性依赖 | 需要运行中的 Sanic 服务 | 无 |
| 服务端改动 | 需新增一个返回权限的轻端点（现 `POST /auth/` 不含权限） | 无 |

**建议：env 传递 + HTTP 回调校验**（即 (b) 的传递 + (a) 的校验）。理由：

1. argv 会把机密暴露给进程表，env 不会——传递方式没有悬念。
2. 本地 decode 等于把数据库凭据交给 MCP 进程：MCP 被攻破时损失从「一个 token」升级为「整库访问」。四层隔离（§6）刻意让工具进程「不带凭据」，本地 decode 直接违背这一立场。
3. HTTP 回调让鉴权口径与 HTTP API 物理同栈，未来鉴权栈演进（如会话校验加码）MCP 侧零改动。
4. 「依赖运行中的服务」是可接受的：写路径本就该在服务可用时使用；服务不可达时 fail-closed（§10.5），只读工具不受影响。
5. 依赖成本：实现用**标准库 urllib**（零新增依赖；同步调用发生在 MCP SDK 给同步工具分配的工作线程里，不阻塞事件循环），超时 5s（CPL 上限）。

**服务端改动**：新增 `GET /auth/whoami`（`auth_bp`）。CPL 对这个**新增对外接口**的硬性约束（全部落实）：

| 约束 | 落实方式 |
|---|---|
| 走现有鉴权链 | `@requires_authentication()`（默认 `require_second_factor=True`）→ `authenticate_request`，与 HTTP API 同栈 |
| 拒绝 2FA 未完成会话 | `requires_authentication` 默认拒绝 `second_factor_pending`（401），无额外代码路径 |
| 拒绝 `must_change_password=True` | 双保险：①`/auth/whoami` **不进** `PASSWORD_CHANGE_EXEMPT_PREFIXES` 白名单 → 全局中间件 `enforce_password_change` fail-closed 拦截（403 `PASSWORD_CHANGE_REQUIRED`）——改密前拿不到权限清单；②handler 内显式再查一次 `bearer.must_change_password`（纵深防御，测试直接调 handler 时中间件不在场） |
| 返回最小化 | 只返回 `account_id` 与 `permissions`，**不返回**邮箱、用户名或任何其他字段 |
| 复用现有限流 | 不新建限流体系：whoami 是认证后低频端点（MCP 每次写调用至多一次），登录限流 `LoginRateLimiter` 不适用于已认证 GET；审计 IP 采信口径复用 `LoginRateLimiter`（`record_auth_event` 内置） |
| 写审计 | `record_auth_event(request, "whoami", account=bearer, status=...)`；`OPERATIONS` 白名单增加 `"whoami"`；审计不含 token（`app/services/audit.py` 硬约束 1 已保证） |

**权限语义**：`is_admin=True` 的账户返回 `admin_all_permissions()`（与 `has_permission` 的 admin 直通语义一致，MCP 侧无需理解 admin，纯集合判断）；普通账户返回 `get_account_permissions()` 的合并结果。MCP 判 `spec:write` 即「permissions 中 `spec` 含 `write` 或 `all`」。

**token 取舍（CPL 约束 2）**：v0.4.2 **不新增** API token 类型，直接用现有会话 JWT。取舍：会话过期后需要重新取 token 并重启 MCP 进程（不做热重载）；吊销靠作废会话实现（`disabled` / 删除），whoami 每次实时校验，吊销即时生效。专用的长期 API token（独立签发、独立过期策略、独立吊销）记为后续项，不在本版范围。

### 10.3 `spec:write` 权限点注册

```python
# app/auth/permissions.py 的 ALL_PERMISSIONS 增加一项：
"spec": ["write"],
```

- 权限串 `spec:write` 经 `rpartition(":")` 解析为资源 `spec`、动作 `write`，与现有归一化口径一致；不进 `RESOURCE_PARENTS`（无折叠需求）。
- **admin 默认拥有**：`admin_all_permissions()` 按注册表键集生成，注册即覆盖；惰性同步 `sync_admin_role_permissions()` 会在下次权限判定时把 admin 角色写为全量。
- **普通角色显式授予**：角色管理端资源列表来自 `all_resources()`，注册后自动出现；存量角色不自动获得（授权字典里没有 `spec` 即无权限，`validate_permissions_dict` 因注册而放行 `{"spec": ["write"]}`）。
- **保留字冲突**：生成器会把业务资源并入同一张 `ALL_PERMISSIONS`（`app/generated/permissions.py`，幂等覆盖同名键）。若业务规格的 `resource` 命名为 `spec`，会覆盖本权限点。建议在 `tools/specgen/schema.py` 的资源名校验里把 `spec` 列为保留字（一行校验 + 一个测试），列入实现清单。

### 10.4 token 的存放、不打印与过期

| 项 | 设计 |
|---|---|
| 存放 | 进程内仅一个模块级变量，从 `SANIC_ADMIN_MCP_TOKEN` 启动时读入一次；不写盘、不进任何返回值 |
| 不打印 | 启动信息只打「token 已配置 / 未配置」，不打值；审计 JSON（`_audit`）与错误消息**结构性**不含 token（token 不进异常链）；`_redact` 兜底规则增加对该变量的抹除 |
| 每次校验 | 三个写入工具**每次调用**实时走一遍 whoami，不缓存判定（写操作低频，成本可忽略；会话被禁用后下一次调用立即失效） |
| 回调目标（CPL 约束 3） | 只允许连 `http://127.0.0.1:<port>`（默认 `http://127.0.0.1:22222`）；要指向别的主机必须在配置里**显式**写 `SANIC_ADMIN_MCP_API_URL` 且通过 host 校验——防止 token 被发到非预期主机。默认配置下 token 不出本机 |
| 超时与失败 | 超时 **5s 以内**（CPL 上限）；超时、连接失败、非 200 一律**拒绝**（fail-closed），不重试 |
| 不打印 | 启动信息只打「token 已配置 / 未配置」，不打值；回调 URL 打 host 不打完整 header；审计 JSON（`_audit`）与错误消息**结构性**不含 token（token 不进异常链）；`_redact` 兜底规则增加对该变量的抹除 |
| 过期 | 会话过期（`SessionExpiredError`）→ whoami 返回 401 → 工具报「token 已失效，请重新签发并重启 MCP 进程」，不自动重试 |
| 吊销 | 会话可 disable；token 泄露时吊销会话即可，无需换 MCP 部署 |

### 10.5 校验失败时写入工具的表现（fail-closed）

三个写入工具（含只读的 `list_proposals`）**一律要求 `spec:write`**：粒度一致、实现与解释最简单，且 `list_proposals` 暴露提案内容，属提案流程的一部分，不应成为无权限方的探测入口。

校验在 `propose_spec_change` 的 `_guard_resource_name` **之前**执行——任何校验失败都不建 clone、不建分支（与 §7「规格校验失败零副作用」同原则）。

| 情形 | 行为 | 审计 |
|---|---|---|
| 未配置 token（env 缺失/空） | `ToolError`：需要配置 `SANIC_ADMIN_MCP_TOKEN` | `status=failure, reason=identity_not_configured` |
| token 无效 / 会话不存在 | `ToolError`：身份校验未通过 | `reason=identity_invalid` |
| 会话过期 / 被禁用 | `ToolError`：token 已失效，请重新签发并重启进程 | `reason=identity_invalid`（whoami 返回 401，MCP 不细分过期与无效） |
| 2FA 未完成（`second_factor_pending`） | `ToolError`（whoami 401，`requires_authentication` 默认拒绝） | `reason=identity_invalid` |
| 需要改密（`must_change_password=True`） | `ToolError`（whoami 403 `PASSWORD_CHANGE_REQUIRED`：中间件白名单不含 `/auth/whoami`，handler 内还有显式检查） | `reason=permission_denied` |
| 权限不足（无 `spec:write`） | `ToolError`：当前账户没有 spec:write 权限 | `reason=permission_denied` + 账户标识 |
| 校验服务不可达 / 超时 | `ToolError`：无法校验权限（服务不可达），**fail-closed 不放行** | `reason=identity_unavailable` |
| 校验通过 | 继续原有流程；审计记录增加 `account_id` | `status=success/failure` 照旧 |

### 10.6 与 `--allow-write` 的关系：建议 AND（两者都满足）

| `--allow-write` | token | 写入工具 |
|---|---|---|
| 无 | 无 | 不注册（v0.4.0 行为不变） |
| 无 | 有 | **不注册**——开关仍是注册门槛 |
| 有 | 无 | 注册；调用报「需要配置 `SANIC_ADMIN_MCP_TOKEN`」 |
| 有 | 有 | 注册；每次调用实时校验 `spec:write` |

**为什么是 AND 而不是「token 取代开关」**：

1. 两者语义不同层：`--allow-write` 是**部署意图**（这台机器上的这个进程要有写路径），token 是**调用方资格**（这次调用是谁、有没有权限）。取缔任何一层都会丢失一类表达。
2. 向后兼容：裸 `--allow-write` 的行为从「能用」变为「报配置错误」，错误消息即引导，可发现性好；若 token 取代开关，裸开关机器会在升级后**静默**改变安全语义。
3. 审计可区分两级原因（`identity_not_configured` vs `permission_denied`），排障不需要猜。
4. 「带 token 但没加开关」不注册：写入工具的存在本身就该是显式决定，token 只回答「谁」，不回答「这台机器要不要写路径」。

### 10.7 威胁模型

| 威胁 | 缓解 | 残余风险（如实声明） |
|---|---|---|
| 本机其他进程**无 token 拉起** MCP 写入进程 | 写入工具 fail-closed（`identity_not_configured`）；AND 矩阵下连注册都要显式开关 | 无实质残余 |
| 本机其他进程**读取已运行进程的 token** | env：`/proc/<pid>/environ` 仅 owner/root 可读（Linux）；macOS 更严 | 同 uid 的恶意进程仍可读 env——但同 uid 本就是 §6 四层机制的边界线（同用户可改代码、可挂 hook），本设计不声称防御同 uid 恶意进程 |
| **宿主客户端内** prompt injection 调用写入工具 | token 校验会**通过**（调用方身份合法）——本层挡不住 | 真正兜底的是既有四层：不能 push / 不能合并 / 人审合并；token 层新增的价值是**审计归属**（提案记到谁头上）与**可吊销**（禁用会话即断） |
| token 泄露到日志 / 返回值 | §10.4 结构性不打印 + `_redact` 兜底 | 客户端配置文件明文落盘（与 argv 等价，是 MCP 部署形态的固有问题，文档提示用户注意配置文件权限） |
| token 被窃后在别处使用 | 会话有 `expires`、可 `disable`；whoami 每次实时校验，吊销即时生效 | 吊销前的窗口内可在任何能连到该服务的位置使用——回环服务的暴露面即风险面 |
| 校验服务被冒充（假 whoami） | 本机回环连接；端口由部署方控制 | 若本机回环上有恶意进程抢占端口并应答任意 200，校验被绕过——该进程已能做任意本机事务，超出本层边界；文档写明「whoami 必须指向真实 Sanic 实例」 |

### 10.8 实现涉及面（裁定后执行；git_isolation.py **不涉及**）

| 文件 | 改动 | 归属 |
|---|---|---|
| `app/auth/permissions.py` | `ALL_PERMISSIONS` 增加 `"spec": ["write"]` | A |
| `app/auth/routes.py` | 新增 `GET /auth/whoami`（返回账户 + 合并权限） | A |
| `tools/specgen/schema.py` | 资源名保留字 `spec`（§10.3） | A |
| `tools/mcp_server/__init__.py` | 读 env、构建身份配置、传入 `build_server`；`--allow-write` 语义按 §10.6 矩阵调整 | A |
| `tools/mcp_server/write_tools.py` | 写调用前置校验（§10.5 矩阵）、审计加账户字段 | A |
| 新文件 `tools/mcp_server/identity.py` | whoami 客户端 + fail-closed 判定（独立成文件便于单测） | A（新文件，与 B 无冲突） |
| `tests/test_mcp_write_path.py`、`tests/test_mcp_write_registration.py`、新增 `tests/test_mcp_spec_write_auth.py` | CPL 约束 4 的测试矩阵（见 §10.8.1） | A |
| `docs/mcp.md` | 配置说明：env 变量、whoami 依赖、AND 矩阵 | A |

`git_isolation.py` 已移交 B，本设计**不需要**改它（身份校验发生在 `write_tools.py` 调用层，隔离层不感知身份）；若裁定后实现中发现必须触碰，先与 B 协调。

### 10.8.1 测试矩阵（CPL 约束 4）

| 组 | 用例 | 断言 |
|---|---|---|
| 拒绝 ×7 | token 缺失 / token 无效 / 会话过期 / 2FA pending / 需要改密 / 无 `spec:write` / Sanic 不可达 | 全部拒绝（`ToolError`），且**零副作用**：用户仓库分支列表不变、无 clone 目录残留 |
| 放行 | 有效 token 且账户有 `spec:write`（admin 与显式授予的普通角色各一条） | 正常产出提案分支 |
| 审计 | 成功与失败各一条 | stderr JSON 含 `account_id`，全文不含 token 子串 |
| 破坏实验 | 去掉 whoami 的 `must_change_password` 显式检查 | 对应测试**必须变红**，留存原始 FAILED 行；随后还原并复绿 |

### 10.9 裁定记录（CPL，2026-10-24）

§10.9 原列五项待裁定问题，CPL 裁定：**①方案、②AND 矩阵、③list_proposals 同受约束、④spec 保留字、⑤whoami 返回合并权限——五项全部认可**。另加 4 条约束：whoami 六项要求（§10.2 表）、token 不新增类型及取舍（§10.2 末段）、MCP 回调 URL/超时/日志约束（§10.4）、测试矩阵与破坏实验（§10.8.1）。本项属**必审类**（鉴权 + 对外接口），交付后由 CPL 派人独立审核。

