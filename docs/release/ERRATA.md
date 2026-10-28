# 发布说明勘误

> **本文件记录已发布 Release 说明中的错误，不修改历史正文。**
>
> 已发布的 Release 正文是历史快照，改了会让「仓库里那份」与「Release 页那份」分叉。
> 因此勘误统一记在这里——**后来人以本文件为准**。
>
> 新增勘误：按发布日期倒序追加，格式见下方条目。

---

## v0.4.2 — Release 在 CI 启动 34 秒后发出，全量测试尚未完成

**位置**：v0.4.2 的发布时序。不是正文文字错误，是**发布动作本身与验证状态不符**。

**事实**（全部取自 GitHub API，非转述）：

| 事件 | 时刻 |
|---|---|
| `test (3.10)` / `test (3.11)` / `test (3.12)` 的 `started_at` | `2026-10-27T06:44:46Z`（三个均相同） |
| Release `publishedAt` | `2026-10-27T06:45:20Z`（距启动 **34 秒**） |
| `test (3.11)` `completed_at` | `06:50:27Z` |
| `test (3.10)` `completed_at` | `06:50:58Z` |
| `test (3.12)` `completed_at` | `06:51:33Z` |

**此前记录有误**：这条曾被记为「Release 早于 CI 37 秒」。那个数是拿
`docker-acceptance`（`06:45:56Z` success）算的 —— **主语错位**。docker 验收只验容器
能否启动与同源托管，不跑测试套件；全量测试是另一批 job。

**影响**：v0.4.2 发布时，全量测试只跑了 34 秒。事后三个 job 全部 success，
**代码本身无障碍；但发布门禁在事实上被跳过了** —— 发布决策是在「测试结果未知」的状态下做出的。

**根因**：`ci.yml` 的 `on:` 只有 `branches:`、没有 `tags:`，因此**打 tag 不会触发 CI**。
tag 上唯一会跑的是 `docker.yml`（它有 `tags: [ 'v*' ]`）。若把「等 CI 全绿再发布」
理解为「看 tag 上的 run」，就**只能看到 docker 验收，看不到全量测试**。

**今后的做法**：见 v0.4.3 发布说明的「验证」节 —— 权威记录指向 **commit 页面的 check**，
而不是 tag 的 Actions run 列表。

---

## v0.4.2（2026-10-27）

**位置**：[`docs/release/v0.4.2-release-notes.md`](v0.4.2-release-notes.md) 的「已知限制（本版）」表，
以及同内容的 [GitHub Release 正文](https://github.com/A-Corner/Sanic-Admin/releases/tag/v0.4.2)。

**原文**：

> | 写入路径仍是原型 | `discard_proposal` 只按 `proposal/` 前缀判定；`describe_proposal` 未实现 |

**问题**：发布说明原文**低估了**实现。`discard_proposal` 不是只按前缀判定，而是三重条件同时成立。

**事实**（`tools/mcp_server/git_isolation.py:573-637`，`discard_proposal` 全函数）：

| 项 | 值 |
|---|---|
| 条件 ① | 分支名是 `proposal/` 前缀 |
| 条件 ② | 存在归属标记 `refs/specgen/proposals/<name>`（证明是本工具创建的） |
| 条件 ③ | 标记指向的 SHA == 分支当前 SHA（证明分支未被人改动） |
| 删除方式 | 带期望值的原子 `update-ref -d refs/heads/<branch> <marked>`——「比对 SHA」与「实际删除」之间分支若被改动，git 自身拒绝，TOCTOU 窗口由原子性封住 |
| 标记清理 | 同样带期望值 `update-ref -d <ref> <marked>`；失败只记 warning，方向安全（下次 discard 会因 SHA 不一致拒绝，不会误删） |
| 与原文同版正文 | 同版「新增」节已有「`discard_proposal` 的删除条件」小节写对了三重条件，与上表一致 |

**影响**：读者会低估该工具的安全性——以为任何人手工建一个 `proposal/xxx` 就能被本工具删掉，
实际上没有归属标记与 SHA 一致性的分支会被拒绝。功能行为本身无误，仅说明文字与实现不符。

**正确表述应为**：

> `discard_proposal` 删除提案分支必须三重条件同时成立：`proposal/` 前缀、存在归属标记
> `refs/specgen/proposals/<name>`、标记 SHA 等于分支当前 SHA；删除用带期望值的原子
> `update-ref -d`，TOCTOU 窗口由 git 自身封住。

**为什么不在正文里改**：Release 正文已发布；改动它会让仓库副本与 Release 页内容不一致。
（本版正文的「已知限制」表已在 `809e940` 中另行修正，本文件记录的是**已发布正文**的错——
两者并存时以本文件为准。）

---

## v0.4.1（2026-10-27）

**位置**：[`docs/release/v0.4.1-release-notes.md`](v0.4.1-release-notes.md) 的「验证」节，
以及同内容的 [GitHub Release 正文](https://github.com/A-Corner/Sanic-Admin/releases/tag/v0.4.1)。

**原文**：

> 发布树 `c08bd21`（本版 squash 提交，工作区干净 `git status --porcelain` 为空）上的实测：

**问题**：`c08bd21` **不是** v0.4.1 的发布树。v0.4.1 的 tag 实际指向 `133a206`。

**事实**：

| 项 | 值 |
|---|---|
| 全量测试实际跑在 | `c08bd21`（材料 PR #33 的 squash） |
| v0.4.1 tag 实际指向 | `133a206`（补写验证节的 PR #34 的 squash） |
| 两者差异 | 仅 2 个文件：`CHANGELOG.md`、`docs/release/v0.4.1-release-notes.md`（`git diff --name-status c08bd21 133a206`） |
| Python 代码差异 | **无** |

**为什么发生**：v0.4.1 是两段式发布的——#33 先合材料，在该树上跑全量；#34 再补写验证节。
说明文档里填的是第一段的 squash，而 tag 打在第二段上。

**影响**：**671 passed 的数字依然有效**。两棵树之间没有任何 `.py` 变更，
测试覆盖的代码完全相同。受影响的只是「指向哪棵树」这句话本身。

**正确表述应为**：

> 全量实测于 `c08bd21`（回填前的树）；本版最终发布树为 `133a206`，与 `c08bd21`
> 的差异仅 `CHANGELOG.md` 与本文档，代码相同。

**为什么不在正文里改**：Release 正文已发布；改动它会让仓库副本与 Release 页内容不一致，
而「两处各写一份」正是本项目反复在防的问题。详见 [`AGENTS.md`](../../AGENTS.md) §3.6
「发布门禁：树 SHA 必须等于 tag 解引用」。

**v0.4.2 起已改用正确写法**：把「全量实测树」与「发布树」分开写，并给出读者可自行验证的
`git diff --name-only` 命令（见 [`v0.4.2-release-notes.md`](v0.4.2-release-notes.md) 验证节）。

---

## 模板（新增勘误时照此填写）

```markdown
## v<版本>（YYYY-MM-DD）

**位置**：<文件路径与锚点 / Release 链接>

**原文**：
> <逐字引用错误原文>

**问题**：<错在哪>

**事实**：<表格：实际情况、时间、相关 SHA>

**影响**：<读者会因此误判什么；什么仍然有效>

**正确表述应为**：<可直接替换的句子>

**为什么不在正文里改**：<发布正文是历史快照，改会让两处分叉>
```
