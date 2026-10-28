#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
MCP-05：``describe_proposal`` 只读工具（契约类，必审）。

完成定义见 `worklist/NEXT-WORKLIST-20261029.md` 的 MCP-05 行：

- 注册在 ``--allow-write`` 分支（第四个写入族工具）
- 入参与 ``discard_proposal`` **同源**做归属校验（``proposal/`` 前缀 +
  ``refs/specgen/proposals/`` 标记存在）
- 返回 ``{branch, base, head, commits[], files[], diff}``，diff 来自**隔离 clone 内**
- 只读：不读用户工作区、不写任何东西
- 无 ``spec:write`` → ``identity_not_configured`` 拒绝（与其余三工具一致）

本文件覆盖清单列出的测试项，一条不少：

1. 正常提案返回非空 diff 且含 ``+++`` / ``---``
2. 手工建的 ``proposal/*`` 分支（无归属标记）被拒
3. 非 ``proposal/`` 前缀被拒
4. 无 token 被拒（``identity_not_configured``）
5. ``--allow-write`` 关闭时不出现在 ``tools/list``

外加负向补足：提案不存在、基线不可达、空 diff（提案无实际改动）。
"""

import os
import subprocess
from pathlib import Path

import pytest

from tools.mcp_server import git_isolation as gi
from tools.mcp_server.proposal_registry import proposal_ref
from tools.mcp_server.write_tools import WRITE_TOOL_NAMES


# ---------------------------------------------------------------------------
# 夹具：与 test_mcp_proposal_hardening.py 同一模式
# ---------------------------------------------------------------------------


def _clean_env() -> dict:
    """剥离继承来的 git 环境，避免宿主仓库的 GIT_DIR 等变量干扰。"""
    env = dict(os.environ)
    for name in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
    ):
        env.pop(name, None)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["HOME"] = env.get("HOME", "/tmp")
    return env


def _run(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=True,
        env=_clean_env(),
    ).stdout


_SPEC = "resource: demo\nlabel: 演示\nfields:\n  - name: title\n    type: string\n    required: true\n"


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _run(r, "init", "-q")
    (r / "specs").mkdir()
    (r / "specs" / "demo.yaml").write_text("name: demo\n", encoding="utf-8")
    # 两个**内容在提案分支上不变**的基线文件：给「重命名」「删除」用例用。
    # 若拿 demo.yaml 改名就不行——提案分支上 demo.yaml 的内容已被改过，
    # git 判不出相似度，只会输出 D + A（不是解析的锅）。
    (r / "specs" / "movable.yaml").write_text("a\nb\nc\nd\ne\n", encoding="utf-8")
    (r / "specs" / "touchable.yaml").write_text("t\n", encoding="utf-8")
    _run(r, "add", "-A")
    _run(r, "-c", "user.name=t", "-c", "user.email=t@x.invalid", "commit", "-q", "-m", "init")
    _run(r, "update-ref", "refs/heads/master", "HEAD")
    return r


@pytest.fixture()
def allow_spec_write(monkeypatch):
    """
    放行身份层。

    ``describe_proposal_tool`` 在入口调 ``identity.require_spec_write()``（每次调用
    实时校验），本文件除 ``test_requires_spec_write_when_no_token`` 外都不测这一层。
    与 ``tests/test_mcp_write_registration.py`` 同一做法。
    """
    from tools.mcp_server import identity

    monkeypatch.setattr(identity, "require_spec_write", lambda: 42)


def _propose(repo: Path, resource: str = "demo") -> dict:
    """经生产写入路径造一个带归属标记的提案。"""
    branch = gi.make_branch_name(resource)
    return gi.make_proposal(
        repo,
        branch,
        f"proposal: {resource}",
        lambda d: (d / "specs" / "demo.yaml").write_text(_SPEC, encoding="utf-8"),
    )


def _commit(repo: Path, message: str, files: dict) -> str:
    """在**当前分支**上再提交一批文件，返回新 HEAD 的 SHA。"""
    for rel, content in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _run(repo, "add", "-A")
    _run(
        repo,
        "-c", "user.name=t", "-c", "user.email=t@x.invalid",
        "commit", "-q", "-m", message,
    )
    return _run(repo, "rev-parse", "HEAD").strip()


def _assert_no_git_command_leak(message: str) -> None:
    """错误信息不得暴露内部 git 命令（argv、CalledProcessError 文案）。"""
    for needle in (
        "Command '['git'",
        "calledprocesserror",
        "update-ref",
        "returned non-zero exit status",
    ):
        assert needle.lower() not in message.lower(), (
            f"错误信息泄露了内部 git 命令细节（{needle!r}）：{message}"
        )


# ---------------------------------------------------------------------------
# 正向：正常提案返回可用 diff
# ---------------------------------------------------------------------------


def test_describe_returns_nonempty_diff_with_markers(repo: Path) -> None:
    """正常提案：diff 非空，且含 ``---`` / ``+++`` 与增删行。"""
    proposed = _propose(repo)

    result = gi.describe_proposal(repo, proposed["branch"])

    assert result["branch"] == proposed["branch"]
    assert result["head"] == proposed["commit"], "head 必须等于提案 commit"
    assert result["base"], "base 必须解析成一个真实 SHA"

    diff = result["diff"]
    assert diff.strip(), "正常提案的 diff 不能为空"
    assert "--- " in diff, f"diff 缺少 ``---`` 行：{diff[:200]!r}"
    assert "+++ " in diff, f"diff 缺少 ``+++`` 行：{diff[:200]!r}"
    assert "specs/demo.yaml" in diff, f"diff 未包含被改文件：{diff[:200]!r}"
    # 至少有一行增或删
    changed = [ln for ln in diff.splitlines() if ln.startswith(("+", "-")) and not ln.startswith(("+++", "---"))]
    assert changed, f"diff 里没有任何增删行：{diff[:200]!r}"


def test_describe_returns_metadata(repo: Path) -> None:
    """元数据齐全：commits 与 files 都要有内容。"""
    proposed = _propose(repo)
    result = gi.describe_proposal(repo, proposed["branch"])

    assert len(result["commits"]) == 1, result["commits"]
    assert result["commits"][0]["sha"] == proposed["commit"]
    assert result["commits"][0]["subject"], "commit subject 不能为空"

    assert result["files"], "files 不能为空"
    assert any(f["path"] == "specs/demo.yaml" for f in result["files"]), result["files"]


def test_describe_does_not_touch_worktree(repo: Path) -> None:
    """只读：调用前后用户工作区的 status 必须一模一样。"""
    proposed = _propose(repo)
    before = _run(repo, "status", "--porcelain")

    gi.describe_proposal(repo, proposed["branch"])

    after = _run(repo, "status", "--porcelain")
    assert before == after, f"describe_proposal 动了工作区：\n改前={before!r}\n改后={after!r}"


# ---------------------------------------------------------------------------
# 负向 1：手工建的 proposal/* 无归属标记
# ---------------------------------------------------------------------------


def test_rejects_branch_without_ownership_marker(repo: Path) -> None:
    """手工建的同名前缀分支没有归属标记，必须拒绝——与 discard 同一判据。"""
    branch = "proposal/manual-20260101-000000"
    _run(repo, "branch", branch)

    with pytest.raises(gi.GitNotAllowed) as exc_info:
        gi.describe_proposal(repo, branch)
    assert "没有归属标记" in str(exc_info.value), str(exc_info.value)


# ---------------------------------------------------------------------------
# 负向 2：非 proposal/ 前缀
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("branch", ["master", "feature/x", "proposals/x", ""])
def test_rejects_non_proposal_prefix(repo: Path, branch: str) -> None:
    """非 proposal/ 前缀直接拒绝。"""
    with pytest.raises(gi.GitNotAllowed) as exc_info:
        gi.describe_proposal(repo, branch)
    assert "proposal/" in str(exc_info.value), str(exc_info.value)


# ---------------------------------------------------------------------------
# 负向 3：提案不存在 / id 格式非法
# ---------------------------------------------------------------------------


def test_rejects_missing_branch(repo: Path) -> None:
    """形态合法但不存在的分支：明确报「不存在」，不是空 diff。"""
    branch = "proposal/demo-20260101-000000"
    with pytest.raises(gi.GitNotAllowed) as exc_info:
        gi.describe_proposal(repo, branch)
    assert "不存在" in str(exc_info.value), str(exc_info.value)


@pytest.mark.parametrize(
    "branch",
    [
        "proposal/..",
        "proposal/x/../../etc",
        "proposal/Demo-20260101-000000",   # 大写开头不合法
        "proposal/demo-2026-01-01",        # 日期形态不对
        "proposal/demo-20260101-000000\n", # 尾随换行
    ],
)
def test_rejects_malformed_branch_name(repo: Path, branch: str) -> None:
    """id 形态非法：在拼 ref 全名之前就拒绝。"""
    with pytest.raises(gi.GitNotAllowed) as exc_info:
        gi.describe_proposal(repo, branch)
    assert "不合法" in str(exc_info.value), str(exc_info.value)


# ---------------------------------------------------------------------------
# 负向 4：基线不可达
# ---------------------------------------------------------------------------


def test_rejects_unreachable_base(repo: Path) -> None:
    """基线分支不存在：明确报「基线不可达」，不是空 diff。"""
    proposed = _propose(repo)
    with pytest.raises(gi.GitNotAllowed) as exc_info:
        gi.describe_proposal(repo, proposed["branch"], base_ref="no-such-base")
    # 基线不存在的检查点在 `_pin_base_ref`（比本函数更早），措辞是「找不到 base_ref」；
    # 两种措辞都算合格——关键是不能静默返回空 diff。
    msg = str(exc_info.value)
    assert "基线" in msg or "base_ref" in msg, msg


# ---------------------------------------------------------------------------
# 负向 5：空 diff（提案没有实际改动）
# ---------------------------------------------------------------------------


def test_empty_diff_is_reported_as_empty_not_error(repo: Path) -> None:
    """
    提案相对基线没有实际改动时：**返回空 diff，而不是报错**。

    这与「提案不存在」是两种事实，必须区分——前者是「这个提案什么都没改」，
    后者是「这个提案根本不存在」。若把空 diff 报成错误，调用方无法判断该补
    提案还是该修 id。
    """
    # 造一个「有提交但相对 master 无改动」的提案。
    # `make_proposal` 在那条路径上会让 `git commit` 因「nothing to commit」失败
    # （它假定回调一定改了东西），所以这里直接手工建：先走正常提案路径拿到
    # 归属标记，再把分支重置回 master 并补一个空提交。
    branch = gi.make_branch_name("demo")
    gi.make_proposal(
        repo,
        branch,
        "proposal: seed",
        lambda d: (d / "specs" / "demo.yaml").write_text(_SPEC, encoding="utf-8"),
    )
    # 空提交：--allow-empty 让「无改动」成为一个合法提交
    _run(repo, "checkout", "-q", branch)
    _run(
        repo,
        "-c", "user.name=t", "-c", "user.email=t@x.invalid",
        "commit", "-q", "--allow-empty", "-m", "proposal: no-op",
    )
    _run(repo, "checkout", "-q", "master")
    # 把分支重置回 master 再打空提交 → 相对 master 零改动
    _run(repo, "update-ref", f"refs/heads/{branch}", "refs/heads/master")
    _run(repo, "checkout", "-q", branch)
    _run(
        repo,
        "-c", "user.name=t", "-c", "user.email=t@x.invalid",
        "commit", "-q", "--allow-empty", "-m", "proposal: no-op",
    )
    new_head = _run(repo, "rev-parse", "HEAD").strip()
    _run(repo, "checkout", "-q", "master")
    # 归属标记同步到新 head，否则会被「标记存在」之外的其他校验挡住
    _run(repo, "update-ref", proposal_ref(branch), new_head)

    result = gi.describe_proposal(repo, branch)
    assert result["diff"] == "", f"无改动的提案应返回空 diff，实际 {result['diff'][:200]!r}"
    assert result["files"] == [], f"无改动时 files 应为空，实际 {result['files']}"


# ---------------------------------------------------------------------------
# 中危 1：diff 区间必须是 merge-base 三点，不能是两点全量对比
# ---------------------------------------------------------------------------


def test_diff_excludes_changes_merged_into_master_after_branching(repo: Path) -> None:
    """
    提案从旧 master 分出后 master 又前进：diff 不得把别人的改动显示成删除。

    审核实测的场景：master 上后来加了 ``reviewer: approved``，两点区间
    （``A..B``）把这一行显示成 ``-reviewer: approved``，``files`` 里也混入
    ``specs/other.yaml``——审核人会误判「AI 删了已批准的行」。

    **破坏实验**：把实现里的 ``f"{base}...{head}"`` 改回 ``f"{base}..{head}"``
    （``--name-status`` 与 diff 两处都要改），本用例必须变红。
    """
    proposed = _propose(repo)
    base_sha = proposed  # 提案 commit
    assert base_sha

    # 提案分支不动；master 上再落一个**别人**的改动。
    _run(repo, "checkout", "-q", "master")
    other_sha = _commit(repo, "others: approve reviewer", {"specs/other.yaml": "reviewer: approved\n"})
    assert other_sha != proposed["commit"]

    result = gi.describe_proposal(repo, proposed["branch"])

    # 正向：提案自己的改动必须在
    assert "specs/demo.yaml" in result["diff"], result["diff"][:400]
    assert any(f["path"] == "specs/demo.yaml" for f in result["files"]), result["files"]

    # 反向：master 上别人的改动**一格都不该出现**
    assert "specs/other.yaml" not in result["diff"], (
        "diff 混入了 master 上别人的改动——区间不是 merge-base 三点号：\n"
        + result["diff"][:600]
    )
    assert "reviewer: approved" not in result["diff"], (
        "diff 把 master 上已合并的行显示成了删除：\n" + result["diff"][:600]
    )
    assert all(f["path"] != "specs/other.yaml" for f in result["files"]), (
        f"files 混入了别人的文件：{result['files']}"
    )

    # base 必须是 merge-base，不是 master 当前的 tip
    master_tip = _run(repo, "rev-parse", "master").strip()
    assert result["base"] != master_tip, (
        "base 是 master 的 tip，不是 merge-base——说明区间还是两点全量对比"
    )
    assert result["base"] == _run(repo, "merge-base", "master", proposed["commit"]).strip()


# ---------------------------------------------------------------------------
# 中危 3：diff 必须有大小上限，且超限是**报错**不是静默截断
# ---------------------------------------------------------------------------


def test_oversized_diff_is_rejected_not_truncated(repo: Path, monkeypatch) -> None:
    """
    超过上限的提案：抛 ``GitNotAllowed``，消息里给出现实字节数与上限。

    为什么选「报错」而不是「截断 + truncated:true」：静默截断会让审核人以为
    看到了全部改动。归属标记不校验 SHA，所以任何人都能让 diff 变大——必须有闸。

    **破坏实验**：删掉 ``if diff_size > MAX_PROPOSAL_DIFF_BYTES`` 那段，本用例红。
    """
    proposed = _propose(repo)
    _run(repo, "checkout", "-q", proposed["branch"])
    # 一个明确超过上限的文件（上限 = 256KB）
    big = "x" * (gi.MAX_PROPOSAL_DIFF_BYTES + 1024)
    _commit(repo, "proposal: 超大文件", {"specs/big.yaml": big})
    _run(repo, "checkout", "-q", "master")

    with pytest.raises(gi.GitNotAllowed) as exc_info:
        gi.describe_proposal(repo, proposed["branch"])
    msg = str(exc_info.value)
    assert "过大" in msg, f"拒绝理由不对：{msg}"
    assert str(gi.MAX_PROPOSAL_DIFF_BYTES) in msg, f"没告诉调用方上限是多少：{msg}"
    # 关键：不能是「截断后照常返回」
    assert "truncated" not in msg.lower()


def test_diff_just_under_limit_is_returned_whole(repo: Path) -> None:
    """
    正向对照：上限以内的提案必须**完整**返回。

    没有这条，「超限报错」可能来自一个把上限写成 0 的实现——那样所有提案都
    报错，超限用例照样绿。
    """
    proposed = _propose(repo)
    result = gi.describe_proposal(repo, proposed["branch"])

    size = len(result["diff"].encode("utf-8"))
    assert 0 < size <= gi.MAX_PROPOSAL_DIFF_BYTES, (size, gi.MAX_PROPOSAL_DIFF_BYTES)
    assert result["diff"].rstrip().endswith(("+", "1", "true", "string", "demo", _SPEC.splitlines()[-1])), (
        "diff 看起来被截断了：末尾 " + repr(result["diff"][-80:])
    )


# ---------------------------------------------------------------------------
# diff 上限之外的第二个闸：commits 条数上限
#
# 起因（PR #55 审核，清单外低危）：diff 闸只封 ``diff`` 字段，``commits`` 是另一个
# 独立字段。空提交不产生任何 diff，因此能让 commits 无上限增长而完全不触发 diff 闸。
# ---------------------------------------------------------------------------


def _add_empty_commits(repo: Path, branch: str, base: str, n: int) -> None:
    """
    在 ``branch`` 上追加 ``n`` 条**空提交**（树与 ``base`` 完全相同）。

    为什么用 ``fast-import`` 而不是循环 ``git commit``：500 次 commit 约 16 秒，
    两条用例就要 30 秒以上，会把整个测试文件拖慢一个数量级。``fast-import``
    同样走 git 自己的对象库与提交链，0.2 秒内完成，产物与 ``--allow-empty``
    逐字段一致（``git log --format`` 输出格式相同，树不变、diff 为空）。

    ``from`` 必须写在第一条 ``commit`` 的 ``data`` **之后**——fast-import 的
    ``from`` 是「相对当前 commit 的状态」而非全局指令，放在最前面会被拒
    （实测：``Unsupported command: from``）。
    """
    if n <= 0:
        return
    script = []
    for i in range(n):
        msg = f"empty {i}"
        script.append(f"commit refs/heads/{branch}")
        script.append(f"committer t <t@x.invalid> {1800000000 + i} +0000")
        script.append(f"data {len(msg)}")
        script.append(msg)
        if i == 0:
            script.append(f"from {base}")
    subprocess.run(
        ["git", "update-ref", f"refs/heads/{branch}", base],
        cwd=str(repo), capture_output=True, text=True, check=True, env=_clean_env(),
    )
    subprocess.run(
        ["git", "fast-import", "--quiet"],
        cwd=str(repo), input="\n".join(script) + "\n",
        capture_output=True, text=True, check=True, env=_clean_env(),
    )


def test_too_many_commits_is_rejected_not_truncated(repo: Path) -> None:
    """
    提交条数超过 ``MAX_PROPOSAL_COMMITS``：抛 ``GitNotAllowed``，含实际条数与上限。

    失败场景（审核实测形态）：向带归属标记的分支推 5 万个**空提交**——diff 为空、
    diff 闸不触发，``commits`` 数组却几 MB 原样进 JSON 响应。

    **破坏实验**：删掉 ``if commit_count > MAX_PROPOSAL_COMMITS`` 那段，本用例红。
    """
    proposed = _propose(repo)
    # 提案分支已含 1 条提交，再补到「上限 + 1」条
    _add_empty_commits(
        repo, proposed["branch"], proposed["commit"], gi.MAX_PROPOSAL_COMMITS
    )

    with pytest.raises(gi.GitNotAllowed) as exc_info:
        gi.describe_proposal(repo, proposed["branch"])
    msg = str(exc_info.value)
    assert "过大" in msg, f"拒绝理由不对：{msg}"
    # 告诉调用方实际条数与上限，二者都必须出现
    assert str(gi.MAX_PROPOSAL_COMMITS) in msg, f"没告诉调用方上限是多少：{msg}"
    assert str(gi.MAX_PROPOSAL_COMMITS + 1) in msg, f"没告诉实际条数：{msg}"
    assert "truncated" not in msg.lower(), "不能以「截断后照常返回」的方式通过"
    # 不能泄露内部 git 命令
    _assert_no_git_command_leak(msg)


def test_commits_at_limit_are_returned_whole(repo: Path) -> None:
    """
    正向对照：恰好等于上限的提案必须**完整**返回全部提交。

    没有这条，「超限报错」可能来自一个把上限写成 0（或 ``>=`` 写反）的实现——
    那样所有提案都报错，超限用例照样绿。
    """
    proposed = _propose(repo)
    # 提案分支原有 1 条，补到恰好 MAX_PROPOSAL_COMMITS 条
    _add_empty_commits(
        repo, proposed["branch"], proposed["commit"], gi.MAX_PROPOSAL_COMMITS - 1
    )

    result = gi.describe_proposal(repo, proposed["branch"])

    assert len(result["commits"]) == gi.MAX_PROPOSAL_COMMITS, (
        f"应返回 {gi.MAX_PROPOSAL_COMMITS} 条提交，实际 {len(result['commits'])} 条"
    )
    # 场景前提：补的那些空提交**不产生任何 diff**——这正是 commits 需要独立闸门
    # 的原因（diff 闸看不见它们）。这里只应看到提案自己那一条提交改的 demo.yaml。
    changed = [
        ln for ln in result["diff"].splitlines()
        if ln.startswith("diff --git ")
    ]
    assert changed == ["diff --git a/specs/demo.yaml b/specs/demo.yaml"], (
        f"空提交不应产生 diff，实际改动文件：{changed}"
    )
    assert result["commits"][0]["subject"], "提交条目不能被截断成空壳"


# ---------------------------------------------------------------------------
# 中危 4：files[].status 对非 ASCII 与重命名路径必须判对
# ---------------------------------------------------------------------------


def test_files_status_added_non_ascii_path(repo: Path) -> None:
    """
    新增非 ASCII 文件名：``status == "A"``，``path`` 是真实中文路径。

    改前从 diff 头切 ``" b/"``：git 输出的是转义引号形式
    ``diff --git "a/specs/\\346\\226\\260..." "b/..."``，解析结果是
    ``{'status': 'M', 'path': '"specs/\\346\\226\\260..."'}``——状态错、路径是转义串。
    """
    proposed = _propose(repo)
    _run(repo, "checkout", "-q", proposed["branch"])
    _commit(repo, "proposal: 新增中文规格", {"specs/新增.yaml": "name: added\n"})
    _run(repo, "checkout", "-q", "master")

    result = gi.describe_proposal(repo, proposed["branch"])
    entry = [f for f in result["files"] if f["path"].endswith("新增.yaml")]
    assert entry, f"files 里没有中文路径（实际：{result['files']}）"
    assert entry[0]["status"] == "A", entry[0]
    assert entry[0]["path"] == "specs/新增.yaml", entry[0]
    assert '"' not in entry[0]["path"] and "\\" not in entry[0]["path"], (
        f"路径还是 git 的转义引号串：{entry[0]['path']!r}"
    )


def test_files_status_rename_reports_r_and_old_path(repo: Path) -> None:
    """
    重命名：``status == "R"``，并给出 ``old_path``。

    改前只报 ``M`` 且旧路径消失——审核实测。``git diff --name-status -z`` 对
    重命名输出 ``R100\\0old\\0new``（实测确认），这里断言两段都解析到了。

    **必须先提交提案、再单独提交一次改名**：若在同一提交里既写规格又改名，
    git 认为两份内容相似度 0%，只会输出 ``D`` + ``A``，根本走不到 ``R`` 分支。
    这里改的是 ``movable.yaml``（提案分支上与 master 完全一致的文件），确保 git
    能把这次改名识别成 100% 相似。
    """
    proposed = _propose(repo)
    _run(repo, "checkout", "-q", proposed["branch"])
    _run(repo, "mv", "specs/movable.yaml", "specs/moved.yaml")
    _commit(repo, "proposal: rename only", {})

    result = gi.describe_proposal(repo, proposed["branch"])
    _run(repo, "checkout", "-q", "master")
    renames = [f for f in result["files"] if f["status"] == "R"]
    assert len(renames) == 1, (
        f"重命名没识别成 R：{result['files']}——"
        "确认是不是夹具让 git 看不到相似度（同一提交里改内容）"
    )
    assert renames[0]["path"] == "specs/moved.yaml", renames[0]
    assert renames[0].get("old_path") == "specs/movable.yaml", renames[0]


def test_files_status_delete_and_modify(repo: Path) -> None:
    """删除 → ``D``；修改 → ``M``。"""
    proposed = _propose(repo)
    _run(repo, "checkout", "-q", proposed["branch"])
    _run(repo, "rm", "-q", "specs/movable.yaml")
    _commit(repo, "proposal: delete movable, touch touchable", {"specs/touchable.yaml": "t2\n"})

    result = gi.describe_proposal(repo, proposed["branch"])
    _run(repo, "checkout", "-q", "master")
    by_path = {f["path"]: f["status"] for f in result["files"]}
    assert by_path.get("specs/movable.yaml") == "D", result["files"]
    assert by_path.get("specs/touchable.yaml") == "M", result["files"]


def test_status_field_is_covered_at_all(repo: Path) -> None:
    """
    正向对照：**至少存在一条**对 ``status`` 的强断言。

    审核实测：把实现改成「status 恒置 M」，原 16 项测试全绿——字段没有任何覆盖。
    这条用例与上面三条一起，保证「恒置 M」必然变红。
    """
    proposed = _propose(repo)
    _run(repo, "checkout", "-q", proposed["branch"])
    _run(repo, "rm", "-q", "specs/demo.yaml")
    _commit(repo, "proposal: 全新增", {"specs/brand_new.yaml": "b: 1\n"})
    _run(repo, "checkout", "-q", "master")

    statuses = {f["path"]: f["status"] for f in gi.describe_proposal(repo, proposed["branch"])["files"]}
    assert statuses == {"specs/demo.yaml": "D", "specs/brand_new.yaml": "A"}, statuses


# ---------------------------------------------------------------------------
# 中危 2：base_ref 必须走 validate_base_ref
# ---------------------------------------------------------------------------


def test_base_ref_head_is_accepted_by_both_tools_gap(repo: Path, allow_spec_write) -> None:
    """
    **已知缺口，已上报待裁定**：``validate_base_ref`` 目前**接受** ``"HEAD"``。

    本次修复只把 ``describe_proposal`` 接到 ``validate_base_ref``（与
    ``propose_spec_change`` 一致），**没有**给共享函数加「拒绝 HEAD」的逻辑——
    那会同时改变另一个工具的行为，属于共享行为变更，需要单独裁定。

    这条用例锁定的是「修复后两个工具**行为一致**」这个事实：要么一起拒，要么
    一起接受。若将来给 ``validate_base_ref`` 加上 HEAD 拒绝，这里的两条
    ``pytest.raises`` 会变红——提醒同步更新本用例，而不是让它悄悄失配。
    """
    from tools.mcp_server.write_tools import describe_proposal_tool

    proposed = _propose(repo)
    # 当前共享校验接受 HEAD（缺口）；describe 不再单独放行，而是与 propose 同源。
    assert gi.validate_base_ref(repo, "HEAD") == "HEAD"
    assert describe_proposal_tool(
        proposed["branch"], base_ref="HEAD", repo_root=repo
    )["branch"] == proposed["branch"]


def test_base_ref_tag_is_accepted(repo: Path, allow_spec_write) -> None:
    """合法 tag 与 ``propose_spec_change`` 一致地被接受（改前报「找不到 base_ref」）。"""
    from tools.mcp_server.write_tools import describe_proposal_tool

    proposed = _propose(repo)
    _run(repo, "tag", "v1", "master")

    result = describe_proposal_tool(proposed["branch"], base_ref="v1", repo_root=repo)
    assert result["branch"] == proposed["branch"]
    assert result["base"] == _run(repo, "rev-parse", "master").strip(), (
        "以 tag 为基线时 merge-base 应等于 tag 指向的 master"
    )


@pytest.mark.parametrize("bad", ["HEAD~0", "master^{commit}", "--output=/tmp/x", "master..main"])
def test_base_ref_invalid_shapes_raise_tool_error_without_git_leak(repo: Path, bad: str, allow_spec_write) -> None:
    """
    形态非法的 base_ref：抛 ``ToolError`` 家族异常，且**不暴露**内部 git 命令。

    改前 ``HEAD~0`` 让 clone 里的 ``update-ref`` 抛裸 ``CalledProcessError``，
    客户端看到 ``Error executing tool ... returned non-zero exit status 128``。
    """
    from tools.mcp_server import ToolError
    from tools.mcp_server.write_tools import describe_proposal_tool

    proposed = _propose(repo)
    with pytest.raises(ToolError) as exc_info:
        describe_proposal_tool(proposed["branch"], base_ref=bad, repo_root=repo)
    _assert_no_git_command_leak(str(exc_info.value))


def test_base_ref_matches_propose_spec_change_behavior(repo: Path, allow_spec_write) -> None:
    """
    同族一致性：两个工具的 ``validate_base_ref`` 判定必须相同。

    这是中危 2 的核心——改前 ``describe_proposal`` 完全没走校验，于是同一批
    输入在 ``propose_spec_change`` 与 ``describe_proposal`` 上得到相反结论。
    """
    from tools.mcp_server.write_tools import describe_proposal_tool

    proposed = _propose(repo)
    _run(repo, "tag", "v2", "master")

    for ref in ("HEAD~0", "master^{commit}", "--output=/tmp/x", "master..main", "no-such"):
        with pytest.raises(Exception) as propose_exc:
            gi.validate_base_ref(repo, ref)
        with pytest.raises(Exception) as describe_exc:
            describe_proposal_tool(proposed["branch"], base_ref=ref, repo_root=repo)
        assert type(describe_exc.value).__name__ == type(propose_exc.value).__name__, (
            f"{ref!r}：propose 抛 {type(propose_exc.value).__name__}，"
            f"describe 抛 {type(describe_exc.value).__name__}"
        )
        assert str(describe_exc.value) == str(propose_exc.value), (
            f"{ref!r}：两个工具的拒绝理由不一致\n"
            f"propose: {propose_exc.value}\ndescribe: {describe_exc.value}"
        )

    # 合法的 tag 两边都接受
    assert gi.validate_base_ref(repo, "v2") == "v2"
    assert describe_proposal_tool(proposed["branch"], base_ref="v2", repo_root=repo)["branch"]


def test_invalid_base_ref_reaches_client_as_tool_error(repo: Path, monkeypatch) -> None:
    """
    端到端：非法 base_ref 经 MCP 出口后，客户端拿到的是**可读原因**，
    不是笼统的 ``Error executing tool``。

    改前 ``GitNotAllowed`` 是裸 Exception，``_mcp_tool`` 不转换，原因被丢掉。
    走真实的 ``server.call_tool``（公开入口），只把 ``ROOT`` 指到临时仓库。
    """
    import asyncio

    import tools.mcp_server as mcp_server
    from tools.mcp_server import identity

    monkeypatch.setattr(identity, "require_spec_write", lambda: 42)
    monkeypatch.setattr(mcp_server, "ROOT", repo)
    proposed = _propose(repo)
    server = mcp_server.build_server(allow_write=True)

    with pytest.raises(Exception) as exc_info:
        asyncio.run(server.call_tool(
            "describe_proposal", {"branch": proposed["branch"], "base_ref": "HEAD~0"}
        ))
    message = str(exc_info.value)
    assert "不合法" in message or "base_ref" in message, f"客户端只看到笼统错误：{message}"
    _assert_no_git_command_leak(message)


# ---------------------------------------------------------------------------
# 认证与注册：清单要求的第 4、5 条
# ---------------------------------------------------------------------------


def test_requires_spec_write_when_no_token(repo: Path, monkeypatch) -> None:
    """无 token：``identity_not_configured``，与其余三工具一致。"""
    from tools.mcp_server.identity import IdentityError
    from tools.mcp_server.write_tools import describe_proposal_tool

    monkeypatch.delenv("SANIC_ADMIN_MCP_TOKEN", raising=False)
    monkeypatch.delenv("SANIC_ADMIN_MCP_API_URL", raising=False)

    proposed = _propose(repo)
    with pytest.raises(IdentityError) as exc_info:
        describe_proposal_tool(proposed["branch"], repo_root=repo)
    assert exc_info.value.reason == "identity_not_configured", exc_info.value.reason


def test_registered_only_with_allow_write() -> None:
    """``--allow-write`` 关闭时不注册；打开时出现在工具列表里。"""
    from tools.mcp_server import build_server

    readonly = build_server(allow_write=False)
    names_readonly = {tool.name for tool in readonly._tool_manager.list_tools()}
    assert "describe_proposal" not in names_readonly, (
        f"--allow-write 关闭时不应注册 describe_proposal，实际工具：{sorted(names_readonly)}"
    )

    writable = build_server(allow_write=True)
    names_writable = {tool.name for tool in writable._tool_manager.list_tools()}
    assert "describe_proposal" in names_writable, (
        f"--allow-write 打开时应注册 describe_proposal，实际工具：{sorted(names_writable)}"
    )
    # 清单要求「与其余三工具一致」：四个都在
    assert WRITE_TOOL_NAMES <= names_writable, (
        f"写入工具族不完整：缺 {sorted(WRITE_TOOL_NAMES - names_writable)}"
    )
