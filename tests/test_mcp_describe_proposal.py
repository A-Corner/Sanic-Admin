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
    _run(r, "add", "-A")
    _run(r, "-c", "user.name=t", "-c", "user.email=t@x.invalid", "commit", "-q", "-m", "init")
    _run(r, "update-ref", "refs/heads/master", "HEAD")
    return r


def _propose(repo: Path, resource: str = "demo") -> dict:
    """经生产写入路径造一个带归属标记的提案。"""
    branch = gi.make_branch_name(resource)
    return gi.make_proposal(
        repo,
        branch,
        f"proposal: {resource}",
        lambda d: (d / "specs" / "demo.yaml").write_text(_SPEC, encoding="utf-8"),
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
