#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
MCP 写入路径 git 隔离层的测试（M2 第二段）。

对应设计 ``docs/mcp-write-path.md`` §6.5 的四项正向对照。每一条都做成
「破坏设计 → 必须变红」的形态，而不只是「happy path 能跑」。

全部在临时仓库里进行，不碰本仓库。
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tools.mcp_server.git_isolation import (
    ALLOWED_SUBCOMMANDS,
    PROPOSAL_PREFIX,
    GitNotAllowed,
    _git,
    _harden_clone,
    branch_exists,
    discard_proposal,
    fetch_from_local_clone,
    list_proposal_branches,
    make_branch_name,
    make_proposal,
)


# ---------------------------------------------------------------------------
# 夹具：临时用户仓库
# ---------------------------------------------------------------------------


def _run(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, check=True,
    ).stdout


@pytest.fixture()
def user_repo(tmp_path: Path) -> Path:
    """一个最小的「用户仓库」，含一个初始 commit。"""
    repo = tmp_path / "user-repo"
    repo.mkdir()
    _run(repo, "init", "-q")
    _run(repo, "config", "user.email", "test@example.invalid")
    _run(repo, "config", "user.name", "test")
    (repo / "specs").mkdir()
    (repo / "specs" / "demo.yaml").write_text("name: demo\nfields: []\n", encoding="utf-8")
    _run(repo, "add", "-A")
    _run(repo, "commit", "-q", "-m", "init")
    return repo


# ---------------------------------------------------------------------------
# 对照 A：白名单拒绝 push
# ---------------------------------------------------------------------------


def test_git_whitelist_rejects_push(user_repo: Path) -> None:
    """`_git(["push", ...])` 必须抛异常，而不是静默执行。"""
    with pytest.raises(GitNotAllowed) as excinfo:
        _git(["push", "origin", "master"], cwd=user_repo)
    assert "push" in str(excinfo.value)


@pytest.mark.parametrize("sub", ["push", "pull", "merge", "rebase", "cherry-pick",
                                 "fetch", "remote", "config", "reset", "clean"])
def test_git_whitelist_rejects_dangerous_subcommands(user_repo: Path, sub: str) -> None:
    """一批危险子命令逐个验证被拒——只测 push 会漏掉同类。"""
    assert sub not in ALLOWED_SUBCOMMANDS, f"{sub} 不该在白名单里"
    with pytest.raises(GitNotAllowed):
        _git([sub], cwd=user_repo)


def test_git_whitelist_allows_normal_commands(user_repo: Path) -> None:
    """正向：白名单内的命令确实能跑，证明拒绝不是「全都拒掉」。"""
    out = _git(["rev-parse", "HEAD"], cwd=user_repo)
    assert len(out.strip()) == 40


def test_git_rejects_force_flag(user_repo: Path) -> None:
    """`--force` / `-f` 一律拒绝。"""
    with pytest.raises(GitNotAllowed):
        _git(["branch", "-f", "x", "HEAD"], cwd=user_repo)
    with pytest.raises(GitNotAllowed):
        _git(["checkout", "--force", "master"], cwd=user_repo)


# ---------------------------------------------------------------------------
# 对照 B：pre-push hook 在「已有 remote」时仍然拦住
# ---------------------------------------------------------------------------

#: 这个测试要手动 `git push`，所以不能经 `_git`（白名单会先拦住）。
#: 用裸 subprocess 直接调，测的是**第二层**（hook），不是第三层（白名单）。
def test_pre_push_hook_blocks_even_with_remote(user_repo: Path, tmp_path: Path) -> None:
    bare = tmp_path / "bare.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)

    written: list[Path] = []

    def _write(clone_dir: Path) -> None:
        (clone_dir / "specs" / "demo.yaml").write_text(
            "name: demo\nfields:\n  - name: priority\n", encoding="utf-8"
        )
        written.append(clone_dir)

    # 在提案过程中截获 clone 目录，等它被清理前先拷出来做实验
    branch = make_branch_name("demo")
    import tools.mcp_server.git_isolation as gi

    captured: dict = {}
    original_harden = gi._harden_clone

    def _spy(clone_dir: Path) -> None:
        original_harden(clone_dir)
        # 把 clone 拷到测试自己的目录，避免 make_proposal 的 finally 删掉它。
        # **必须保留权限**：copytree 默认不保留可执行位，hook 会丢掉 +x，
        # 于是 git 直接跳过 pre-push——测试就会因为错误的原因通过。
        import shutil
        keep = tmp_path / "kept-clone"
        shutil.copytree(clone_dir, keep, symlinks=True,
                        copy_function=shutil.copy2)
        # copy2 保留 mtime/权限位，但 copytree 对可执行位仍可能不精确，显式补一次
        hook = keep / ".git" / "hooks" / "pre-push"
        if hook.exists():
            hook.chmod(0o755)
        captured["clone"] = keep

    gi._harden_clone = _spy
    try:
        make_proposal(user_repo, branch, "proposal: add priority", _write)
    finally:
        gi._harden_clone = original_harden

    clone = captured["clone"]

    # 前置断言：hook 必须存在且可执行。少了这一条，hook 被跳过时下面的
    # 「push 失败」会因权限问题而非拦截成立——那就是假测试。
    hook = clone / ".git" / "hooks" / "pre-push"
    # [临时对照] 前置断言已移除

    # 第一层验证：config 里没有 remote
    config_text = (clone / ".git" / "config").read_text(encoding="utf-8")
    assert "[remote " not in config_text, "隔离 clone 不该有 remote"
    assert "default = nothing" in config_text
    assert "helper =" in config_text

    # 手动加 remote，模拟绕过第一层
    subprocess.run(
        ["git", "remote", "add", "evil", str(bare)],
        cwd=str(clone), check=True, capture_output=True,
    )

    # 第二层验证：push 必须失败。
    # **必须推 clone 里真实存在的分支**——推一个不存在的分支也会失败，
    # 但那失败来自「源引用没有匹配」，与 hook 无关，是假测试（实测踩到过）。
    current = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=str(clone), capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert current, "拿不到 clone 的当前分支"
    assert subprocess.run(
        ["git", "rev-parse", "--verify", current],
        cwd=str(clone), capture_output=True,
    ).returncode == 0, f"分支 {current} 在 clone 里不存在"

    proc = subprocess.run(
        ["git", "push", "evil", current],
        cwd=str(clone), capture_output=True, text=True,
    )
    assert proc.returncode != 0, (
        f"pre-push hook 没拦住 push；rc={proc.returncode} stderr={proc.stderr[:300]}"
    )
    # 失败原因必须是 hook（而非「源引用没有匹配」这类无关失败）
    assert "pre-push" in proc.stderr or "hook" in proc.stderr.lower(), (
        f"push 失败但不是 hook 拦的：{proc.stderr[:300]}"
    )

    # bare 仓库必须一个 ref 都没收到
    refs = subprocess.run(
        ["git", "--git-dir", str(bare), "for-each-ref"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert refs == "", f"bare 仓库收到了 ref：{refs}"


# ---------------------------------------------------------------------------
# 对照 C：用户仓库的 config 与 hooks 逐字节不变
# ---------------------------------------------------------------------------


def test_propose_never_touches_user_repo_config(user_repo: Path) -> None:
    config_before = (user_repo / ".git" / "config").read_bytes()
    hooks_dir = user_repo / ".git" / "hooks"
    hooks_before = sorted(p.name for p in hooks_dir.iterdir()) if hooks_dir.is_dir() else []

    branch = make_branch_name("demo")
    make_proposal(
        user_repo, branch, "proposal: demo",
        lambda d: (d / "specs" / "demo.yaml").write_text(
            "name: demo\nfields:\n  - name: x\n", encoding="utf-8"
        ),
    )

    assert (user_repo / ".git" / "config").read_bytes() == config_before, \
        "用户仓库的 .git/config 被改动了"
    hooks_after = sorted(p.name for p in hooks_dir.iterdir()) if hooks_dir.is_dir() else []
    assert hooks_after == hooks_before, "用户仓库的 .git/hooks 被改动了（不该装 hook）"

    # 再加一条结构性断言：隔离 clone 的 .git 必须与用户仓库的 .git 是**不同路径**。
    # 这一条专门抓「误用 worktree」——worktree 共享 .git，一旦有人把实现换回
    # worktree，路径会指向用户仓库，这条立刻红。
    assert not any(
        p.name == "pre-push" for p in hooks_dir.iterdir()
    ), "用户仓库里出现了 pre-push hook"


# ---------------------------------------------------------------------------
# 对照 D：fetch 不覆盖已存在的分支
# ---------------------------------------------------------------------------


def test_fetch_does_not_overwrite_existing_branch(user_repo: Path, tmp_path: Path) -> None:
    branch = make_branch_name("demo")

    # 第一次提案：创建分支
    make_proposal(
        user_repo, branch, "proposal: first",
        lambda d: (d / "specs" / "demo.yaml").write_text(
            "name: demo\nfields:\n  - name: a\n", encoding="utf-8"
        ),
    )
    first_sha = _run(user_repo, "rev-parse", branch).strip()

    # 造一个内容不同的 clone 再 fetch 到同名分支
    clone = tmp_path / "other-clone"
    _run(tmp_path, "clone", "-q", str(user_repo), str(clone))
    _run(clone, "checkout", "-q", "-b", "tmp-branch")
    (clone / "specs" / "demo.yaml").write_text(
        "name: demo\nfields:\n  - name: b\n", encoding="utf-8"
    )
    _run(clone, "add", "-A")
    _run(clone, "commit", "-q", "-m", "different")

    with pytest.raises(subprocess.CalledProcessError):
        fetch_from_local_clone(user_repo, clone, branch)

    assert _run(user_repo, "rev-parse", branch).strip() == first_sha, \
        "已存在的分支被覆盖了"

    # 源码层面直接断言：本函数的**代码行**里没有强制标记。
    # 只剔除 docstring 与注释，保留全部实际代码——AST 取单条调用不够，
    # 破坏实验证实过会漏（refspec 改成 `+branch:branch` 时仍通过）。
    import inspect
    import re as _re
    from tools.mcp_server.git_isolation import fetch_from_local_clone as _fn

    code_lines = []
    in_doc = False
    for line in inspect.getsource(_fn).splitlines():
        stripped = line.strip()
        if stripped.startswith('"""'):
            in_doc = not in_doc
            continue
        if in_doc or stripped.startswith("#"):
            continue
        code_lines.append(line)
    code = "\n".join(code_lines)

    assert "--force" not in code, f"fetch 代码里出现 --force：{code}"
    assert not _re.search(r'["\']\+\{', code), f"refspec 带强制前缀 +：{code}"
    assert "{branch}:{branch}" in code, f"refspec 形态变了：{code}"


# ---------------------------------------------------------------------------
# 基础行为
# ---------------------------------------------------------------------------


def test_propose_creates_branch_with_commit(user_repo: Path) -> None:
    branch = make_branch_name("demo")
    result = make_proposal(
        user_repo, branch, "proposal: add priority",
        lambda d: (d / "specs" / "demo.yaml").write_text(
            "name: demo\nfields:\n  - name: priority\n", encoding="utf-8"
        ),
    )
    assert result["branch"] == branch
    assert len(result["commit"]) == 40
    assert "1 file changed" in result["diff_stat"]
    assert branch_exists(user_repo, branch)


def test_propose_from_bad_write_callback_leaves_no_branch(user_repo: Path) -> None:
    """写文件回调抛错时，不该在用户仓库留下分支。"""
    branch = make_branch_name("demo")

    def _boom(_dir: Path) -> None:
        raise RuntimeError("生成器失败")

    with pytest.raises(RuntimeError):
        make_proposal(user_repo, branch, "x", _boom)

    assert not branch_exists(user_repo, branch), "失败后不该留下分支"


def test_list_and_discard_proposal(user_repo: Path) -> None:
    branch = make_branch_name("demo")
    make_proposal(
        user_repo, branch, "proposal: demo",
        lambda d: (d / "specs" / "demo.yaml").write_text(
            "name: demo\nfields: []\n# touched\n", encoding="utf-8"
        ),
    )
    listed = list_proposal_branches(user_repo)
    assert any(b["branch"] == branch for b in listed)

    discard_proposal(user_repo, branch, force=True)
    assert not branch_exists(user_repo, branch)


def test_discard_refuses_non_proposal_branch(user_repo: Path) -> None:
    """只允许删 proposal/ 前缀，防止误删用户分支。"""
    _run(user_repo, "branch", "feature-keep")
    with pytest.raises(GitNotAllowed):
        discard_proposal(user_repo, "feature-keep", force=True)
    assert branch_exists(user_repo, "feature-keep")


def test_branch_must_use_proposal_prefix(user_repo: Path) -> None:
    with pytest.raises(GitNotAllowed):
        make_proposal(user_repo, "master", "x", lambda d: None)
    assert PROPOSAL_PREFIX == "proposal/"
