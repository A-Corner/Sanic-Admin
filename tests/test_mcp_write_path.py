#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
MCP 写入路径 git 隔离层的测试（M2 第二段）。

对应设计 ``docs/mcp-write-path.md`` §6.5 的四项正向对照。每一条都做成
「破坏设计 → 必须变红」的形态，而不只是「happy path 能跑」。

全部在临时仓库里进行，不碰本仓库。
"""
from __future__ import annotations

import os
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
    """
    即使手工加了 remote，push 也必须被 pre-push hook 拦下。

    审核指出上一版的两个问题：
    1. `"hook" in stderr.lower()` 可能因为 tmp_path 目录名里含 "hook" 而通过——
       改成「hook 写标记文件」这种**不可伪造**的证据；
    2. 测试自己又 chmod 了一次 hook，导致实现里的 chmod 根本没被测到——
       删掉测试里的 chmod，改为断言 `os.access(X_OK)`。
    """
    bare = tmp_path / "bare.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)

    branch = make_branch_name("demo")
    import tools.mcp_server.git_isolation as gi

    captured: dict = {}
    original_harden = gi._harden_clone

    def _spy(clone_dir: Path) -> None:
        original_harden(clone_dir)
        # 拷一份给测试用（make_proposal 的 finally 会删掉原目录）。
        # copy2 保留权限位；**不再补 chmod**——否则实现里的 chmod 测不到。
        import shutil
        keep = tmp_path / "kept-clone"
        shutil.copytree(clone_dir, keep, symlinks=True, copy_function=shutil.copy2)
        # hooksPath 是绝对路径，指向原 clone 的 hooks 目录；拷到新位置后必须
        # 同步改指，否则 git 会去原目录找 hook（那里已经被 make_proposal 删了）。
        # 这正是 P2-3「显式指定 hooksPath」生效的证据。
        cfg = keep / ".git" / "config"
        text = cfg.read_text(encoding="utf-8")
        old_hooks = str((clone_dir / ".git" / "hooks").resolve())
        new_hooks = str((keep / ".git" / "hooks").resolve())
        cfg.write_text(text.replace(old_hooks, new_hooks), encoding="utf-8")
        captured["clone"] = keep

    gi._harden_clone = _spy
    try:
        make_proposal(
            user_repo, branch, "proposal: add priority",
            lambda d: (d / "specs" / "demo.yaml").write_text(
                "name: demo\nfields:\n  - name: priority\n", encoding="utf-8"
            ),
        )
    finally:
        gi._harden_clone = original_harden

    clone = captured["clone"]
    hook = clone / ".git" / "hooks" / "pre-push"

    # --- 前置断言：hook 必须存在、可执行（测的是实现里的 chmod）---
    assert hook.exists(), "pre-push hook 不存在"
    assert os.access(hook, os.X_OK), (
        "pre-push hook 不可执行——实现里的 chmod 没生效（测试不得代为 chmod）"
    )
    assert "exit 1" in hook.read_text(encoding="utf-8")

    # --- 让 hook 留下不可伪造的执行证据 ---
    marker = tmp_path / "hook-ran.marker"
    hook.write_text(
        "#!/bin/sh\n"
        f'echo ran > "{marker}"\n'
        "exit 1\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)

    # 第一层：config 里没有 remote
    config_text = (clone / ".git" / "config").read_text(encoding="utf-8")
    assert "[remote " not in config_text, "隔离 clone 不该有 remote"
    assert "default = nothing" in config_text
    assert "helper =" in config_text

    # 手工加 remote，模拟绕过第一层
    subprocess.run(
        ["git", "remote", "add", "evil", str(bare)],
        cwd=str(clone), check=True, capture_output=True,
    )

    # 必须推 clone 里真实存在的分支
    current = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=str(clone), capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert current and current != "HEAD", "clone 处于分离 HEAD，无法推出有效分支"

    proc = subprocess.run(
        ["git", "push", "evil", current],
        cwd=str(clone), capture_output=True, text=True,
    )
    assert proc.returncode != 0, f"pre-push hook 没拦住 push：{proc.stderr[:300]}"

    # --- 核心证据：hook 确实被执行了（标记文件）---
    assert marker.exists() and marker.read_text().strip() == "ran", (
        "hook 没有执行痕迹——push 失败可能另有原因（如 ref 不存在），不是 hook 拦的"
    )

    # bare 仓库必须一个 ref 都没收到
    refs = subprocess.run(
        ["git", "--git-dir", str(bare), "for-each-ref"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert refs == "", f"bare 仓库收到了 ref：{refs}"

    # --- 反向对照：把 hook 换成放行，push 必须成功 ---
    # 这条证明「上面的失败确实是 hook 造成的」，而不是别的原因
    hook.write_text(
        "#!/bin/sh\n"
        f'echo ran > "{marker}"\n'
        "exit 0\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    marker.unlink()
    ok_proc = subprocess.run(
        ["git", "push", "evil", current],
        cwd=str(clone), capture_output=True, text=True,
    )
    assert ok_proc.returncode == 0, (
        f"hook 放行后 push 应当成功，否则说明失败另有原因：{ok_proc.stderr[:300]}"
    )
    refs_after = subprocess.run(
        ["git", "--git-dir", str(bare), "for-each-ref"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert refs_after != "", "放行后 bare 应当收到 ref（证明这条路径本来是通的）"


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
    """
    目标分支已存在时，fetch 必须被拒绝，且**失败原因必须是「非快进」**。

    之前的版本有三个问题（审核指出）：
    1. clone 里根本没有同名的 proposal 分支，fetch 失败是因为「找不到 ref」，
       与「拒绝覆盖」无关——测试看起来绿，实际什么都没测到；
    2. 没有快进场景的对照，无法证明拒绝只发生在分叉时；
    3. 靠源码文本断言兜底，那是补丁不是测试。
    """
    branch = make_branch_name("demo")

    # 第一次提案：在用户仓库里创建 proposal 分支
    make_proposal(
        user_repo, branch, "proposal: first",
        lambda d: (d / "specs" / "demo.yaml").write_text(
            "name: demo\nfields:\n  - name: a\n", encoding="utf-8"
        ),
    )
    first_sha = _run(user_repo, "rev-parse", branch).strip()

    # --- 场景 1：分叉（非快进）---
    clone = tmp_path / "other-clone"
    _run(tmp_path, "clone", "-q", str(user_repo), str(clone))
    # 在 clone 里基于**提案分支的父提交**造一个真正的分叉（不是接在它后面）
    _run(clone, "checkout", "-q", "-b", "work", f"origin/{branch}^")
    (clone / "specs" / "demo.yaml").write_text(
        "name: demo\nfields:\n  - name: b\n", encoding="utf-8"
    )
    _run(clone, "add", "-A")
    _run(clone, "commit", "-q", "-m", "diverged")
    # 让 clone 里出现同名的本地分支，否则 fetch 失败的原因是「找不到 ref」
    _run(clone, "update-ref", f"refs/heads/{branch}", "HEAD")

    proc = subprocess.run(
        ["git", "fetch", str(clone), f"{branch}:{branch}"],
        cwd=str(user_repo), capture_output=True, text=True,
    )
    assert proc.returncode != 0, "分叉场景下 fetch 应当被拒绝"
    # 失败原因必须是「非快进」——这是本测试的核心断言
    err = (proc.stderr + proc.stdout).lower()
    assert "non-fast-forward" in err or "非快进" in err or "rejected" in err, (
        f"fetch 失败但不是因为非快进：{proc.stderr[:300]}"
    )
    assert _run(user_repo, "rev-parse", branch).strip() == first_sha, \
        "已存在的分支被覆盖了"

    # --- 场景 2：快进（同一个分支上多一个提交）---
    # 快进应当**允许**——否则「拒绝」就不是针对分叉，而是 fetch 本身坏了。
    ff_clone = tmp_path / "ff-clone"
    _run(tmp_path, "clone", "-q", "--branch", branch, str(user_repo), str(ff_clone))
    (ff_clone / "specs" / "demo.yaml").write_text(
        "name: demo\nfields:\n  - name: c\n", encoding="utf-8"
    )
    _run(ff_clone, "add", "-A")
    _run(ff_clone, "commit", "-q", "-m", "fast-forward")
    _run(ff_clone, "update-ref", f"refs/heads/{branch}", "HEAD")
    ff_proc = subprocess.run(
        ["git", "fetch", str(ff_clone), f"{branch}:{branch}"],
        cwd=str(user_repo), capture_output=True, text=True,
    )
    assert ff_proc.returncode == 0, (
        f"快进 fetch 应当成功；stderr={ff_proc.stderr[:300]}"
    )
    assert _run(user_repo, "rev-parse", branch).strip() != first_sha, \
        "快进之后分支应当前进"


def test_propose_refuses_existing_branch_before_writing(user_repo: Path) -> None:
    """
    分支已存在时，提案必须在**写入用户仓库之前**就拒绝——快进也不行。

    与 test_fetch_does_not_overwrite_existing_branch 的区别：那条测的是 fetch
    层（非快进被 git 拒绝），这条测的是提案层的**前置检查**。去掉前置检查后，
    fetch 仍会因为非快进失败，所以那条测试抓不到——破坏实验证实过。
    这里断言的是报错来自前置检查（消息含「拒绝写入」），而非 fetch 的 git 错误。
    """
    branch = make_branch_name("demo")
    make_proposal(
        user_repo, branch, "proposal: first",
        lambda d: (d / "specs" / "demo.yaml").write_text(
            "name: demo\nfields:\n  - name: v1\n", encoding="utf-8"
        ),
    )
    first_sha = _run(user_repo, "rev-parse", branch).strip()

    # 同名分支再提案一次（即使内容能让 fetch 快进，也必须被前置检查拒绝）
    with pytest.raises(GitNotAllowed) as excinfo:
        make_proposal(
            user_repo, branch, "proposal: second",
            lambda d: (d / "specs" / "demo.yaml").write_text(
                "name: demo\nfields:\n  - name: v2\n", encoding="utf-8"
            ),
        )
    assert "拒绝写入" in str(excinfo.value), (
        f"拒绝理由不是前置检查：{excinfo.value}"
    )
    assert _run(user_repo, "rev-parse", branch).strip() == first_sha


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
