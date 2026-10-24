#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
MCP 写入路径的 git 隔离层（M2 第二段）。

设计见 ``docs/mcp-write-path.md`` §6。核心职责只有一件：**在隔离 clone 里
提交提案，然后只把分支 fetch 回用户仓库，绝不 push、绝不合并**。

为什么单独一个模块：git 调用是这一层唯一有破坏力的操作，把它收敛到一个
带白名单的函数里，才能用测试证明「push 不可达」——而不是靠代码审查时的
肉眼确认。
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import List, Optional, Sequence

_log = logging.getLogger(__name__)

#: 允许的 git 子命令白名单。
#:
#: **只增不减地审查这里**：每加一项都意味着工具获得了一项新能力。
#: `push` / `pull` / `merge` / `rebase` / `cherry-pick` / `config`（写入）/
#: `remote add|set-url` / `reset --hard` / `clean` 一律不在表内——不是「我们
#: 不调用」，而是「调用会抛异常」。
ALLOWED_SUBCOMMANDS = frozenset({
    "clone",
    "add",
    "commit",
    "diff",
    "log",
    "status",
    "branch",
    "rev-parse",
    "ls-files",
    "checkout",
    "show",
})

#: 提案分支前缀。`list_proposals` / `discard_proposal` 只认这个前缀。
PROPOSAL_PREFIX = "proposal/"

#: 挂在不该挂的子命令上的危险参数（按完整 argv 元素比对）。
_FORBIDDEN_ARGS = frozenset({
    "--hard", "--no-verify", "--no-gpg-sign", "--allow-empty",
    "--push", "--upload-pack", "--receive-pack", "--exec",
})


class GitNotAllowed(Exception):
    """尝试执行白名单之外的 git 子命令。"""


def _git(args: Sequence[str], cwd: Path, *, env_extra: Optional[dict] = None) -> str:
    """
    执行一条 git 命令，**子命令必须在白名单内**。

    Args:
        args: 完整参数列表，``args[0]`` 是子命令（如 ``"commit"``）
        cwd: 在哪个工作目录执行
        env_extra: 追加的环境变量

    Returns:
        stdout

    Raises:
        GitNotAllowed: 子命令不在白名单
        subprocess.CalledProcessError: git 自身失败
    """
    if not args:
        raise GitNotAllowed("git 调用缺少子命令")

    sub = args[0]
    if sub not in ALLOWED_SUBCOMMANDS:
        raise GitNotAllowed(
            f"git 子命令 {sub!r} 不在允许列表内；"
            f"允许的是 {sorted(ALLOWED_SUBCOMMANDS)}"
        )

    # 子命令合法时，再挡住几个「挂在不该挂的子命令上」的危险参数。
    # 用独立 argv 元素比对，不做子串匹配——子串会误伤 `--format=` 里的 `-f`
    # 和路径里的字符。
    for arg in args[1:]:
        if arg in _FORBIDDEN_ARGS:
            raise GitNotAllowed(
                f"git {sub} 不允许参数 {arg!r}（会改动历史或绕过安全检查）"
            )
        if arg.startswith("--force") or arg.startswith("-f"):
            raise GitNotAllowed(f"git {sub} 不允许强制参数 {arg!r}")

    env = dict(os.environ)
    # 切断可能存在的凭据通道：即使代码路径被改，也没有可用的 credential helper。
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = ""
    env["SSH_ASKPASS"] = ""
    if env_extra:
        env.update(env_extra)

    result = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, ["git", *args],
            output=result.stdout, stderr=result.stderr,
        )
    return result.stdout


def _write_pre_push_hook(clone_dir: Path) -> None:
    """
    在**隔离 clone** 里装一个无条件失败的 pre-push hook。

    安全性来自「这是 clone 自己的 `.git/hooks`」——临时目录，用完即删，
    不会影响用户仓库（这正是选 clone 而非 worktree 的原因，见设计 §4.2）。
    """
    hooks = clone_dir / ".git" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    hook = hooks / "pre-push"
    hook.write_text(
        "#!/bin/sh\n"
        "# MCP 提案 clone：禁止任何 push。这是设计约束，不是可配置项。\n"
        "exit 1\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)


def _harden_clone(clone_dir: Path) -> None:
    """
    让隔离 clone 从根上没有推送目标，且凭据通道置空。

    **直接改 `.git/config` 文件，不走 `git config` 命令**：`config` 既能读也能写，
    放进白名单等于给工具一个「改任意配置」的能力。只改这一个临时 clone 的文件，
    能力边界最小。
    """
    config_path = clone_dir / ".git" / "config"
    lines: List[str] = []
    skip_remote = False
    for line in config_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("[remote "):
            skip_remote = True
            continue
        if skip_remote:
            if stripped.startswith("["):
                skip_remote = False
            else:
                continue
        lines.append(line)

    body = "\n".join(lines).rstrip() + "\n"
    body += "[push]\n\tdefault = nothing\n[credential]\n\thelper =\n"
    config_path.write_text(body, encoding="utf-8")
    _write_pre_push_hook(clone_dir)


def make_proposal(
    repo_root: Path,
    branch: str,
    commit_message: str,
    write_files: "callable",
    *,
    base_ref: str = "HEAD",
) -> dict:
    """
    在隔离 clone 里执行一次提案提交，再把分支 fetch 回用户仓库。

    Args:
        repo_root: 用户仓库根目录
        branch: 目标分支名，必须以 ``proposal/`` 开头
        commit_message: commit message（**不经 shell**，作为独立参数传给 git）
        write_files: 回调 ``(clone_dir: Path) -> None``，在 clone 里写文件
        base_ref: 隔离 clone 的起点

    Returns:
        ``{"branch":..., "commit":..., "diff_stat":..., "diff":...}``
    """
    if not branch.startswith(PROPOSAL_PREFIX):
        raise GitNotAllowed(f"分支名必须以 {PROPOSAL_PREFIX!r} 开头，实际 {branch!r}")

    repo_root = repo_root.resolve()
    tmp_root = Path(tempfile.mkdtemp(prefix="mcp-proposal-"))
    clone_dir = tmp_root / "repo"
    try:
        # 1) 隔离 clone：--no-hardlinks 强制真实复制，避免与用户仓库共享 inode
        _git(["clone", "--no-hardlinks", "--local", str(repo_root), str(clone_dir)],
             cwd=repo_root)
        # 2) 硬化：无 remote、无凭据、pre-push 无条件失败
        _harden_clone(clone_dir)
        # 3) 从 base_ref 切出提案分支（分支不存在才创建，不改已有）
        _git(["checkout", "-b", branch, base_ref], cwd=clone_dir)
        # 4) 让调用方写文件（规格 YAML 等）
        write_files(clone_dir)
        # 5) 提交
        _git(["add", "-A"], cwd=clone_dir)
        _git(["commit", "-m", commit_message], cwd=clone_dir)
        commit = _git(["rev-parse", "HEAD"], cwd=clone_dir).strip()
        diff_stat = _git(["show", "--stat", "--format=", commit], cwd=clone_dir).strip()
        diff = _git(["show", "--format=", commit], cwd=clone_dir)

        # 6) fetch 回用户仓库（在用户仓库这一侧执行，只读操作的相反方向）
        fetch_from_local_clone(repo_root, clone_dir, branch)
        return {
            "branch": branch,
            "commit": commit,
            "diff_stat": diff_stat,
            "diff": diff,
        }
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


def fetch_from_local_clone(repo_root: Path, clone_dir: Path, branch: str) -> None:
    """
    把提案分支从临时 clone 拉回用户仓库。

    单独一个函数、参数形态固定，是为了不让调用方传入任意 remote 名。
    目标分支已存在时 git 原生拒绝（未传 ``--force``），因此「不覆盖已有分支」
    由 git 保证，不靠本函数判断。
    """
    subprocess.run(
        ["git", "fetch", str(clone_dir), f"{branch}:{branch}"],
        cwd=str(repo_root),
        capture_output=True, text=True, timeout=120, check=True,
    )


def list_proposal_branches(repo_root: Path) -> List[dict]:
    """列出用户仓库里的提案分支。只读。"""
    out = _git(["branch", "--list", f"{PROPOSAL_PREFIX}*", "--format=%(refname:short)"],
               cwd=repo_root)
    branches = []
    for name in out.split("\n"):
        name = name.strip()
        if not name:
            continue
        try:
            sha = _git(["rev-parse", name], cwd=repo_root).strip()
            subject = _git(["log", "-1", "--format=%s", name], cwd=repo_root).strip()
        except subprocess.CalledProcessError:
            continue
        branches.append({"branch": name, "commit": sha, "subject": subject})
    return branches


def discard_proposal(repo_root: Path, branch: str, *, force: bool = False) -> None:
    """删除提案分支。只允许 ``proposal/`` 前缀。"""
    if not branch.startswith(PROPOSAL_PREFIX):
        raise GitNotAllowed(f"只能删除 {PROPOSAL_PREFIX!r} 前缀的分支，实际 {branch!r}")
    flag = "-D" if force else "-d"   # -d 对未合并分支会失败，形成二次确认
    _git(["branch", flag, branch], cwd=repo_root)


def branch_exists(repo_root: Path, branch: str) -> bool:
    out = _git(["branch", "--list", branch], cwd=repo_root)
    return bool(out.strip())


def make_branch_name(resource: str) -> str:
    """生成不重复的提案分支名：``proposal/<resource>-<YYYYmmdd-HHMMSS>``。"""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return f"{PROPOSAL_PREFIX}{resource}-{stamp}"
