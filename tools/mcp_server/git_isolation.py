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
import re
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
    "update-ref",
})

#: 提案分支前缀。`list_proposals` / `discard_proposal` 只认这个前缀。
PROPOSAL_PREFIX = "proposal/"

#: 默认 base_ref。**不取 HEAD**：用户的工作区可能停在某个功能分支上，那样提案
#: 会基于一个未完成的提交。master 才是约定的主线。
DEFAULT_BASE_REF = "master"

#: 提案提交使用的工具身份。
#:
#: 为什么必须显式指定：``_git`` 会设 ``GIT_CONFIG_GLOBAL=/dev/null`` 与
#: ``GIT_CONFIG_NOSYSTEM=1``（防用户全局 hooksPath 干扰，见 §6），副作用是
#: **读不到任何用户身份**。本地之所以能过，是因为 git 会拿「用户名+主机名」
#: 自动推断；CI 容器里连这个推断也不成立，``git commit`` 直接 exit 128。
#:
#: 显式署名同时是审计要求：提案的 commit 应当能一眼看出是工具产生的，
#: 而不是和人的提交混在一起。
_COMMIT_IDENTITY = (
    "user.name=sanic-specgen-mcp",
    "user.email=specgen-mcp@noreply.invalid",
)

#: 允许通过 `git -c key=value` 前置传入的配置键。
#: 只放行提交身份；`core.hooksPath`、`alias.*`、`filter.*` 等一律拒绝。
_ALLOWED_CONFIG_KEYS = frozenset({"user.name", "user.email"})

#: **参数级**白名单：每个子命令只放行明确列出的参数形态。
#:
#: 只做子命令白名单不够——`git clone --upload-pack=<恶意命令>` 能在子命令合法的
#: 前提下执行任意程序。这里按子命令列出允许的位置参数个数与可接受的选项前缀，
#: 表外的组合一律拒绝。
#:
#: 值是 `(允许的选项前缀元组, 位置参数个数上限)`。
_ALLOWED_ARGS: dict = {
    "clone": (("--no-hardlinks", "--local", "-q"), 2),
    "add": (("-A", "-u"), 0),
    "commit": (("-m", "-q"), 1),
    "diff": (("--stat", "--name-only", "--format=", "-U"), 2),
    "log": (("--format=", "-1", "--oneline", "--stat", "-n"), 1),
    "status": (("--porcelain", "--short"), 0),
    "branch": (("--list", "--format=", "-d", "-D", "--show-current"), 2),
    "rev-parse": (("--verify", "--abbrev-ref", "--short", "--show-toplevel"), 1),
    "ls-files": ((), 1),
    "checkout": (("-b", "-q", "--detach"), 2),
    "update-ref": ((), 2),
    "show": (("--stat", "--format=", "--name-only"), 1),
}

#: 一律禁止的参数（任何子命令）。
_FORBIDDEN_ARGS = frozenset({
    "--hard", "--no-verify", "--no-gpg-sign", "--allow-empty",
    "--push", "--upload-pack", "--receive-pack", "--exec",
    "--output", "-u", "--template", "--template-dir",
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

    # 允许**受控的**前置全局选项：仅 `-c key=value`，且 key 必须在允许集合内。
    # `git -c user.name=... commit` 是给单条命令临时配置的标准写法——我们需要它
    # 给提案提交署上工具身份（见 _COMMIT_IDENTITY），而不写进任何配置文件。
    # 只放行白名单里的 key，`-c core.hooksPath=...` 之类的逃逸仍然被拒。
    prefix: List[str] = []
    rest = list(args)
    while len(rest) >= 2 and rest[0] == "-c":
        kv = rest[1]
        key = kv.split("=", 1)[0]
        if key not in _ALLOWED_CONFIG_KEYS:
            raise GitNotAllowed(
                f"git -c 只允许以下配置键：{sorted(_ALLOWED_CONFIG_KEYS)}；拒绝 {key!r}"
            )
        if "=" not in kv:
            raise GitNotAllowed(f"git -c 需要 key=value 形式，实际 {kv!r}")
        prefix.extend(["-c", kv])
        rest = rest[2:]
    if not rest:
        raise GitNotAllowed("git 调用缺少子命令")
    args = rest

    sub = args[0]
    if sub not in ALLOWED_SUBCOMMANDS:
        raise GitNotAllowed(
            f"git 子命令 {sub!r} 不在允许列表内；"
            f"允许的是 {sorted(ALLOWED_SUBCOMMANDS)}"
        )

    # 子命令合法时，再做**参数级**检查：表外的选项与过多的位置参数一律拒绝。
    # 只挡子命令不够——`clone --upload-pack=<命令>` 能在子命令合法的前提下
    # 执行任意程序。
    allowed_prefixes, max_positional = _ALLOWED_ARGS[sub]
    positional = 0
    i = 1
    while i < len(args):
        arg = args[i]
        if arg in _FORBIDDEN_ARGS or arg.startswith("--force"):
            raise GitNotAllowed(
                f"git {sub} 不允许参数 {arg!r}（会改动历史、执行外部程序或绕过检查）"
            )
        if arg.startswith("-"):
            if arg.startswith("-f") and not arg.startswith("--"):
                raise GitNotAllowed(f"git {sub} 不允许强制参数 {arg!r}")
            if not any(arg == p or arg.startswith(p) for p in allowed_prefixes):
                raise GitNotAllowed(
                    f"git {sub} 不允许选项 {arg!r}；允许的是 {list(allowed_prefixes)}"
                )
            # 选项带独立值（如 `-m` 后面跟 message）时，把下一个参数当作值跳过
            if arg in ("-m", "-b", "-n", "-U", "-c"):
                i += 2
                continue
        else:
            positional += 1
            if positional > max_positional:
                raise GitNotAllowed(
                    f"git {sub} 位置参数过多（上限 {max_positional}）：{args[1:]}"
                )
        i += 1

    env = dict(os.environ)
    # 切断可能存在的凭据通道：即使代码路径被改，也没有可用的 credential helper。
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = ""
    env["SSH_ASKPASS"] = ""
    # **净化全局配置**：用户可能有全局 core.hooksPath 或 templateDir，前者会让
    # 我们的 pre-push 失效（git 去别处找 hook），后者会让 clone 里出现用户自己的
    # hook。把全局与系统配置都关掉，git 只看仓库自己的 .git/config。
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    if env_extra:
        env.update(env_extra)

    result = subprocess.run(
        ["git", *prefix, *args],
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


def _harden_clone(clone_dir: Path) -> None:
    """
    让隔离 clone 从根上没有推送目标，且凭据通道置空。

    **直接改 `.git/config` 文件，不走 `git config` 命令**：`config` 既能读也能写，
    放进白名单等于给工具一个「改任意配置」的能力。只改这一个临时 clone 的文件，
    能力边界最小。

    同时把 ``core.hooksPath`` 显式指向 clone 自己的 hooks 目录——即使用户的
    （已被隔离的）配置里有什么花样，git 也只会去我们指定的地方找 hook。
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

    hooks_dir = (clone_dir / ".git" / "hooks").resolve()
    body = "\n".join(lines).rstrip() + "\n"
    body += "[push]\n\tdefault = nothing\n[credential]\n\thelper =\n"
    body += "[core]\n\thooksPath = " + str(hooks_dir) + "\n[gc]\n\tauto = 0\n"
    config_path.write_text(body, encoding="utf-8")
    _write_pre_push_hook(clone_dir)


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


def _has_remote_ref(clone_dir: Path, name: str) -> bool:
    """clone 里是否存在 ``origin/<name>``（删 remote 前判断用）。"""
    try:
        _git(["rev-parse", "--verify", f"refs/remotes/origin/{name}^{{commit}}"],
             cwd=clone_dir)
        return True
    except subprocess.CalledProcessError:
        return False


def _pin_base_ref(clone_dir: Path, base_ref: str) -> None:
    """
    在 clone 里确保存在一个名为 ``base_ref`` 的**本地分支**，指向正确提交。

    顺序很重要：必须在 ``_harden_clone`` 删掉 remote 之前调用。clone 默认只
    checkout 用户当前的 HEAD 分支，若 base_ref 是别的分支（常见：用户停在功能
    分支、base_ref 是 master），它只以 ``refs/remotes/origin/<name>`` 存在。
    """
    candidates = [
        f"refs/heads/{base_ref}",
        f"refs/remotes/origin/{base_ref}",
    ]
    for ref in candidates:
        try:
            sha = _git(["rev-parse", "--verify", f"{ref}^{{commit}}"],
                       cwd=clone_dir).strip()
            break
        except subprocess.CalledProcessError:
            continue
    else:
        raise GitNotAllowed(f"隔离 clone 里找不到 base_ref {base_ref!r}")

    # 用 update-ref 而非 `git branch`：不依赖当前 HEAD 状态，也不受分支已存在影响
    _git(["update-ref", f"refs/heads/{base_ref}", sha], cwd=clone_dir)


def make_proposal(
    repo_root: Path,
    branch: str,
    commit_message: str,
    write_files: "callable",
    *,
    base_ref: str = DEFAULT_BASE_REF,
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
        # 2) 在删 remote **之前**把 base_ref 固化成 clone 里的本地分支。
        #    clone 默认只 checkout 用户仓库的当前分支，`master` 可能只以
        #    `origin/master` 的形式存在；一旦 `_harden_clone` 删掉 remote，
        #    那个远程跟踪分支也就没了，后续 `checkout -b ... master` 会失败。
        _pin_base_ref(clone_dir, base_ref)
        # 3) 硬化：无 remote、无凭据、pre-push 无条件失败
        _harden_clone(clone_dir)
        # 4) 从 base_ref 切出提案分支（分支不存在才创建，不改已有）
        _git(["checkout", "-b", branch, base_ref], cwd=clone_dir)
        # 4) 让调用方写文件（规格 YAML 等）
        write_files(clone_dir)
        # 5) 提交。**显式带上工具身份**：_git 清空了全局与系统配置，
        #    拿不到用户身份；CI 容器里连 git 的「用户名+主机名」自动推断
        #    也不成立，不带 -c 会直接 exit 128。
        _git(["add", "-A"], cwd=clone_dir)
        commit_args = ["-c", _COMMIT_IDENTITY[0], "-c", _COMMIT_IDENTITY[1],
                       "commit", "-m", commit_message]
        _git(commit_args, cwd=clone_dir)
        commit = _git(["rev-parse", "HEAD"], cwd=clone_dir).strip()
        diff_stat = _git(["show", "--stat", "--format=", commit], cwd=clone_dir).strip()
        diff = _git(["show", "--format=", commit], cwd=clone_dir)

        # 6) 写用户仓库前再确认一次分支不存在。
        #    即使快进也不允许——同一个提案分支被二次写入会让「一个提案一个分支」
        #    的语义失效，人在 PR 里看到的 diff 也不再是最初那份。
        if branch_exists(repo_root, branch):
            raise GitNotAllowed(
                f"用户仓库里已存在分支 {branch!r}，拒绝写入（快进也不行）"
            )
        # 7) fetch 回用户仓库（在用户仓库这一侧执行）
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

    **在用户仓库一侧执行 fetch 时同样做净化**：
    - ``-c core.hooksPath=/dev/null``：用户仓库若装了 reference-transaction /
      post-fetch 之类的 hook，会被这次 fetch 触发。我们不希望替用户跑他们的 hook。
    - ``-c gc.auto=0``：避免 fetch 顺带触发 gc 在用户仓库里做大扫除。
    - 全局与系统配置关闭，同 ``_git``。

    目标分支已存在时 git 原生拒绝（未传 ``--force``），因此「不覆盖已有分支」
    由 git 保证，不靠本函数判断。
    """
    env = dict(os.environ)
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    subprocess.run(
        ["git",
         "-c", "core.hooksPath=" + os.devnull,
         "-c", "gc.auto=0",
         "fetch", str(clone_dir), f"{branch}:{branch}"],
        cwd=str(repo_root),
        env=env,
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


#: ref 形态白名单：`check-ref-format` 的严格子集。
#: 不用 `git check-ref-format` 子命令——它需要 `--` 与参数形态配合，多一层
#: 出错面；这里的正则覆盖分支名与 tag 名的常见形态，且天然拒绝 `..`、`~`、
#: `^`、`:`、`?`、`*`、`[`、`\`、空格与以 `/` 或 `.` 开头结尾的名字。
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*[A-Za-z0-9]$|^[A-Za-z0-9]$")


def validate_base_ref(repo_root: Path, ref: str) -> str:
    """
    校验 base_ref：形态合法 + 确实存在。

    Raises:
        GitNotAllowed: 形态不合法，或 ref 在仓库里不存在
    """
    if not isinstance(ref, str) or not ref:
        raise GitNotAllowed("base_ref 不能为空")
    if ref.startswith("-"):
        raise GitNotAllowed(f"base_ref 不合法：{ref!r}（不能以 - 开头，会被当成选项）")
    if ".." in ref or ref.startswith("/") or ref.endswith("/"):
        raise GitNotAllowed(f"base_ref 不合法：{ref!r}（不允许 '..' 或以 / 开头结尾）")
    if not _REF_RE.fullmatch(ref):
        raise GitNotAllowed(f"base_ref 不合法：{ref!r}（含非法字符）")
    try:
        _git(["rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=repo_root)
    except subprocess.CalledProcessError:
        raise GitNotAllowed(f"base_ref 不存在：{ref!r}") from None
    return ref


def make_branch_name(resource: str) -> str:
    """
    生成不重复的提案分支名：``proposal/<resource>-<YYYYmmdd-HHMMSS>``。

    拼好的名字还要过一遍 ``_BRANCH_RE``（``git check-ref-format`` 的形态子集）——
    resource 已经过白名单，这里是第二道，防的是将来 resource 校验被放宽时
    分支名悄悄变成非法或带路径穿越的形态。
    """
    stamp = time.strftime("%Y%m%d-%H%M%S")
    name = f"{PROPOSAL_PREFIX}{resource}-{stamp}"
    if not _BRANCH_RE.fullmatch(name):
        raise GitNotAllowed(f"生成的分支名不合法：{name!r}")
    return name


#: 分支名形态（``git check-ref-format`` 的严格子集）。
#: 拒绝 `..`、`~`、`^`、`:`、`?`、`*`、`[`、`\`、空格、连续 `/`、
#: 以 `/` 或 `.` 开头结尾、以 `.lock` 结尾。
_BRANCH_RE = re.compile(
    r"^(?!.*\.\.)(?!.*//)(?!.*[~^:?*\[\\ ])"
    r"(?!.*\.lock$)(?!.*\.$)(?!.*/$)proposal/[a-z][a-z0-9_]*-\d{8}-\d{6}$"
)
