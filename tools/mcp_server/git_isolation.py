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

from tools.mcp_server import ToolError
from tools.mcp_server.proposal_registry import (
    make_workspace,
    proposal_ref,
)
from tools.specgen.schema import MAX_SPEC_TEXT_BYTES

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
    "merge-base",
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

#: 单次 ``describe_proposal`` 返回的 diff 字节上限。
#:
#: 为什么必须有：归属标记按设计**不校验 SHA**——任何人本地在带标记的分支上提交
#: 一个大文件即可，``git diff`` 的输出会原样进 JSON 响应（审核实测 2.4MB 原样
#: 返回）。``_git`` 用 ``capture_output`` 全量缓冲，只有 300s 超时、没有字节上限。
#:
#: 为什么取 4× 规格上限（=256KB）而不是 1×：``propose_spec_change`` 允许 64KB
#: 规格文本，其 diff 加上文件头与行前缀后必然超过 64KB。上限若取 1×，一个**合法**
#: 的最大提案会变得无法被 describe——工具拒绝自己的产物。4× 覆盖合法上限，又给
#: 多文件提案留出余量，同时把响应封在几百 KB 内。
#:
#: 超限**报错而不是截断**：静默截断会让审核人以为看到了全部改动。
MAX_PROPOSAL_DIFF_BYTES = 4 * MAX_SPEC_TEXT_BYTES

#: 单次 ``describe_proposal`` 返回的提交条数上限。
#:
#: 为什么 diff 的上限不够：那道上限只封 ``diff`` 字段，而 ``commits`` 是**另一个**
#: 无上限的字段。归属标记不校验 SHA，任何人都能在带标记的分支上推大量提交——
#: 每一条都进 ``commits`` 数组、原样进 JSON 响应，一个字节的 diff 都不用产生
#: （空提交，``--allow-empty``）。审核实测的形态：5 万个空提交 → diff 为空、
#: 闸不触发、响应却是几 MB 的 commits 数组。
#:
#: 为什么取 500：``propose_spec_change`` 一次提交一条提案，人工迭代的正常提案
#: 远达不到这个量级；500 条已远超任何真实提案的提交数，同时把 ``commits``
#: 元数据的 JSON 体积封在几百 KB 内（与 diff 闸同一量级）。
#:
#: 超限**报错而不是截断**：只返回前 N 条会让读者以为提案只有这些提交——与 diff
#: 截断是同一类误导，处置方式保持一致。
MAX_PROPOSAL_COMMITS = 500

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

#: 从 :data:`_COMMIT_IDENTITY` 派生，供环境变量覆盖使用（避免两处定义漂移）。
_TOOL_NAME = _COMMIT_IDENTITY[0].split("=", 1)[1]
_TOOL_EMAIL = _COMMIT_IDENTITY[1].split("=", 1)[1]

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
    "diff": (("--stat", "--name-only", "--name-status", "--format=", "-U", "-z"), 2),
    "log": (("--format=", "-1", "--oneline", "--stat", "-n"), 1),
    "status": (("--porcelain", "--short"), 0),
    "branch": (("--list", "--format=", "-d", "-D", "--show-current"), 2),
    "rev-parse": (("--verify", "--abbrev-ref", "--short", "--show-toplevel"), 1),
    # 只读 plumbing：两个 ref，无选项。用于三点区间（`A...B`）的左端。
    "merge-base": ((), 2),
    "ls-files": ((), 1),
    "checkout": (("-b", "-q", "--detach"), 2),
    "update-ref": (("-d",), 2),
    "show": (("--stat", "--format=", "--name-only"), 1),
}

#: 一律禁止的参数（任何子命令）。
_FORBIDDEN_ARGS = frozenset({
    "--hard", "--no-verify", "--no-gpg-sign", "--allow-empty",
    "--push", "--upload-pack", "--receive-pack", "--exec",
    "--output", "-u", "--template", "--template-dir",
})


class GitNotAllowed(ToolError):
    """
    尝试执行白名单之外的 git 子命令，或提案相关校验不通过。

    继承 :class:`tools.mcp_server.ToolError`（**不是**裸 Exception）：它携带的是
    已经脱敏、可以给调用方看的原因（分支名、base_ref 形态、diff 超限的字节数）。
    不继承的话，``_mcp_tool`` 出口会把它当「未预料异常」，客户端只收到
    ``Error executing tool <name>``，真实原因被丢掉——正是 MCP-05 审核实测到的
    ``HEAD~0`` 那类表现。``identity.IdentityError`` 已经是同一做法。
    """


#: 能覆盖「操作哪个仓库」的环境变量。必须全部清掉：
#: ``GIT_DIR`` 最危险——它优先于 cwd，会让我们的命令操作别的仓库。
_REPO_ENV_VARS = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_COMMON_DIR",
)


def _strip_repo_env(env: dict) -> None:
    """从 env 里删掉所有能改变目标仓库的变量（原地修改）。"""
    for name in _REPO_ENV_VARS:
        env.pop(name, None)


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
    # 顺序：**先清理、再覆盖**。
    # 1) 清掉能改变「操作哪个仓库」的变量。不清理的话，用户环境里的 GIT_DIR
    #    会让 `git -C <我们指定的 cwd>` 仍然操作另一个仓库——cwd 参数形同虚设。
    #    （本工具，v0.4.1 硬化）
    _strip_repo_env(env)
    # 2) 显式覆盖身份环境变量：`GIT_AUTHOR_NAME` / `GIT_COMMITTER_EMAIL` 这类
    #    变量的优先级高于 `-c user.name=...`——若运行环境设了它们，会盖过工具
    #    身份。与 `-c user.*` 配套，确保 commit 的作者始终是本工具，不随环境漂移。
    #    （另一条 lane 的改动，与本工具的 `_REPO_ENV_VARS` 零交集，两段并存）
    for _k, _v in (
        ("GIT_AUTHOR_NAME", _TOOL_NAME),
        ("GIT_AUTHOR_EMAIL", _TOOL_EMAIL),
        ("GIT_COMMITTER_NAME", _TOOL_NAME),
        ("GIT_COMMITTER_EMAIL", _TOOL_EMAIL),
    ):
        env[_k] = _v
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
            result.returncode, ["git", *prefix, *args],
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

    ``refs/tags/<name>`` 也在候选表内：``validate_base_ref`` 接受合法 tag
    （``rev-parse --verify <tag>^{commit}`` 能解析），若这里只看 heads/remotes，
    同一个 ``v1`` 就会「校验通过、创建提案时却说找不到」——审核实测到的不一致。
    优先级保持 heads → remotes → tags：已有分支名的解析结果不变，只是补上 tag。
    """
    candidates = [
        f"refs/heads/{base_ref}",
        f"refs/remotes/origin/{base_ref}",
        f"refs/tags/{base_ref}",
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
    # 用带标记文件的固定前缀目录：既是隔离工作区，也让残留清理能识别归属
    tmp_root = make_workspace()
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
        # 8) 写归属标记 ref：discard 靠它判断「是不是本工具建的」。
        #    放在 fetch 之后——分支确实落地了才登记，否则会留下指向空气的标记。
        #    必须走 `_git_on_user_repo`（屏蔽用户仓库自己的 reference-transaction
        #    hook），不能走 `_git`——后者只净化环境，不屏蔽 hook。
        try:
            _git_on_user_repo(
                repo_root,
                ["update-ref", proposal_ref(branch), commit],
            )
        except subprocess.CalledProcessError as exc:
            # L1：标记写失败时回滚刚落地的分支——否则会留下一个「无归属」的
            # 提案分支，既不能被 discard（没有标记），又占着名字。
            # 用带期望值的 update-ref -d 保证只删我们刚写的那个 commit。
            #
            # 回滚本身也可能失败，两种结果必须**分别**告诉调用方：
            # 失败的 `pass` 会让调用方以为已经清理干净，实际残留了一个分支。
            rollback_ok = True
            rollback_err = ""
            try:
                _git_on_user_repo(
                    repo_root,
                    ["update-ref", "-d", f"refs/heads/{branch}", commit],
                )
            except (GitNotAllowed, subprocess.CalledProcessError) as rb_exc:
                rollback_ok = False
                rollback_err = (
                    getattr(rb_exc, "stderr", "") or str(rb_exc)
                ).strip()[:200]
                _log.error(
                    "提案分支回滚失败，残留分支 %s（commit %s）：%s",
                    branch, commit, rollback_err,
                )
            if rollback_ok:
                raise GitNotAllowed(
                    f"提案分支已创建但归属标记写入失败，**已回滚分支** {branch!r}，"
                    f"仓库已恢复到操作前状态。原因：{(exc.stderr or '').strip()[:200]}"
                ) from None
            raise GitNotAllowed(
                f"提案分支已创建，归属标记写入失败，**回滚也失败了**："
                f"残留分支 {branch!r}（commit {commit}）需要人工删除。"
                f"标记写入错误：{(exc.stderr or '').strip()[:150]}；"
                f"回滚错误：{rollback_err}"
            ) from None
        return {
            "branch": branch,
            "commit": commit,
            "diff_stat": diff_stat,
            "diff": diff,
        }
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


#: 允许在**用户仓库**上执行的子命令。
_USER_REPO_SUBCOMMANDS = frozenset({
    "update-ref", "fetch", "rev-parse", "for-each-ref", "symbolic-ref",
})


def _git_on_user_repo(repo_root: Path, args: Sequence[str]) -> str:
    """
    在**用户仓库**上执行 git 命令，并屏蔽该仓库自己的 hook。

    为什么不能直接走 ``_git``：``_git`` 只做环境净化，但用户仓库里可能装了
    ``reference-transaction`` / ``post-checkout`` 等 hook——任何改 ref 的操作
    （``update-ref``、``branch -D``）都会触发它们。我们不该替用户跑他们的 hook：
    副作用不可控（可能部署、可能通知、可能失败导致我们的操作中途失败）。

    做法：独立起 subprocess，带 ``-c core.hooksPath=/dev/null -c gc.auto=0``
    （与 ``fetch_from_local_clone`` 一致），并做同样的环境净化。
    """
    if not args:
        raise GitNotAllowed("用户仓库操作缺少子命令")
    # 只允许**实际用到**的子命令。`_git` 的白名单更宽（含 clone/add/commit 等
    # 只在隔离 clone 里用的），这里收紧到用户仓库上真正需要的几个——
    # 任何新增的用户仓库写操作都必须显式加进这个集合，避免顺手扩权。
    if args[0] not in _USER_REPO_SUBCOMMANDS:
        raise GitNotAllowed(
            f"用户仓库不允许子命令 {args[0]!r}；允许的是 "
            f"{sorted(_USER_REPO_SUBCOMMANDS)}"
        )
    for arg in args:
        if arg in _FORBIDDEN_ARGS or arg.startswith("--force"):
            raise GitNotAllowed(f"用户仓库操作不允许参数 {arg!r}")
    env = dict(os.environ)
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = ""
    env["SSH_ASKPASS"] = ""
    _strip_repo_env(env)
    result = subprocess.run(
        ["git",
         "-c", "core.hooksPath=" + os.devnull,
         "-c", "gc.auto=0",
         *args],
        cwd=str(repo_root),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, ["git", *args],
            output=result.stdout, stderr=result.stderr,
        )
    return result.stdout


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
    # 同样要清 GIT_DIR 等变量：不清的话 fetch 会把分支写进 GIT_DIR 指向的
    # 另一个仓库，而我们后续在主仓库里找不到它（实测：回滚会因此失败）。
    _strip_repo_env(env)
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


#: 归属校验失败时按操作给出的补充说明。``describe_proposal`` 与
#: ``discard_proposal`` 共用同一份校验（:func:`_check_proposal_ownership`），
#: 只有这句解释按操作分叉。
_OWNERSHIP_HINTS = {
    "描述": "本工具只描述自己创建的提案分支——手工建立的同名分支不在此列。",
    "删除": "本工具只删除自己创建的提案分支——手工建立的同名分支不会被删。",
}


def _check_proposal_ownership(repo_root: Path, branch: str, *, action: str) -> str:
    """
    提案归属校验——``describe_proposal`` 与 ``discard_proposal`` **共用这一份**。

    在抽出来之前，两个工具各写了一遍（连注释都几乎一样），「与 discard 同源」
    只是口头说法：任何一处的判据被改动，另一处不会跟着变。现在只有一个实现。

    必须同时满足：

    1. 分支名是 ``proposal/`` 前缀（:data:`PROPOSAL_PREFIX`）
    2. 分支名形态合法（:data:`_BRANCH_RE`，``git check-ref-format`` 的子集）
    3. 分支存在
    4. 存在归属标记 ``refs/specgen/proposals/<name>``（证明是本工具创建的）

    **不比对标记 SHA**：那条只为「删除时被人偷换内容」服务，由
    :func:`discard_proposal` 在拿到返回值后自己做——读操作应如实返回分支现状。

    Args:
        repo_root: 用户仓库根目录（调用方负责 ``resolve()``）
        branch: 提案分支名
        action: ``"描述"`` 或 ``"删除"``，只用于错误措辞

    Returns:
        ``(ref, marked)``：归属标记的 ref 全名，以及它指向的 commit SHA（已 strip）。
        ``discard`` 用这两者做 SHA 比对与标记清理；``describe`` 只关心「标记存在」，
        忽略返回值。

    Raises:
        GitNotAllowed: 上述任一条不满足
    """
    if not branch.startswith(PROPOSAL_PREFIX):
        raise GitNotAllowed(
            f"只能{action} {PROPOSAL_PREFIX!r} 前缀的分支，实际 {branch!r}"
        )
    # 形态校验放在最前：拼 `refs/heads/<b>` 全名之前先确认名字合法，
    # 否则 `proposal/../x` 这类输入可能拼出意料之外的 ref 路径。
    if not _BRANCH_RE.fullmatch(branch):
        raise GitNotAllowed(f"分支名不合法：{branch!r}")

    if not branch_exists(repo_root, branch):
        raise GitNotAllowed(f"分支不存在：{branch!r}")

    ref = proposal_ref(branch)
    try:
        marked = _git(
            ["rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=repo_root
        ).strip()
    except subprocess.CalledProcessError:
        raise GitNotAllowed(
            f"拒绝{action} {branch!r}：没有归属标记（{ref}）。"
            + _OWNERSHIP_HINTS[action]
        ) from None
    return ref, marked


def _parse_name_status(raw: str) -> List[dict]:
    """
    解析 ``git diff --name-status -z`` 的输出。

    **为什么不从 diff 头里猜状态**（改前的做法）：git 对非 ASCII 路径输出转义
    引号形式 ``diff --git "a/specs/\\346\\226\\260\\345\\242\\236.yaml" "b/..."``，
    切 ``" b/"`` 得到的是「状态恒为 M + 被转义的引号串」——新增文件被报成修改，
    重命名只剩新路径。审核实测：把状态恒置 ``"M"``，16 项测试全绿，证明该字段
    没有任何断言覆盖。

    ``--name-status -z`` 直接给出状态字母与 **未转义** 的 NUL 分隔路径。实测格式::

        A\\0path\\0
        M\\0path\\0
        D\\0path\\0
        R100\\0oldpath\\0newpath\\0

    重命名/复制（``R``/``C``）占三段：状态、旧路径、新路径；其余占两段。

    Returns:
        ``[{"status": "A"|"M"|"D"|"R"|"C"|..., "path": <新路径>, "old_path": <仅 R/C>}]``

        状态归一成首字母（``R100`` → ``R``），与 ``A``/``M``/``D`` 保持同为单字符，
        相似度分数不携带额外语义。重命名额外给出 ``old_path``——旧路径消失正是
        改前实现的第二个错误。
    """
    tokens = raw.split("\0")
    # `-z` 末尾必带一个 NUL，split 后末位是空串；中途的空串只可能来自格式异常。
    if tokens and tokens[-1] == "":
        tokens.pop()

    entries: List[dict] = []
    i = 0
    while i < len(tokens):
        status = tokens[i]
        i += 1
        if not status:
            continue
        letter = status[:1]
        if letter in ("R", "C"):
            # 重命名/复制占三段：<status> <old> <new>
            if i + 1 >= len(tokens):
                # 格式异常：宁可丢弃这一条，也不要凭空造一个空路径。
                _log.warning("git diff --name-status -z 输出不完整，已跳过：%r", raw)
                break
            old_path, new_path = tokens[i], tokens[i + 1]
            i += 2
            entries.append({"status": letter, "path": new_path, "old_path": old_path})
        else:
            # 其余占两段：<status> <path>
            if i >= len(tokens):
                _log.warning("git diff --name-status -z 输出不完整，已跳过：%r", raw)
                break
            entries.append({"status": letter, "path": tokens[i]})
            i += 1
    return entries


def describe_proposal(repo_root: Path, branch: str, *, base_ref: str = DEFAULT_BASE_REF) -> dict:
    """
    返回一个提案相对基线的完整 unified diff 与元数据。**只读**。

    归属校验与 :func:`discard_proposal` **同源**——两边都调用
    :func:`_check_proposal_ownership`，必须同时满足：

    1. 分支名是 ``proposal/`` 前缀且形态合法
    2. 存在归属标记 ``refs/specgen/proposals/<name>``（证明是本工具创建的）

    与 ``discard`` 的区别：不要求「标记 SHA == 分支当前 SHA」。那条是为了防
    **删除**时被人偷换内容；这里只**读**，内容变了反而应该如实返回——读者
    看到的正是分支现在的样子。标记只用来证明「这是本工具建的提案」，不是证明
    「没被改过」。

    全程在**隔离 clone** 里执行 ``git diff``：不读用户工作区、不写任何东西、
    不碰工作区的 index。

    **diff 区间用三点号**（``<base>...<head>`` = ``merge-base(base, head)..head``）：
    提案从旧 master 分出后 master 又前进了，两点号会把别人已合并的改动**反向**
    显示成本提案删除的内容，并在 ``files`` 里混入别人的文件（审核实测）。

    Args:
        repo_root: 用户仓库根目录
        branch: 提案分支名
        base_ref: 对比的基线，默认 ``master``

    Returns:
        ``{"branch", "base", "head", "commits", "files", "diff"}``

        ``base`` 是 **merge-base** 的 SHA（即三点区间的左端），不是 ``base_ref``
        当前指向的提交——master 前进后二者会不同，而 diff 恰好是相对前者的。

    Raises:
        GitNotAllowed: 前缀/形态不合法、分支不存在、无归属标记、基线不可达、
            diff 超过 :data:`MAX_PROPOSAL_DIFF_BYTES`、提交条数超过
            :data:`MAX_PROPOSAL_COMMITS`
    """
    repo_root = repo_root.resolve()
    _check_proposal_ownership(repo_root, branch, action="描述")

    # 全名解析，避免与同名 tag 混淆
    head = _git(["rev-parse", f"refs/heads/{branch}^{{commit}}"], cwd=repo_root).strip()

    tmp_root = make_workspace()
    clone_dir = tmp_root / "repo"
    try:
        _git(
            ["clone", "--no-hardlinks", "--local", str(repo_root), str(clone_dir)],
            cwd=repo_root,
        )
        _pin_base_ref(clone_dir, base_ref)
        _harden_clone(clone_dir)

        # 「基线不可达」不由本函数报：`_pin_base_ref` 解析不到 base_ref 时已经
        # 先抛（措辞「隔离 clone 里找不到 base_ref」）。改前这里还有一段
        # `rev-parse <base_ref>^{commit}` + 「基线分支不可达」，但 `_pin_base_ref`
        # 刚把该 ref 固化成 `refs/heads/<base_ref>`，那段永远走不到（审核指出是
        # 死代码，已删）。这里负责的是另一件事——两个 ref 可达但**没有共同祖先**。

        # 三点区间：A...B == diff $(git merge-base A B) B。
        # 两点号是「两棵树全量对比」，master 前进后会把别人已合并的改动**反向**
        # 显示成本提案删除的内容（审核实测），且 `files` 里混入别人的文件。
        # 注意 `git rev-parse A...B` 会输出**三行**（A、B、^merge-base），不能拿它
        # 算左端；`git merge-base` 只给那一行。
        try:
            base = _git(["merge-base", base_ref, head], cwd=clone_dir).strip()
        except subprocess.CalledProcessError:
            raise GitNotAllowed(
                f"基线 {base_ref!r} 与提案分支没有共同祖先，无法计算 diff"
            ) from None

        commits_out = _git(
            ["log", "--format=%H%x1f%an%x1f%aI%x1f%s", f"{base}..{head}"],
            cwd=clone_dir,
        ).strip()

        # 提交条数闸：上面的 diff 闸只封 ``diff`` 字段，``commits`` 是另一个
        # 独立字段——空提交（``--allow-empty``）不产生任何 diff，能让 commits
        # 无上限增长而完全不触发 diff 闸。超限同样**报错而不是截断**。
        commit_lines = [line for line in commits_out.split("\n") if line.strip()]
        commit_count = len(commit_lines)
        if commit_count > MAX_PROPOSAL_COMMITS:
            raise GitNotAllowed(
                f"提案过大：{commit_count} 条提交，超过上限 "
                f"{MAX_PROPOSAL_COMMITS} 条。本工具不返回被截断的内容——"
                "请缩小提案，或由人在本地用 git log 查看完整提交列表。"
            )

        commits = []
        for line in commit_lines:
            sha, author, iso, subject = line.split("\x1f", 3)
            commits.append(
                {"sha": sha, "author": author, "date": iso, "subject": subject}
            )

        diff = _git(["diff", f"{base}...{head}"], cwd=clone_dir)
        # 归属标记按设计不校验 SHA：任何人本地在带标记的分支上提交一个大文件
        # 即可让 diff 无限增长原样进 JSON。超限**报错而不是截断**——静默截断会
        # 让审核人以为看到了全部改动。
        diff_size = len(diff.encode("utf-8"))
        if diff_size > MAX_PROPOSAL_DIFF_BYTES:
            raise GitNotAllowed(
                f"提案过大：diff {diff_size} 字节，超过上限 "
                f"{MAX_PROPOSAL_DIFF_BYTES} 字节。本工具不返回被截断的内容——"
                "请缩小提案，或由人在本地用 git show 查看完整改动。"
            )

        files = _parse_name_status(
            _git(["diff", "--name-status", "-z", f"{base}...{head}"], cwd=clone_dir)
        )
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    return {
        "branch": branch,
        "base": base,
        "head": head,
        "commits": commits,
        "files": files,
        "diff": diff,
    }


def discard_proposal(repo_root: Path, branch: str, *, force: bool = False) -> None:
    """
    删除提案分支。**必须同时满足三条**才允许删：

    1. 分支名是 ``proposal/`` 前缀
    2. 存在归属标记 ``refs/specgen/proposals/<name>``（证明是本工具创建的）
    3. 标记指向的 SHA 等于分支当前 SHA（证明分支没被人改过）

    只按前缀删是危险的：任何人手工建一个 ``proposal/xxx`` 就能被本工具删掉，
    而删除不可逆。归属标记把「命名约定」换成了「可验证的证据」。

    前两条由 :func:`_check_proposal_ownership` 执行——与 ``describe_proposal``
    **同一个函数**，不是两份副本。第三条只有删除需要，在本函数内完成。
    """
    # 与 describe 共用同一份归属校验：前缀 → 形态 → 存在 → 标记存在。
    ref, marked = _check_proposal_ownership(repo_root, branch, action="删除")

    # 全名解析：短名遇到同名 tag 时 git 会有歧义（tag 与分支同名是合法的）
    current = _git(
        ["rev-parse", f"refs/heads/{branch}^{{commit}}"], cwd=repo_root
    ).strip()
    if marked != current:
        raise GitNotAllowed(
            f"拒绝删除 {branch!r}：分支已被改动（标记指向 {marked[:7]}，"
            f"分支现在 {current[:7]}）。请人工确认后再处理。"
        )

    # M3：用**原子的** `update-ref -d refs/heads/<b> <expected>` 删除分支。
    # 带期望值时，若分支在「我们比对 SHA」和「实际删除」之间又变了，git 会
    # 自己拒绝（TOCTOU 窗口由 git 的原子性封住），而不是靠我们两次读之间的假设。
    # L2：全程用 refs/heads/<b> 全名，避免与同名 tag 混淆。
    full_branch = f"refs/heads/{branch}"
    try:
        _git_on_user_repo(
            repo_root, ["update-ref", "-d", full_branch, marked]
        )
    except subprocess.CalledProcessError as exc:
        raise GitNotAllowed(
            f"删除分支 {branch!r} 失败（可能已被并发修改）："
            f"{(exc.stderr or '').strip()[:200]}"
        ) from None

    # 分支删掉后归属标记也要清掉，否则下次同名分支会撞上一个陈旧标记。
    # 失败不致命：标记指向一个已不存在的 commit，下次 discard 会因 SHA 不一致拒绝，
    # 但不会误删——这是安全方向的失败。
    try:
        # 带期望值：只删掉指向 marked 的那个标记。若标记在此期间被别人改成
        # 别的 commit，git 会拒绝——避免误删他人的标记。
        _git_on_user_repo(repo_root, ["update-ref", "-d", ref, marked])
    except subprocess.CalledProcessError:
        _log.warning("归属标记 %s 清理失败（分支已删除）", ref)


def branch_exists(repo_root: Path, branch: str) -> bool:
    """
    分支是否存在。

    用 `rev-parse --verify refs/heads/<b>` 而非 `branch --list <b>`：后者在
    存在同名 tag 时行为依赖匹配模式，前者按全名精确解析，不会把 tag 当成分支。
    """
    try:
        _git(["rev-parse", "--verify", f"refs/heads/{branch}^{{commit}}"],
             cwd=repo_root)
        return True
    except subprocess.CalledProcessError:
        return False


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
