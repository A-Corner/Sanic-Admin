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
import signal
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


#: 测试自己跑 git 时也做净化，避免本机全局配置影响结果
#: （用户可能设了 core.hooksPath / init.defaultBranch / user.* 等）。
_CLEAN_ENV = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
}


def _run(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, check=True,
        env={**os.environ, **_CLEAN_ENV},
    ).stdout


def _git_raw(cwd: Path, *args: str, env_extra=None) -> subprocess.CompletedProcess:
    """跑 git 但**不检查返回码**，用于断言失败场景。"""
    env = {**os.environ, **_CLEAN_ENV}
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, env=env,
    )


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


def _run_git_push_isolated(cwd: Path, args: list, timeout: int = 30):
    """
    跑 `git push`，超时时**杀掉整个进程组**，不留孤儿。

    为什么不能只用 ``subprocess.run(timeout=...)``：它超时只杀掉直接子进程
    （`git push`），而 `git push` 会再拉起 `git-receive-pack`，后者又调用
    pre-push hook。这两个孙进程不随父进程退出，变成 PPID=1 的孤儿继续等待
    （实测：一次超时留下 4 个 `git-receive-pack` / `pre-push.real` 进程）。

    做法：
    - ``start_new_session=True`` 让子进程成为新会话/进程组的组长；
    - 超时时 ``os.killpg(pgid, SIGKILL)`` 把整组一次干掉。

    Returns:
        ``(returncode, stdout, stderr)``
    """
    proc = subprocess.Popen(
        ["git", *args],
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # 整组一起杀：pgid == 子进程 pid（start_new_session 的效果）
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()
        raise
    return proc.returncode, out, err


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
    #
    # **不改写实现装进去的 hook**——否则跑的是测试写的 hook，不是实现的。
    # 做法：把实现的 hook 改名为 pre-push.real（内容一字未动），再装一个
    # wrapper 调用它，wrapper 在调用前后各写一次标记文件。
    marker = tmp_path / "hook-ran.marker"
    real_hook = hook.with_name("pre-push.real")
    hook.rename(real_hook)
    hook.write_text(
        "#!/bin/sh\n"
        # **先读掉 stdin**：git push 会把待推的 ref 列表写进 pre-push 的 stdin。
        # hook 不读就走，git 写管道时可能阻塞——实测这套测试偶发挂起 600 秒，
        # 残留进程停在 `git push` 与 `git-receive-pack` 互相等待。
        "cat >/dev/null\n"
        f'echo ran > "{marker}"\n'
        f'exec "{real_hook}" "$@"\n',
        encoding="utf-8",
    )
    hook.chmod(0o755)
    assert real_hook.read_text(encoding="utf-8") == (
        "#!/bin/sh\n"
        "# MCP 提案 clone：禁止任何 push。这是设计约束，不是可配置项。\n"
        "exit 1\n"
    ), "实现的 hook 内容被改动了，测试跑的不是实现"

    # 第一层：config 里没有 remote
    config_text = (clone / ".git" / "config").read_text(encoding="utf-8")
    assert "[remote " not in config_text, "隔离 clone 不该有 remote"
    assert "default = nothing" in config_text
    assert "helper =" in config_text
    # core.hooksPath 必须指向 clone 自己的 hooks 目录——否则用户全局的
    # hooksPath 会让实现装的 hook 失效（P2-3 的核心保护）
    expected_hooks = str((clone / ".git" / "hooks").resolve())
    assert f"hooksPath = {expected_hooks}" in config_text, (
        f"core.hooksPath 未指向 clone 的 hooks 目录：{config_text}"
    )

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

    # 超时判**失败**：真挂起时必须报错，不能因为「没返回」而被当成「被 hook 拦截」。
    # 用 _run_git_push_isolated 而不是 subprocess.run——后者超时只杀直接子进程，
    # `git-receive-pack` 与 hook 这两个孙进程会变成孤儿继续等待（PR #30 遗漏的那半）。
    try:
        rc, _out, err = _run_git_push_isolated(clone, ["push", "evil", current])
    except subprocess.TimeoutExpired:
        pytest.fail(
            "git push 30 秒未返回——hook 或管道死锁，不能判定为「被 hook 拦截」"
        )
    assert rc != 0, f"pre-push hook 没拦住 push：{err[:300]}"

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
    real_hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    real_hook.chmod(0o755)
    marker.unlink()
    try:
        ok_rc, _ok_out, ok_err = _run_git_push_isolated(
            clone, ["push", "evil", current]
        )
    except subprocess.TimeoutExpired:
        pytest.fail("反向对照的 git push 30 秒未返回——同样视为死锁，判失败")
    assert ok_rc == 0, (
        f"hook 放行后 push 应当成功，否则说明失败另有原因：{ok_err[:300]}"
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

    # 调用**实现里的** fetch_from_local_clone，不是裸 git fetch——
    # 否则测的是 git 的行为，改实现（加 --force）测试照样绿。
    with pytest.raises(subprocess.CalledProcessError) as excinfo:
        fetch_from_local_clone(user_repo, clone, branch)
    err = (str(excinfo.value.stderr or "") + str(excinfo.value.output or "")).lower()
    # 只认 non-fast-forward：去掉宽泛的 "rejected"（任何拒绝原因都含它，
    # 会把「找不到 ref」这类无关失败也算通过）
    assert "non-fast-forward" in err or "非快进" in err, (
        f"fetch 失败但不是因为非快进：{err[:300]}"
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
    # 同样走实现函数：快进应当成功（不带 --force 的 fetch 本来就允许快进）
    fetch_from_local_clone(user_repo, ff_clone, branch)
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
# 提交身份：不依赖运行环境的 gitconfig
# ---------------------------------------------------------------------------


def test_commit_works_without_any_user_gitconfig(tmp_path: Path) -> None:
    """
    CI 环境没有 user.email/name 时，提案提交仍必须成功。

    这是 #22 三个 Python 版本全部失败的根因：``_git`` 设了
    ``GIT_CONFIG_GLOBAL=/dev/null`` + ``GIT_CONFIG_NOSYSTEM=1``（为防用户全局
    hooksPath 干扰），副作用是读不到身份；本地靠 git 的「用户名+主机名」推断
    侥幸通过，CI 容器里连推断都不成立，``git commit`` 直接 exit 128。

    修法是提交时显式 ``-c user.name/-c user.email``。这条测试把「没有任何
    身份配置」这件事造出来——注意**测试夹具本身也不能配身份**，否则又会盖住。
    """
    repo = tmp_path / "bare-repo"
    repo.mkdir()
    # 用完全空的环境建仓：HOME 指向空目录，无全局/系统配置
    empty_home = tmp_path / "empty-home"
    empty_home.mkdir()
    clean = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(empty_home),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }

    def _bare_git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *args], cwd=str(repo), capture_output=True, text=True,
            env=clean, check=check,
        )

    _bare_git("init", "-q")
    (repo / "specs").mkdir()
    (repo / "specs" / "demo.yaml").write_text("name: demo\n", encoding="utf-8")
    _bare_git("add", "-A")
    # 先确认这个环境确实没有身份——否则测试是空的
    probe = _bare_git("config", "--get", "user.email", check=False)
    assert probe.returncode != 0, "测试环境意外存在 user.email，无法验证无身份场景"
    # 用 -c 造初始 commit（模拟工具身份），避免初始提交就失败
    _bare_git("-c", "user.name=seed", "-c", "user.email=seed@x.invalid",
              "commit", "-q", "-m", "init")
    _bare_git("update-ref", "refs/heads/master", "HEAD")

    # 真正的断言：在**没有任何身份**的环境里跑提案。
    # 必须同时清空进程环境里的 HOME —— make_proposal 内部调 _git 时
    # 用的是 os.environ，虽然它会设 GIT_CONFIG_GLOBAL=/dev/null，
    # 但如果 HOME 还指向真实用户目录，git 仍可能从别处读到身份。
    # 早先版本没清 HOME，导致「去掉 -c user.*」时这条测试照样通过（假测试）。
    branch = make_branch_name("demo")
    saved = {k: os.environ.get(k) for k in ("HOME", "GIT_CONFIG_GLOBAL",
                                            "GIT_CONFIG_NOSYSTEM")}
    os.environ["HOME"] = str(empty_home)
    os.environ["GIT_CONFIG_GLOBAL"] = os.devnull
    os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
    try:
        result = make_proposal(
            repo, branch, "proposal: no identity in env",
            lambda d: (d / "specs" / "demo.yaml").write_text(
                "name: demo\nfields:\n  - name: x\n", encoding="utf-8"
            ),
        )
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    assert result["commit"]
    assert branch_exists(repo, branch)


#: 上面这条测试的**已知局限**，必须写在这里而不是让它显得比实际更强：
#:
#: 本机（macOS）上 git 在完全拿不到 user.name/user.email 时会用「系统用户名 +
#: 主机名」自动推断并成功提交，因此**即使在修复前的实现上，这条测试也可能通过**。
#: 实测：把 `-c user.*` 去掉后它仍然绿。所以它守不住「CI 无身份」这个场景。
#:
#: 真正能守住的是 `test_commit_author_is_tool_identity` —— 它断言 author 必须是
#: 工具身份，去掉 `-c user.*` 立刻红。CI 上的 128 失败之所以会发生，是因为
#: 容器里连推断都不成立；那个环境本地无法完全模拟。
#:
#: 保留本条的理由：它至少验证「不依赖仓库级 user.* 配置也能提交」，
#: 且当 git 行为的推断规则改变时会给出信号。**不要把它当作 CI 场景的保护。**


def test_commit_author_survives_hostile_env_vars(user_repo: Path, monkeypatch) -> None:
    """
    运行环境设了 ``GIT_AUTHOR_*`` / ``GIT_COMMITTER_*`` 时，author 仍必须是工具身份。

    这些环境变量的**优先级高于** `git -c user.name=...`——只靠 `-c` 不足以守住。
    本用例设置一套与之冲突的值，断言工具显式覆盖它们。

    （这条是**行为断言**：如果只检查「代码里有 env 覆盖逻辑」，即使覆盖写错了
    变量名也会通过——今晚 `prefix` 没传给 subprocess 的 bug 就是这么漏掉的。）
    """
    from tools.mcp_server.git_isolation import _COMMIT_IDENTITY

    expected_name = _COMMIT_IDENTITY[0].split("=", 1)[1]
    expected_email = _COMMIT_IDENTITY[1].split("=", 1)[1]

    # 与工具身份冲突的环境变量（模拟「用户的 shell / CI 设了这些」）
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Hostile Human")
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "human@example.com")
    monkeypatch.setenv("GIT_COMMITTER_NAME", "Hostile Committer")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "committer@example.com")

    branch = make_branch_name("envprobe")
    make_proposal(
        user_repo, branch, "proposal: env override",
        lambda d: (d / "specs" / "envprobe.yaml").write_text(
            "name: envprobe\nfields:\n  - name: a\n", encoding="utf-8"
        ),
    )
    actual = _run(user_repo, "log", "-1", "--format=%an|%ae|%cn|%ce", branch).strip()
    assert actual == f"{expected_name}|{expected_email}|{expected_name}|{expected_email}", (
        f"环境变量改写了 author/committer；期望全部为工具身份，实际 {actual}"
    )


def test_commit_author_is_tool_identity(user_repo: Path) -> None:
    """提案 commit 的 author 必须是工具身份，不是运行它的机器身份。"""
    from tools.mcp_server.git_isolation import _COMMIT_IDENTITY

    expected_name = _COMMIT_IDENTITY[0].split("=", 1)[1]
    expected_email = _COMMIT_IDENTITY[1].split("=", 1)[1]

    branch = make_branch_name("demo")
    make_proposal(
        user_repo, branch, "proposal: authorship",
        lambda d: (d / "specs" / "demo.yaml").write_text(
            "name: demo\nfields:\n  - name: a\n", encoding="utf-8"
        ),
    )
    # %an = author name, %ae = author email
    actual = _run(user_repo, "log", "-1", "--format=%an|%ae", branch).strip()
    assert actual == f"{expected_name}|{expected_email}", (
        f"author 应为工具身份 {expected_name}，实际 {actual}"
    )


# ---------------------------------------------------------------------------
# 环境净化与参数逃逸
# ---------------------------------------------------------------------------


def test_malicious_global_hookspath_is_ignored(user_repo: Path, tmp_path: Path) -> None:
    """
    用户全局配置里若有恶意的 ``core.hooksPath``，实现的 git 调用不得受其影响。

    做法：造一个假的全局 gitconfig，把 hooksPath 指到一个「所有 hook 都 exit 0」
    的目录，用 GIT_CONFIG_GLOBAL 指过去——模拟用户本机的恶意/特殊配置。
    然后跑一次提案 + 一次 fetch，两者都必须正常工作，且**不能**执行那个假目录
    里的 hook（用标记文件验证）。
    """
    evil_hooks = tmp_path / "evil-hooks"
    evil_hooks.mkdir()
    evil_marker = tmp_path / "evil-ran.marker"
    for name in ("pre-push", "post-checkout", "reference-transaction"):
        h = evil_hooks / name
        h.write_text(f'#!/bin/sh\necho x >> "{evil_marker}"\nexit 0\n', encoding="utf-8")
        h.chmod(0o755)

    fake_global = tmp_path / "fake-global-config"
    fake_global.write_text(
        f"[core]\n\thooksPath = {evil_hooks}\n", encoding="utf-8"
    )

    # 用实现函数跑一次完整提案：实现的 _git 会强制 GIT_CONFIG_GLOBAL=/dev/null，
    # 因此这份假配置不该生效
    branch = make_branch_name("demo")
    env_backup = os.environ.get("GIT_CONFIG_GLOBAL")
    os.environ["GIT_CONFIG_GLOBAL"] = str(fake_global)
    try:
        result = make_proposal(
            user_repo, branch, "proposal: under evil config",
            lambda d: (d / "specs" / "demo.yaml").write_text(
                "name: demo\nfields:\n  - name: evil\n", encoding="utf-8"
            ),
        )
    finally:
        if env_backup is None:
            os.environ.pop("GIT_CONFIG_GLOBAL", None)
        else:
            os.environ["GIT_CONFIG_GLOBAL"] = env_backup

    assert result["branch"] == branch
    assert not evil_marker.exists(), (
        "恶意全局 hooksPath 里的 hook 被执行了——环境净化没生效"
    )


@pytest.mark.parametrize("escape", [
    ["clone", "--upload-pack=touch /tmp/pwned", "x", "y"],
    ["clone", "--exec=x", "a", "b"],
    ["-c", "core.pager=evil", "log"],
    ["--git-dir=/tmp/x", "status"],
    ["log", "--upload-pack=x"],
    ["commit", "--exec=x"],
    ["diff", "--output=/tmp/x"],
    ["add", "-u", "x"],
    ["checkout", "--template-dir=/tmp/x", "master"],
])
def test_param_escape_rejected(user_repo: Path, escape: list) -> None:
    """危险参数放在子命令前后都必须被拒。"""
    with pytest.raises(GitNotAllowed):
        _git(escape, cwd=user_repo)


def test_git_c_only_allows_identity_keys(user_repo: Path) -> None:
    """
    ``git -c key=value <sub>`` 只放行提交身份两个键，其余一律拒绝。

    ``-c`` 是受控的例外：提案提交需要 `-c user.name=... -c user.email=...`
    给工具署名（见 `_COMMIT_IDENTITY`），因为 `_git` 清空了全局/系统配置。
    但 ``-c core.hooksPath=...``、``-c alias.x=...`` 这类能绕过安全检查的键
    必须继续拒绝——否则「参数级白名单」就被 ``-c`` 打开了后门。
    """
    # 允许的：user.name / user.email
    out = _git(["-c", "user.name=probe", "-c", "user.email=p@x.invalid",
                "rev-parse", "HEAD"], cwd=user_repo)
    assert len(out.strip()) == 40

    # 拒绝的：其余任何键
    for kv in (
        "core.hooksPath=/tmp/evil",
        "alias.status=!rm -rf /",
        "filter.x.clean=evil",
        "credential.helper=evil",
        "core.pager=evil",
        "url.x.insteadOf=https://evil/",
    ):
        with pytest.raises(GitNotAllowed) as excinfo:
            _git(["-c", kv, "status"], cwd=user_repo)
        assert "只允许" in str(excinfo.value), f"{kv} 的拒绝理由不对：{excinfo.value}"


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
