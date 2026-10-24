#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
v0.4.1 写入路径硬化测试：归属标记与残留清理。

对应 CPL 的两项要求：
1. discard 不再只看前缀——必须有归属标记且 SHA 一致
2. 残留清理只删「有标记 + 过期 + 非本进程」的目录

每条都做过破坏实验（见各测试的 docstring）。
"""
from __future__ import annotations

import os
import subprocess
import shutil
import tempfile
import time
from pathlib import Path

import pytest

from tools.mcp_server.git_isolation import (
    GitNotAllowed,
    _git,
    branch_exists,
    discard_proposal,
    make_branch_name,
    make_proposal,
)
from tools.mcp_server.proposal_registry import (
    PROPOSAL_REF_PREFIX,
    STALE_AFTER_SECONDS,
    TMP_MARKER,
    TMP_PREFIX,
    cleanup_stale_workspaces,
    count_stale_workspaces,
    make_workspace,
    proposal_ref,
)

_SPEC = "resource: demo\ntable: demo\nlabel: d\nfields:\n  - name: a\n    type: string\n"


def _run(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, check=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    ).stdout


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _run(r, "init", "-q")
    (r / "specs").mkdir()
    (r / "specs" / "demo.yaml").write_text("name: demo\n", encoding="utf-8")
    _run(r, "add", "-A")
    _run(r, "-c", "user.name=t", "-c", "user.email=t@x.invalid",
         "commit", "-q", "-m", "init")
    _run(r, "update-ref", "refs/heads/master", "HEAD")
    return r


def _propose(repo: Path, resource: str = "demo") -> dict:
    branch = make_branch_name(resource)
    return make_proposal(
        repo, branch, f"proposal: {resource}",
        lambda d: (d / "specs" / "demo.yaml").write_text(_SPEC, encoding="utf-8"),
    )


# ---------------------------------------------------------------------------
# 一、discard 的归属校验
# ---------------------------------------------------------------------------


def test_propose_writes_ownership_ref(repo: Path) -> None:
    """提案成功后必须写归属标记 ref，指向提案 commit。"""
    result = _propose(repo)
    ref = proposal_ref(result["branch"])
    marked = _run(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").strip()
    assert marked == result["commit"], f"标记 {marked[:7]} != commit {result['commit'][:7]}"
    assert ref.startswith(PROPOSAL_REF_PREFIX)


def test_tool_created_branch_can_be_discarded(repo: Path) -> None:
    """工具建的提案分支可以正常删除。"""
    result = _propose(repo)
    branch = result["branch"]
    assert branch_exists(repo, branch)

    discard_proposal(repo, branch, force=True)
    assert not branch_exists(repo, branch)
    # 标记也要一并清掉，否则下次同名分支会撞上陈旧标记
    proc = subprocess.run(
        ["git", "rev-parse", "--verify", proposal_ref(branch)],
        cwd=str(repo), capture_output=True, text=True,
    )
    assert proc.returncode != 0, "分支删了但归属标记还在"


def test_handmade_proposal_branch_cannot_be_discarded(repo: Path) -> None:
    """
    手工建的 ``proposal/`` 前缀分支删不掉——即使名字符合约定。

    破坏实验：把 discard 的归属校验去掉（只留前缀判断），这条会红。
    """
    branch = "proposal/handmade-20261024-120000"
    _run(repo, "branch", branch, "master")
    assert branch_exists(repo, branch)

    with pytest.raises(GitNotAllowed) as excinfo:
        discard_proposal(repo, branch, force=True)
    msg = str(excinfo.value)
    assert "归属标记" in msg or "没有归属标记" in msg, f"拒绝理由不对：{msg}"
    assert branch_exists(repo, branch), "手工分支被删掉了"


def test_modified_proposal_branch_cannot_be_discarded(repo: Path) -> None:
    """
    工具建的分支被人改动过（SHA 与标记不一致）后，拒绝删除并提示。

    破坏实验：去掉 SHA 比对，这条会红。
    """
    result = _propose(repo)
    branch = result["branch"]

    # 在分支上再提交一次，改变 SHA（模拟「人接管了这个分支」）
    _run(repo, "checkout", "-q", branch)
    (repo / "extra.txt").write_text("human edit", encoding="utf-8")
    _run(repo, "add", "-A")
    _run(repo, "-c", "user.name=h", "-c", "user.email=h@x.invalid",
         "commit", "-q", "-m", "human change")
    new_sha = _run(repo, "rev-parse", branch).strip()
    assert new_sha != result["commit"]

    with pytest.raises(GitNotAllowed) as excinfo:
        discard_proposal(repo, branch, force=True)
    msg = str(excinfo.value)
    assert "已被改动" in msg, f"拒绝理由不对：{msg}"
    assert branch_exists(repo, branch), "被改动的分支不该被删"


def test_discard_refuses_non_proposal_prefix(repo: Path) -> None:
    """非 proposal/ 前缀一律拒绝（原有约束，回归保护）。"""
    _run(repo, "branch", "feature-keep", "master")
    with pytest.raises(GitNotAllowed):
        discard_proposal(repo, "feature-keep", force=True)
    assert branch_exists(repo, "feature-keep")


# ---------------------------------------------------------------------------
# 一之二、用户仓库的 hook 不得被触发（M1）
# ---------------------------------------------------------------------------


def test_user_repo_hooks_not_triggered(repo: Path, tmp_path: Path) -> None:
    """
    写归属标记、删分支这些**改 ref** 的操作不能触发用户仓库自己的 hook。

    M1 的实测证据：修复前跑一次提案，用户的 reference-transaction hook 被触发
    **2 次**（一次来自 fetch、一次来自 update-ref）。修复后应当 0 次
    （fetch 那侧本来就带 hooksPath=/dev/null，update-ref 这侧是本次修的）。

    破坏实验：把 `_git_on_user_repo` 换回 `_git` → 标记文件出现，测试红。
    """
    marker_log = tmp_path / "ref-tx.log"
    hook = repo / ".git" / "hooks" / "reference-transaction"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(f"#!/bin/sh\necho ran >> '{marker_log}'\nexit 0\n", encoding="utf-8")
    hook.chmod(0o755)

    result = _propose(repo)
    assert not marker_log.exists(), (
        f"用户仓库的 reference-transaction hook 被触发了 "
        f"{len(marker_log.read_text().splitlines())} 次：{marker_log.read_text()}"
    )

    # discard 也要走净化路径
    discard_proposal(repo, result["branch"], force=True)
    assert not marker_log.exists(), "discard 触发了用户仓库的 hook"


def test_discard_uses_full_ref_name(repo: Path) -> None:
    """
    discard 全程用 refs/heads/<b> 全名，不会误删同名 tag。

    构造一个与分支同名的 tag，discard 之后 tag 必须还在。
    """
    result = _propose(repo)
    branch = result["branch"]
    _run(repo, "tag", branch, branch)

    discard_proposal(repo, branch, force=True)
    assert not branch_exists(repo, branch)
    tags = _run(repo, "tag", "--list", branch).strip()
    assert tags == branch, f"同名 tag 被误删了：{tags!r}"


def test_discard_rejects_malformed_branch_name(repo: Path) -> None:
    """
    L2：形态不合法的分支名在拼 refs/heads/ 之前就被拒绝。

    **断言必须检查拒绝理由**：只断言「抛了 GitNotAllowed」不够——去掉
    `_BRANCH_RE` 校验后，`branch_exists` 会因为「分支不存在」抛同一个异常类型，
    测试照样绿（实测踩到）。这里要求理由里出现「不合法」。
    """
    for bad in ("proposal/../evil", "proposal/..", "proposal/x y", "proposal/x.lock"):
        with pytest.raises(GitNotAllowed) as excinfo:
            discard_proposal(repo, bad, force=True)
        assert "不合法" in str(excinfo.value), (
            f"{bad!r} 的拒绝理由不是形态校验：{excinfo.value}"
        )


# ---------------------------------------------------------------------------
# 二、残留清理
# ---------------------------------------------------------------------------


def test_marker_missing_but_otherwise_eligible_is_kept(tmp_path: Path) -> None:
    """
    L3 独立测试：目录名前缀对、mtime 过期，但**没有标记文件**时必须保留。

    这条专门守 `if not marker.is_file()` 那道防线。破坏实验要注意：
    删掉整段检查**不会**让这条测试红——后面的 read_text 会对不存在的文件
    抛 OSError 并导致提前返回，恰好等价于跳过。有效的破坏方式是让无标记
    走到「当作有标记」的路径（例如给 read_text 一个默认值）。
    """
    root = tmp_path / "r"
    root.mkdir()
    d = root / f"{TMP_PREFIX}no-marker"
    d.mkdir()
    old = time.time() - STALE_AFTER_SECONDS - 3600
    os.utime(d, (old, old))

    assert count_stale_workspaces(temp_root=root) == 0, "无标记目录不该被统计"
    assert cleanup_stale_workspaces(temp_root=root) == []
    assert d.exists(), "无标记目录被删了——会误删别人的目录"


def test_symlink_entries_are_rejected(tmp_path: Path) -> None:
    """
    L3：符号链接一律跳过。

    `Path.is_dir()` 对指向目录的符号链接返回 True；若跟着 rmtree，
    行为会受链接目标影响。这里构造一个「看起来合格」的符号链接目录，
    断言它既不被统计也不被删除。
    """
    root = tmp_path / "r"
    root.mkdir()
    target = tmp_path / "real-dir"
    target.mkdir()
    (target / TMP_MARKER).write_text("pid=999999\n", encoding="utf-8")
    old = time.time() - STALE_AFTER_SECONDS - 3600
    os.utime(target, (old, old))

    link = root / f"{TMP_PREFIX}link"
    link.symlink_to(target)

    assert count_stale_workspaces(temp_root=root) == 0
    assert cleanup_stale_workspaces(temp_root=root) == []
    assert link.exists() and link.is_symlink(), "符号链接被动了"
    assert target.exists(), "符号链接的目标目录被删了"


def test_symlinked_marker_is_rejected(tmp_path: Path) -> None:
    """标记文件本身是符号链接时也跳过——避免被诱导删除非本工具目录。"""
    root = tmp_path / "r"
    root.mkdir()
    d = root / f"{TMP_PREFIX}marker-link"
    d.mkdir()
    real = tmp_path / "real-marker"
    real.write_text("pid=999999\n", encoding="utf-8")
    (d / TMP_MARKER).symlink_to(real)
    old = time.time() - STALE_AFTER_SECONDS - 3600
    os.utime(d, (old, old))

    assert cleanup_stale_workspaces(temp_root=root) == []
    assert d.exists()


def test_live_process_workspace_is_kept(tmp_path: Path) -> None:
    """
    L4：标记里的 pid 对应的进程仍存活时，即使目录过期也不删。

    pid 复用是已知局限：极端情况下过期目录的 pid 被新进程占用，会被当作
    「活的」而漏删——这是安全方向的失败。反过来（为了删干净而忽略存活检查）
    可能删掉正在使用的工作区，不可接受。
    """
    root = tmp_path / "r"
    root.mkdir()
    # 用当前进程的父进程 pid（一定存活且不是当前进程）
    live_pid = os.getppid()
    d = _make_fake_workspace(
        root, f"{TMP_PREFIX}live", age_seconds=STALE_AFTER_SECONDS + 3600, pid=live_pid
    )

    assert count_stale_workspaces(temp_root=root) == 0, "存活进程的工作区被统计了"
    assert cleanup_stale_workspaces(temp_root=root) == []
    assert d.exists(), "存活进程的工作区被删了"


def test_dead_process_workspace_is_removed(tmp_path: Path) -> None:
    """进程已不存在时正常清理（正向对照：上面的保护不是「一律不删」）。"""
    root = tmp_path / "r"
    root.mkdir()
    # 一个几乎不可能存在的 pid
    d = _make_fake_workspace(
        root, f"{TMP_PREFIX}dead", age_seconds=STALE_AFTER_SECONDS + 3600, pid=2 ** 22
    )

    removed = cleanup_stale_workspaces(temp_root=root)
    assert removed == [d.name]
    assert not d.exists()



# ---------------------------------------------------------------------------


def _make_fake_workspace(root: Path, name: str, *, age_seconds: float,
                         pid: int = 999999, with_marker: bool = True) -> Path:
    """造一个假的临时工作目录，可控年龄与标记。"""
    d = root / name
    d.mkdir()
    if with_marker:
        (d / TMP_MARKER).write_text(f"pid={pid}\ncreated=0\n", encoding="utf-8")
    old = time.time() - age_seconds
    os.utime(d, (old, old))
    return d


def test_cleanup_removes_only_stale_marked_dirs(tmp_path: Path) -> None:
    """
    只删「前缀匹配 + 有标记 + 过期 + 非本进程」的目录。

    同目录下其它东西（无标记的同名目录、名字不匹配的目录、未过期的）都必须保留。

    **破坏实验的一个陷阱**（实测踩到）：第一次我把
    ``if not marker.is_file(): continue`` 整段删掉，测试**仍然绿**——因为后面
    ``marker.read_text()`` 对不存在的文件抛 OSError，被外层的
    ``except OSError: continue`` 吞掉，恰好等价于「跳过」。
    换句话说，那种破坏方式并没有真的改变行为。

    有效的破坏方式是让「无标记」走到「当作有标记」的路径：把 read_text 换成
    不抛异常的默认值，测试立刻红。**这提醒：破坏实验本身也要验证它真的改变了行为。**
    """
    root = tmp_path / "temp-root"
    root.mkdir()

    stale = _make_fake_workspace(root, f"{TMP_PREFIX}old", age_seconds=STALE_AFTER_SECONDS + 3600)
    fresh = _make_fake_workspace(root, f"{TMP_PREFIX}new", age_seconds=60)
    no_marker = _make_fake_workspace(
        root, f"{TMP_PREFIX}no-marker", age_seconds=STALE_AFTER_SECONDS + 3600,
        with_marker=False,
    )
    wrong_prefix = _make_fake_workspace(root, "unrelated-dir", age_seconds=STALE_AFTER_SECONDS + 3600)
    same_pid = _make_fake_workspace(
        root, f"{TMP_PREFIX}samepid", age_seconds=STALE_AFTER_SECONDS + 3600, pid=os.getpid()
    )
    a_file = root / f"{TMP_PREFIX}file-not-dir"
    a_file.write_text("x", encoding="utf-8")
    os.utime(a_file, (time.time() - STALE_AFTER_SECONDS - 3600,) * 2)

    removed = cleanup_stale_workspaces(temp_root=root)

    assert removed == [stale.name], f"只应删 {stale.name}，实际删了 {removed}"
    assert not stale.exists()
    assert fresh.exists(), "未过期的被删了"
    assert no_marker.exists(), "无标记的被删了——这会误删别人的目录"
    assert wrong_prefix.exists(), "名字不匹配的被删了"
    assert same_pid.exists(), "当前进程自己的目录被删了"
    assert a_file.exists(), "文件被当成目录删了"


def test_cleanup_is_noop_on_empty_or_missing_root(tmp_path: Path) -> None:
    """空目录、不存在的目录都不该报错。"""
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cleanup_stale_workspaces(temp_root=empty) == []
    assert cleanup_stale_workspaces(temp_root=tmp_path / "nope") == []


def test_count_matches_cleanup_criteria(tmp_path: Path) -> None:
    """count 与 cleanup 的判据必须一致，否则诊断数字会误导。"""
    root = tmp_path / "r"
    root.mkdir()
    _make_fake_workspace(root, f"{TMP_PREFIX}a", age_seconds=STALE_AFTER_SECONDS + 10)
    _make_fake_workspace(root, f"{TMP_PREFIX}b", age_seconds=STALE_AFTER_SECONDS + 10)
    _make_fake_workspace(root, f"{TMP_PREFIX}c", age_seconds=10)
    _make_fake_workspace(root, f"{TMP_PREFIX}d", age_seconds=STALE_AFTER_SECONDS + 10,
                         with_marker=False)

    before = count_stale_workspaces(temp_root=root)
    assert before == 2
    removed = cleanup_stale_workspaces(temp_root=root)
    assert len(removed) == before
    assert count_stale_workspaces(temp_root=root) == 0


def test_make_workspace_is_marked_and_cleanable(tmp_path: Path, monkeypatch) -> None:
    """
    make_workspace 产出的目录必须带标记，且**不会**被清理逻辑当作残留删掉。

    M2 修正两处：
    - 原来写 ``assert ... or True``，那条断言恒真，等于没测；
    - ``monkeypatch.setenv("TMPDIR")`` 对已缓存的 ``tempfile.gettempdir()`` 不生效，
      必须直接 patch ``tempfile.tempdir``。
    """
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    ws = make_workspace()
    try:
        assert ws.name.startswith(TMP_PREFIX)
        assert ws.parent == tmp_path, f"工作区没落在临时根目录：{ws.parent}"
        assert (ws / TMP_MARKER).is_file()
        text = (ws / TMP_MARKER).read_text(encoding="utf-8")
        assert f"pid={os.getpid()}" in text
        # 当前进程自己的工作区**必须**被跳过——这是真实断言，不是 or True
        assert count_stale_workspaces(temp_root=tmp_path) == 0, \
            "当前进程的工作区被当成残留了"
        assert cleanup_stale_workspaces(temp_root=tmp_path) == []
        assert ws.exists(), "当前进程的工作区被删了"
    finally:
        shutil.rmtree(ws, ignore_errors=True)


def test_proposal_success_leaves_no_workspace(repo: Path, tmp_path: Path, monkeypatch) -> None:
    """
    成功的提案走 finally 清理，不留临时目录。

    M2：去掉 ``importlib.reload(gi)`` —— 它会重新执行模块、重建 ``GitNotAllowed``
    等异常类，导致其它测试里 ``pytest.raises(GitNotAllowed)`` 抓不到新实例。
    改用直接 patch ``tempfile.tempdir``，``mkdtemp`` 会读它。
    """
    fake_tmp = tmp_path / "tmp"
    fake_tmp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(fake_tmp))

    branch = make_branch_name("demo")
    make_proposal(
        repo, branch, "proposal: cleanup check",
        lambda d: (d / "specs" / "demo.yaml").write_text(_SPEC, encoding="utf-8"),
    )
    leftovers = [p for p in fake_tmp.iterdir() if p.name.startswith(TMP_PREFIX)]
    assert leftovers == [], f"提案成功后残留了临时目录：{leftovers}"
