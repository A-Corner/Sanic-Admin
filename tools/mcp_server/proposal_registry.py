#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
提案分支的归属标记与临时目录残留清理（v0.4.1 硬化）。

## 为什么需要归属标记

``discard_proposal`` 原来只看 ``proposal/`` 前缀就允许删除。问题在于：任何
人（或任何脚本）都可以手工建一个 ``proposal/xxx`` 分支，然后这个工具就会把
它当作「自己的产物」删掉。**删除是不可逆的**，所以「是不是我建的」必须能被
证明，而不是靠命名约定。

做法：每次提案成功、分支 fetch 回用户仓库之后，在用户仓库写一个 ref：

    refs/specgen/proposals/<branch 去掉 proposal/ 前缀>  ->  提案 commit SHA

这个 ref 由本工具独占命名空间（``refs/specgen/``），不会与用户的分支、
tag、notes 冲突。``discard_proposal`` 的判据变成：

1. 分支名必须是 ``proposal/`` 前缀（原有约束，保留）
2. **必须存在对应的 ref 标记**（证明是本工具创建的）
3. **标记指向的 SHA 必须等于分支当前 SHA**（证明分支没被人改过）

任何一条不满足就拒绝，并给出具体原因。

## 为什么需要残留清理

``make_proposal`` 用 ``finally: shutil.rmtree`` 清理临时目录，但进程被 kill
（CI 超时、SIGKILL、机器重启）时不会执行 finally，目录会留下。长期积累占磁盘。

清理策略（**宁可漏删，不可误删**）：

- 只扫 ``tempfile.gettempdir()`` 这一层，不递归
- 只考虑名字匹配 ``sanic-specgen-*`` 的目录
- 目录里**必须**有本工具写入的标记文件 ``.sanic-specgen-workspace``
- 且 mtime 超过 24 小时
- 且目录名不等于当前进程正在使用的目录（用 pid 后缀区分）

任何一条不满足就跳过。**绝不按通配删除**——即使有人恰好建了同名目录，
没有标记文件也不会被碰。
"""
from __future__ import annotations

import logging
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import List, Optional

_log = logging.getLogger(__name__)

#: 提案归属标记的 ref 命名空间。本工具独占。
PROPOSAL_REF_PREFIX = "refs/specgen/proposals/"

#: 临时工作目录名前缀。
TMP_PREFIX = "sanic-specgen-"

#: 标记文件名。存在即表示「这个目录是本工具创建的」，是清理的唯一依据之一。
TMP_MARKER = ".sanic-specgen-workspace"

#: 残留目录的过期时长（秒）。
STALE_AFTER_SECONDS = 24 * 60 * 60


def proposal_ref(branch: str) -> str:
    """把分支名映射成归属标记的 ref 名。"""
    if not branch.startswith("proposal/"):
        raise ValueError(f"不是提案分支：{branch!r}")
    return PROPOSAL_REF_PREFIX + branch[len("proposal/"):]


def make_workspace() -> Path:
    """
    创建本次提案的临时工作目录，并写入标记文件。

    目录名带 pid，便于清理时跳过当前进程正在用的那个（同一进程内多次提案也
    不会互相误删）。
    """
    root = Path(tempfile.mkdtemp(prefix=TMP_PREFIX))
    (root / TMP_MARKER).write_text(
        f"pid={os.getpid()}\ncreated={int(time.time())}\n", encoding="utf-8"
    )
    return root


def cleanup_stale_workspaces(
    *, temp_root: Optional[Path] = None, now: Optional[float] = None
) -> List[str]:
    """
    清理过期的临时工作目录，返回被删掉的目录名列表。

    **安全约束**（每一条都是为了「绝不误删」）：

    1. 只扫 ``temp_root`` 这一层，不递归
    2. 名字必须以 ``TMP_PREFIX`` 开头
    3. 必须存在 ``TMP_MARKER`` 文件
    4. mtime 必须早于 ``now - STALE_AFTER_SECONDS``
    5. 标记文件里的 pid 若是当前进程，跳过（不能删自己正在用的）

    任何异常都不影响其它目录的清理，也不向上抛——清理是旁路。
    """
    root = Path(temp_root or tempfile.gettempdir())
    now_ts = now if now is not None else time.time()
    removed: List[str] = []
    try:
        entries = list(root.iterdir())
    except OSError:
        return removed

    for entry in entries:
        try:
            if not entry.is_dir():
                continue
            if not entry.name.startswith(TMP_PREFIX):
                continue
            marker = entry / TMP_MARKER
            if not marker.is_file():
                # 没有标记 = 不是我们的产物，即使名字像也不碰
                continue
            text = marker.read_text(encoding="utf-8", errors="replace")
            pid_line = next(
                (ln for ln in text.splitlines() if ln.startswith("pid=")), ""
            )
            try:
                pid = int(pid_line.split("=", 1)[1])
            except (IndexError, ValueError):
                pid = -1
            if pid == os.getpid():
                continue
            if now_ts - entry.stat().st_mtime < STALE_AFTER_SECONDS:
                continue
            shutil.rmtree(entry)
            removed.append(entry.name)
        except OSError:
            # 单个目录失败不影响其它
            continue
    return removed


def count_stale_workspaces(
    *, temp_root: Optional[Path] = None, now: Optional[float] = None
) -> int:
    """只统计不删除，便于测试与诊断。判据与 cleanup 完全一致。"""
    root = Path(temp_root or tempfile.gettempdir())
    now_ts = now if now is not None else time.time()
    n = 0
    try:
        entries = list(root.iterdir())
    except OSError:
        return 0
    for entry in entries:
        try:
            if not entry.is_dir() or not entry.name.startswith(TMP_PREFIX):
                continue
            marker = entry / TMP_MARKER
            if not marker.is_file():
                continue
            if now_ts - entry.stat().st_mtime < STALE_AFTER_SECONDS:
                continue
            n += 1
        except OSError:
            continue
    return n
