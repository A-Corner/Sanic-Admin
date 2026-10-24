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
- 且标记文件记录的 pid 既不是当前进程、也不是仍存活的进程
  （目录名**不含** pid，pid 只写在标记文件里；`make_workspace` 用
  `tempfile.mkdtemp` 生成随机后缀，不自己拼 pid）

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

    **目录名不含 pid**：用 ``tempfile.mkdtemp(prefix=TMP_PREFIX)`` 生成随机后缀，
    这样同一进程内连续多次提案不会撞名。识别「是不是当前进程的」靠**标记文件
    内容里的 pid**，不靠目录名。

    （早先的 docstring 写「目录名带 pid」，与实现不符，已更正。）
    """
    root = Path(tempfile.mkdtemp(prefix=TMP_PREFIX))
    (root / TMP_MARKER).write_text(
        f"pid={os.getpid()}\ncreated={int(time.time())}\n", encoding="utf-8"
    )
    return root


def _is_live_process(pid: int) -> bool:
    """
    pid 对应的进程是否还活着。

    ``os.kill(pid, 0)`` 不发信号，只做存在性检查：进程存在返回 None（不抛），
    不存在抛 ProcessLookupError，无权限抛 PermissionError（进程存在但不属于我们）。

    **已知局限**：pid 会被系统复用。极端情况下一个过期目录记录的 pid 恰好被
    新进程占用，我们就会把它当作「活的」而跳过——这是**安全方向的失败**
    （漏删，不误删），可以接受。反过来若为了「删干净」忽略这个检查，风险是
    删掉正在使用的工作区，不可接受。
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # 进程存在，只是不属于当前用户
        return True
    except OSError:
        return False
    return True


def _is_ours_and_stale(entry: Path, now_ts: float) -> bool:
    """
    判断一个目录条目是否「属于本工具 + 已过期 + 非本进程」。

    判据顺序有意为之：先做便宜的排除（不是目录 / 名字不匹配 / 是符号链接），
    再读标记文件，最后看 mtime 和 pid。任何一步不满足都返回 False。

    **符号链接单独检查**：``entry.is_dir()`` 对指向目录的符号链接也返回 True，
    如果跟着删，``shutil.rmtree`` 的行为会受目标影响——可能删到链接目标里。
    直接拒绝，不与符号链接打交道。
    """
    if entry.is_symlink():
        return False
    if not entry.is_dir():
        return False
    if not entry.name.startswith(TMP_PREFIX):
        return False
    marker = entry / TMP_MARKER
    if not marker.is_file() or marker.is_symlink():
        return False
    try:
        text = marker.read_text(encoding="utf-8", errors="replace")
        st = entry.stat()
    except OSError:
        return False
    pid = _parse_pid(text)
    if pid == os.getpid() or _is_live_process(pid):
        return False
    return now_ts - st.st_mtime >= STALE_AFTER_SECONDS


def _parse_pid(text: str) -> int:
    """从标记文件内容取 pid；取不到返回 -1。"""
    for line in text.splitlines():
        if line.startswith("pid="):
            try:
                return int(line.split("=", 1)[1])
            except (IndexError, ValueError):
                return -1
    return -1


def cleanup_stale_workspaces(
    *, temp_root: Optional[Path] = None, now: Optional[float] = None
) -> List[str]:
    """
    清理过期的临时工作目录，返回被删掉的目录名列表。

    **安全约束**（每一条都是为了「绝不误删」）：

    1. 只扫 ``temp_root`` 这一层，不递归
    2. 名字必须以 ``TMP_PREFIX`` 开头
    3. 不能是符号链接
    4. 必须存在 ``TMP_MARKER`` 文件（且它本身不是符号链接）
    5. mtime 必须早于 ``now - STALE_AFTER_SECONDS``
    6. 标记里的 pid 若是当前进程、或该进程仍存活，跳过

    任何单目录的失败都不影响其它目录，也不向上抛——清理是旁路。
    """
    root = Path(temp_root or tempfile.gettempdir())
    now_ts = now if now is not None else time.time()
    removed: List[str] = []
    try:
        entries = list(root.iterdir())
    except OSError:
        return removed

    for entry in entries:
        if not _is_ours_and_stale(entry, now_ts):
            continue
        # 只有真正删除这一步的错误被吞掉并记 warning——上面的判据错误不该被
        # 同一层 except 掩盖（那样会让「判据写错」看起来像「删不掉」）。
        try:
            shutil.rmtree(entry)
        except OSError:
            _log.warning("清理临时工作区失败：%s", entry.name, exc_info=True)
            continue
        removed.append(entry.name)
    return removed


def count_stale_workspaces(
    *, temp_root: Optional[Path] = None, now: Optional[float] = None
) -> int:
    """只统计不删除，便于测试与诊断。**判据与 cleanup 完全一致**（共用 `_is_ours_and_stale`）。"""
    root = Path(temp_root or tempfile.gettempdir())
    now_ts = now if now is not None else time.time()
    try:
        entries = list(root.iterdir())
    except OSError:
        return 0
    return sum(1 for e in entries if _is_ours_and_stale(e, now_ts))
