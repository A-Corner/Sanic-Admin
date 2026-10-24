#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
MCP 写入工具的注册开关与 base_ref 校验测试。

对应 CPL 的两项裁定：
1. 写入工具**默认不注册**，必须 ``--allow-write`` 才出现在 tools/list
2. ``base_ref`` 默认取 ``master``（不取 HEAD），显式传入时校验形态与存在性

每条都做过「破坏实现 → 必须变红」的对照。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tools.mcp_server.git_isolation import (
    DEFAULT_BASE_REF,
    GitNotAllowed,
    validate_base_ref,
)
from tools.mcp_server.write_tools import WRITE_TOOL_NAMES


@pytest.fixture(autouse=True)
def _bypass_identity(monkeypatch):
    """
    本文件测的是注册开关与 base_ref 校验，不是身份层。

    SA-v042-SPECWRITE 起 ``propose_spec_change`` 等写入工具在入口做
    ``spec:write`` 校验（whoami 回调）；本文件不关心该层——固定放行并
    给出确定性的 account_id。身份层的七种拒绝矩阵与零副作用断言见
    ``tests/test_mcp_spec_write_auth.py``。
    """
    from tools.mcp_server import identity

    monkeypatch.setattr(identity, "require_spec_write", lambda: 42)


def _run(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=True,
    ).stdout


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _run(r, "init", "-q")
    _run(r, "config", "user.email", "t@example.invalid")
    _run(r, "config", "user.name", "t")
    (r / "specs").mkdir()
    (r / "specs" / "demo.yaml").write_text("name: demo\n", encoding="utf-8")
    _run(r, "add", "-A")
    _run(r, "commit", "-q", "-m", "init")
    # 确保存在一个叫 master 的分支（git init 的默认分支名可能是 main）
    head = _run(r, "rev-parse", "HEAD").strip()
    _run(r, "update-ref", "refs/heads/master", head)
    return r


# ---------------------------------------------------------------------------
# 一、写入工具默认不注册
# ---------------------------------------------------------------------------


def test_write_tools_not_registered_by_default(repo: Path, monkeypatch) -> None:
    """不带 --allow-write 时，tools/list 里没有三个写入工具。"""
    from tools.mcp_server import build_server

    server = build_server()  # 默认 allow_write=False

    # 取出已注册的工具名。SDK 的存储形态可能变化，这里用最小依赖的方式：
    # 通过 asgi/mcp 暴露的 list 能力拿工具清单。
    names = _tool_names(server)
    for write_tool in WRITE_TOOL_NAMES:
        assert write_tool not in names, f"{write_tool} 在默认（只读）模式下不应出现；实际工具：{sorted(names)}"
    # 正向对照：只读工具必须在，证明上面的「不在」不是因为列表为空
    assert "list_resources" in names, f"只读工具缺失，工具列表异常：{sorted(names)}"
    assert "preview_generate" in names


def test_write_tools_registered_with_allow_write(repo: Path) -> None:
    """带 allow_write=True 时，三个写入工具都在。"""
    from tools.mcp_server import build_server

    server = build_server(allow_write=True)
    names = _tool_names(server)
    for write_tool in WRITE_TOOL_NAMES:
        assert write_tool in names, f"{write_tool} 未注册；实际工具：{sorted(names)}"


def test_main_parses_allow_write_flag(monkeypatch) -> None:
    """`--allow-write` 从 argv 里被识别并移除，不会当成 --root 的值。"""
    import tools.mcp_server as mcp

    captured: dict = {}

    class _FakeServer:
        def run(self) -> None:
            captured["ran"] = True

    def _fake_build(allow_write: bool = False):
        captured["allow_write"] = allow_write
        return _FakeServer()

    monkeypatch.setattr(mcp, "build_server", _fake_build)
    monkeypatch.setattr(mcp, "_specs_dir", lambda: Path(mcp.ROOT) / "specs")
    # 用真实仓库根，保证 specs/ 存在
    monkeypatch.setattr(mcp, "ROOT", Path(__file__).resolve().parent.parent)

    rc = mcp.main(["--allow-write"])
    assert rc == 0
    assert captured.get("allow_write") is True
    assert captured.get("ran") is True


def _tool_names(server) -> set:
    """
    从 MCP server 对象取已注册的工具名，兼容几种常见存储位置。

    **取不到就失败，不跳过**——``pytest.skip`` 会让「没取到数据」显示成
    「这轮不用测」，与 AGENTS.md §3.6 的纪律直接冲突（跑了 ≠ 通过 ≠ 有效）。
    SDK 升级导致结构变化时，这里必须红，让人来适配，而不是静默通过。
    """
    for attr_path in (
        ("_tool_manager", "_tools"),
        ("_tools",),
        ("tools",),
    ):
        obj = server
        ok = True
        for attr in attr_path:
            obj = getattr(obj, attr, None)
            if obj is None:
                ok = False
                break
        if ok:
            if isinstance(obj, dict):
                return set(obj.keys())
            if isinstance(obj, (list, tuple, set)):
                out = set()
                for item in obj:
                    name = getattr(item, "name", None) or str(item)
                    out.add(name)
                return out
    raise AssertionError(
        "无法从 MCP SDK 对象取出工具列表——SDK 结构可能变了，请更新本函数。"
        f"server 的公开属性：{sorted(a for a in dir(server) if not a.startswith('__'))}"
    )


# ---------------------------------------------------------------------------
# 二、base_ref 默认与校验
# ---------------------------------------------------------------------------


def test_default_base_ref_is_master_not_head() -> None:
    """默认必须是 master——不能是 HEAD（用户可能停在功能分支上）。"""
    assert DEFAULT_BASE_REF == "master"
    assert DEFAULT_BASE_REF != "HEAD"


def test_base_ref_accepts_existing_ref(repo: Path) -> None:
    assert validate_base_ref(repo, "master") == "master"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "../etc/passwd",
        "master..main",
        "/master",
        "master/",
        "ma ster",
        "master~1",
        "master^x",
        "master:path",
        "master?",
        "master*",
    ],
)
def test_base_ref_rejects_bad_shapes(repo: Path, bad: str) -> None:
    with pytest.raises(GitNotAllowed):
        validate_base_ref(repo, bad)


def test_base_ref_rejects_nonexistent_ref(repo: Path) -> None:
    """形态合法但不存在，同样拒绝——否则 clone 会以一个奇怪的错误失败。"""
    with pytest.raises(GitNotAllowed) as excinfo:
        validate_base_ref(repo, "no-such-branch")
    assert "不存在" in str(excinfo.value)


def test_propose_uses_master_by_default(repo: Path, monkeypatch) -> None:
    """
    提案默认基于 master：把 HEAD 切到功能分支后，提案的父提交应是 master 的 tip。
    """
    from tools.mcp_server.write_tools import propose_spec_change

    master_tip = _run(repo, "rev-parse", "master").strip()

    # 切到功能分支并多做一个提交——若实现误用 HEAD，提案会把这条也带进去
    _run(repo, "checkout", "-q", "-b", "feature-x")
    (repo / "extra.txt").write_text("x", encoding="utf-8")
    _run(repo, "add", "-A")
    _run(repo, "commit", "-q", "-m", "feature work")
    feature_tip = _run(repo, "rev-parse", "HEAD").strip()
    assert feature_tip != master_tip

    result = propose_spec_change(
        "demo",
        "resource: demo\ntable: demo\nlabel: 演示\nfields:\n  - name: title\n    type: string\n    max_length: 64\n    required: true\n    label: 标题\n",
        repo_root=repo,
    )
    branch = result["branch"]
    parent = _run(repo, "rev-parse", f"{branch}^").strip()

    assert parent == master_tip, (
        f"提案应基于 master（{master_tip[:7]}），实际父提交 {parent[:7]}；若等于 feature tip {feature_tip[:7]} 说明误用了 HEAD"
    )


def test_propose_rejects_invalid_base_ref(repo: Path) -> None:
    from tools.mcp_server.write_tools import propose_spec_change

    with pytest.raises(GitNotAllowed):
        propose_spec_change(
            "demo",
            "resource: demo\ntable: demo\nlabel: 演示\nfields:\n  - name: title\n    type: string\n    max_length: 64\n    required: true\n    label: 标题\n",
            base_ref="../evil",
            repo_root=repo,
        )
    # 失败后不应留下任何提案分支
    branches = _run(repo, "branch", "--list", "proposal/*")
    assert branches.strip() == ""


# ---------------------------------------------------------------------------
# 返回值字段的真实性
# ---------------------------------------------------------------------------


def test_audit_written_reflects_real_result(repo: Path, monkeypatch) -> None:
    """
    ``audit_written`` 必须反映真实写入结果，不能恒为 True。

    审核指出：早期实现里它写死 True，而 stderr 被关掉时审计其实没写出去——
    调用方会误以为审计成功。这条钉死「字段要如实」。
    """
    from tools.mcp_server import write_tools

    # 正常情况：True
    ok = write_tools.propose_spec_change(
        "first",
        "resource: first\ntable: first\nlabel: d\nfields:\n  - name: a\n    type: string\n",
        repo_root=repo,
    )
    assert ok["audit_written"] is True

    # 让 _audit 写失败：stderr 换成一个会抛异常的对象
    class _BrokenStderr:
        def write(self, *_a, **_k):
            raise OSError("stderr closed")

        def flush(self):
            raise OSError("stderr closed")

    real_stderr = write_tools.sys.stderr
    write_tools.sys.stderr = _BrokenStderr()
    try:
        broken = write_tools.propose_spec_change(
            "second",
            "resource: second\ntable: second\nlabel: d\nfields:\n  - name: b\n    type: string\n",
            repo_root=repo,
        )
    finally:
        write_tools.sys.stderr = real_stderr

    assert broken["audit_written"] is False, "审计写入失败时 audit_written 仍是 True——字段没有如实反映结果"


def test_result_carries_base_commit(repo: Path) -> None:
    """返回值必须带 base_commit（完整 SHA），供人判断提案基于哪个提交。"""
    from tools.mcp_server.write_tools import propose_spec_change

    expected = _run(repo, "rev-parse", "master").strip()
    out = propose_spec_change(
        "third",
        "resource: third\ntable: third\nlabel: d\nfields:\n  - name: c\n    type: string\n",
        repo_root=repo,
    )
    assert out["base_commit"] == expected, (
        f"base_commit 应为 master 的 SHA {expected[:7]}，实际 {out.get('base_commit', '缺失')[:7]}"
    )
    assert len(out["base_commit"]) == 40


# ---------------------------------------------------------------------------
# 三、审计写 stderr
# ---------------------------------------------------------------------------


def test_audit_written_to_stderr(repo: Path, capsys) -> None:
    """每次调用都往 stderr 写一行结构化 JSON。"""
    from tools.mcp_server.write_tools import propose_spec_change

    propose_spec_change(
        "demo",
        "resource: demo\ntable: demo\nlabel: 演示\nfields:\n  - name: title\n    type: string\n    max_length: 64\n    required: true\n    label: 标题\n",
        repo_root=repo,
    )
    err = capsys.readouterr().err
    assert '"channel": "mcp-audit"' in err or '"channel":"mcp-audit"' in err
    assert '"operation": "propose_spec_change"' in err.replace('":"', '": "')
    assert '"status": "success"' in err.replace('":"', '": "')
    # 审计不得包含规格全文
    assert "fields:" not in err
