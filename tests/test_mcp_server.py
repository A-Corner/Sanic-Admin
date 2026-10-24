#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
MCP 服务（只读层）的测试。

每个工具一条正例 + 一条反例；另有三条安全边界用例：
路径穿越必须被拒、preview 前后仓库生成物哈希不变（正向对照）、
不暴露环境变量/数据库/密钥。
"""

import os
import pathlib

import pytest

from tools.mcp_server import (
    ToolError,
    _guard_resource_name,
    _repo_generated_digests,
    check,
    describe_resource,
    list_resources,
    preview_generate,
    validate_spec,
)

ROOT = pathlib.Path(__file__).resolve().parent.parent
CUSTOMER_SPEC = (ROOT / "specs" / "customer.yaml").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# list_resources
# ---------------------------------------------------------------------------


def test_list_resources_returns_specs():
    """正例：列出仓库内全部规格及字段摘要。"""
    items = list_resources()
    names = {i["resource"] for i in items}
    assert {"customer", "order"} <= names
    customer = next(i for i in items if i["resource"] == "customer")
    assert customer["field_count"] >= 3
    assert any(f["name"] == "name" for f in customer["fields"])


def test_list_resources_reports_soft_delete_and_sorting():
    """正例：摘要里带 soft_delete 与排序白名单（AI 需要据此理解资源）。"""
    customer = next(i for i in list_resources() if i["resource"] == "customer")
    assert customer["soft_delete"] is True
    assert "birthday" in customer["sorting_allowed"]


# ---------------------------------------------------------------------------
# describe_resource
# ---------------------------------------------------------------------------


def test_describe_resource_returns_spec_and_paths():
    """正例：返回规格全文、生成物路径、权限点。"""
    info = describe_resource("customer")
    assert info["resource"] == "customer"
    assert "resource: customer" in info["spec_yaml"]
    assert set(info["generated"]) == {"model", "resource", "amis_page", "test"}
    assert "customer:read" in info["permissions"]


def test_describe_resource_missing_raises():
    """反例：不存在的资源名报错（不返回空结构）。"""
    with pytest.raises(ToolError):
        describe_resource("no_such_resource")


# ---------------------------------------------------------------------------
# validate_spec
# ---------------------------------------------------------------------------


def test_validate_spec_accepts_valid_yaml():
    """正例：合法规格校验通过并回报资源名。"""
    result = validate_spec(CUSTOMER_SPEC)
    assert result["ok"] is True
    assert result["resource"] == "customer"


def test_validate_spec_reports_field_path_on_error():
    """反例：非法规格返回带字段路径的错误，而不是抛异常或只给一句话。"""
    bad = "resource: thing\nfields: []\n"
    result = validate_spec(bad)
    assert result["ok"] is False
    assert result["errors"], "应返回具体错误"
    assert any(e["path"] for e in result["errors"]), "错误应带字段路径"


def test_validate_spec_rejects_unknown_key():
    """反例：未知键（拼写错误）必须报错，不静默忽略。"""
    bad = CUSTOMER_SPEC + "\nunknown_key: 1\n"
    result = validate_spec(bad)
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# preview_generate
# ---------------------------------------------------------------------------


def test_preview_generate_returns_diff_without_writing_repo():
    """正例：返回 diff，且仓库生成物哈希前后一致（正向对照）。"""
    before = _repo_generated_digests()
    changed_spec = CUSTOMER_SPEC.replace("label: 客户", "label: 客户档案（改）")
    result = preview_generate(changed_spec)
    after = _repo_generated_digests()

    assert result["ok"] is True
    assert result["repo_unchanged"] is True
    assert result["diff"], "应返回非空 diff"
    assert "客户档案（改）" in result["diff"], "diff 应体现本次改动"
    assert before == after, "preview 不得修改仓库任何生成物"


def test_preview_generate_rejects_invalid_spec():
    """反例：非法规格在预览阶段就报错，不进入生成。"""
    result = preview_generate("resource: thing\nfields: []\n")
    assert result["ok"] is False
    assert result["errors"]


def test_preview_generate_diff_is_scoped_to_changed_resource():
    """正例：预览单个资源时，不应出现「删除其它资源」的误导性 diff。"""
    changed_spec = CUSTOMER_SPEC.replace("label: 客户", "label: 客户档案（改）")
    result = preview_generate(changed_spec)
    # order 资源没被改动，它的权限点不应出现在 diff 的删除行里
    assert "'order'" not in result["diff"], (
        "预览不应把其它资源渲染成被删除——临时目录需要包含全部现有规格"
    )


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


def test_check_reports_consistent():
    """正例：当前仓库生成物与规格一致。"""
    result = check()
    assert result["ok"] is True
    assert result["drift"] == [] and result["stale"] == []


# ---------------------------------------------------------------------------
# 安全边界：路径穿越
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [
    "../customer",
    "../../etc/passwd",
    "/etc/passwd",
    "customer/../../etc",
    "sub/dir/customer",
    "customer\\x",
    "",
    "Customer",
    "customer-1",
])
def test_resource_name_whitelist_rejects_traversal(bad):
    """路径穿越与非法资源名必须被拒（白名单，不是黑名单）。"""
    with pytest.raises(ToolError):
        _guard_resource_name(bad)


def test_describe_resource_rejects_traversal():
    """工具入口同样拦截路径穿越，不给「读取任意文件」的口子。"""
    for bad in ("../customer", "/etc/passwd", "../../etc/passwd"):
        with pytest.raises(ToolError):
            describe_resource(bad)


# ---------------------------------------------------------------------------
# 安全边界：不暴露环境变量 / 数据库 / 密钥
# ---------------------------------------------------------------------------


def test_tools_do_not_leak_env_or_secrets(monkeypatch):
    """工具输出不得包含环境变量值、数据库连接串或密钥。"""
    monkeypatch.setenv("SECRET_KEY", "TOP-SECRET-DO-NOT-LEAK")
    monkeypatch.setenv("DATABASE_URL", "postgres://user:pw@host/db")
    monkeypatch.setenv("JWT_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----")

    blob = str(list_resources()) + str(describe_resource("customer")) + str(check())
    for needle in ("TOP-SECRET-DO-NOT-LEAK", "postgres://user:pw@host/db",
                   "BEGIN PRIVATE KEY"):
        assert needle not in blob, f"工具输出泄露了 {needle!r}"


def test_preview_temporaries_are_cleaned_up():
    """preview 用的临时目录用完即删。"""
    import tempfile

    before = set(pathlib.Path(tempfile.gettempdir()).glob("specgen-preview-*"))
    preview_generate(CUSTOMER_SPEC.replace("label: 客户", "label: tmp-check"))
    after = set(pathlib.Path(tempfile.gettempdir()).glob("specgen-preview-*"))
    assert not (after - before), f"临时目录未清理：{after - before}"


# ---------------------------------------------------------------------------
# 对外契约：MCP 工具名必须与 docs/mcp.md 一致
# ---------------------------------------------------------------------------


def test_registered_tool_names_match_documented_contract():
    """注册给客户端的工具名须是文档里那五个，不能带 _tool 后缀。"""
    pytest.importorskip("mcp")
    from tools.mcp_server import build_server

    server = build_server()
    names = {t.name for t in server._tool_manager.list_tools()}
    assert names == {
        "list_resources",
        "describe_resource",
        "validate_spec",
        "preview_generate",
        "check",
    }, f"工具名与 docs/mcp.md 契约不符：{sorted(names)}"
