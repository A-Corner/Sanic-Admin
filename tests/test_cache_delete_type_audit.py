#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
缓存清理的 ``type`` 参数与审计（EVT-20261028-041）。

问题
====
``DELETE /api/v1/cache`` 此前 ``type`` 默认 ``"all"`` —— **不带参数的 DELETE
直接清空整个缓存**，且**不写审计**。

三个分支里，``all`` 是唯一不可逆的，却是唯一有默认值的。

改动
====
1. ``type`` 改为必填：不传 / 传非法值 → 400 + ``VALIDATION_ERROR``
2. ``type=all`` 写一条审计（``resource=cache`` / ``action=delete`` / ``object_id=all``）
3. ``type=route`` 与 ``type=pattern`` **不写**审计

本文件的三层目的
================
1. **默认值真的取消了** —— 不传 / 非法值都 400，不是「静默按 all 处理」
2. **只有 all 写审计** —— 这是**正向对照**：只测「all 写了」不够，
   还要证明「别的分支没写」，否则「每条都写」也能通过
3. **三个合法分支都还能正常清** —— 收紧入口不能把功能改坏
"""

import pytest

from app.cache import get_cache
from app.models import OperationLog


async def _clear_audit_rows():
    """清掉本次测试产生的 cache 审计行，避免与套件内其他断言互相干扰。"""
    await OperationLog.filter(operation_type="cache").delete()


async def _audit_count() -> int:
    return await OperationLog.filter(operation_type="cache").count()


# ----------------------------------------------------------------------
# 1. type 必填
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "query,case",
    [
        ("", "完全不传 type"),
        ("?type=", "传了但为空"),
        ("?type=garbage", "传了非法值"),
        ("?type=ALL", "大小写不匹配（值是大小写敏感的）"),
        ("?type=allx", "近似但不等于 all"),
    ],
)
async def test_delete_without_valid_type_returns_400(client, auth_headers, query, case):
    """
    不传 ``type`` 或传非法值必须是 **400 + VALIDATION_ERROR**，不能静默按 all 处理。

    **为什么必须精确到 400**：这个测试的核心是「默认全清取消了」。如果断言写成
    ``>= 400``，一个 500（代码写崩了）也能通过 —— 那测的不是「入口被收紧」，
    是「服务出错了」。
    """
    cache = get_cache()
    cache.set("rbac09c-guard", "v", timeout=300)
    try:
        resp = await client.delete(f"/api/v1/cache{query}", headers=auth_headers)
        assert resp.status_code == 400, (
            f"{case} 应 400，实际 {resp.status_code}: {resp.text}"
        )
        body = resp.json()
        assert body.get("error") == "VALIDATION_ERROR", (
            f"{case} 的错误码应为 VALIDATION_ERROR，实际 {body.get('error')!r}"
        )
        # 关键：缓存没被清 —— 这才是「默认全清已取消」的实质证据
        assert cache.exists("rbac09c-guard"), (
            f"{case} 被拒绝后缓存不应被清空（这正是本项要防的误操作）"
        )
    finally:
        cache.delete("rbac09c-guard")


# ----------------------------------------------------------------------
# 2. 审计：只有 type=all 写（含正向对照）
# ----------------------------------------------------------------------

async def test_type_all_writes_audit(client, auth_headers):
    """``type=all`` 必须写一条审计，且带操作者。"""
    await _clear_audit_rows()

    resp = await client.delete("/api/v1/cache?type=all", headers=auth_headers)
    assert resp.status_code == 200, resp.text

    rows = await OperationLog.filter(operation_type="cache").all()
    assert len(rows) == 1, (
        f"type=all 应写 1 条审计，实际 {len(rows)} 条"
    )
    row = rows[0]
    assert row.operation == "delete", f"operation 应为 delete，实际 {row.operation!r}"
    assert (row.detail or "") == "id=all", (
        f"type=all 的 detail 应为 'id=all'，实际 {row.detail!r}"
    )
    assert row.account_id is not None, (
        "审计必须带操作者 account（谁清的空缓存是可追溯性的核心）"
    )


@pytest.mark.parametrize(
    "query,expected_id",
    [
        ("?type=route", "route:*"),
        ("?type=route&pattern=api:", "route:api:"),
        ("?type=pattern&pattern=rbac09c-*", "pattern:rbac09c-*"),
    ],
)
async def test_route_and_pattern_also_write_audit(
    client, auth_headers, query, expected_id
):
    """
    **三个分支都写审计** —— 这是 ``pattern=*`` 绕过点的修复。

    历史：最初只有 ``type=all`` 写审计，于是 ``?type=pattern&pattern=*``
    能达成与 ``type=all`` 完全相同的效果却不留任何记录 —— 一条**不留痕的全清路径**。

    修复方式不是「判断 pattern 是否等效全清再决定是否审计」（那个集合无法穷举：
    ``*`` / ``**`` / ``*?`` / ``[a-w]*`` …），而是「**凡删除必审计**」。

    审计内容按分支填，让 detail 能读出删除范围：
    ``id=route:<pattern>`` / ``id=pattern:<pattern>``。
    """
    await _clear_audit_rows()

    resp = await client.delete(f"/api/v1/cache{query}", headers=auth_headers)
    assert resp.status_code == 200, resp.text

    rows = await OperationLog.filter(operation_type="cache").all()
    assert len(rows) == 1, (
        f"{query} 应写 1 条审计（三个分支都写），实际 {len(rows)} 条"
    )
    assert (rows[0].detail or "") == f"id={expected_id}", (
        f"{query} 的 detail 应为 'id={expected_id}'，实际 {rows[0].detail!r}"
    )


async def test_pattern_star_cannot_bypass_audit(client, auth_headers):
    """
    **回归测试**：``?type=pattern&pattern=*`` 不能成为「不留痕的全清」。

    这条是本项最重要的回归 —— 它测的正是审核席指出的绕过点。
    ``pattern=*`` 与 ``type=all`` 效果相同（都清空全部键），
    修复后两者**都必须留审计**。
    """
    await _clear_audit_rows()
    cache = get_cache()
    cache.set("rbac09c-bypass-a", "v", timeout=300)
    cache.set("rbac09c-bypass-b", "v", timeout=300)

    resp = await client.delete(
        "/api/v1/cache?type=pattern&pattern=*", headers=auth_headers
    )
    assert resp.status_code == 200, resp.text
    assert not cache.exists("rbac09c-bypass-a"), "pattern=* 确实删除了全部键"
    assert not cache.exists("rbac09c-bypass-b"), "pattern=* 确实删除了全部键"

    count = await _audit_count()
    assert count == 1, (
        f"pattern=* 等效全清，必须留审计；实际写了 {count} 条"
    )
    row = (await OperationLog.filter(operation_type="cache").all())[0]
    assert (row.detail or "") == "id=pattern:*", (
        f"detail 应记录删除范围 'id=pattern:*'，实际 {row.detail!r}"
    )

    await _clear_audit_rows()


# ----------------------------------------------------------------------
# 2b. 审计注入防护：pattern 不能破坏 detail 结构
# ----------------------------------------------------------------------
#
# ``pattern`` 会被拼进 ``detail``（``id=pattern:<pattern>``），而 detail 是
# **空格分隔的 key=value 格式**，官方解析器（docs/audit-log-format.md）按
# ``detail[3:].split(" ", 1)[0]`` 取 id、按 ``detail.find("fields=")`` 取字段名。
#
# 两类字符能让操作者**伪造审计内容**：
#   1. 空格      → id 被截断
#   2. "fields=" → 解析器把 pattern 里的 ``fields=`` 当成真的字段段
#
# 第 2 条更隐蔽：id 段没被截断，整条记录看起来格式合法，但 fields 是伪造的。


@pytest.mark.parametrize(
    "pattern,case",
    [
        ("a b", "含空格 → id 会被截断"),
        ("fields=y", "含 fields= → 伪造 fields 段（无空格，id 不被截断，更隐蔽）"),
        ('x fields=["fake"]', "组合注入：空格 + JSON 数组形态的 fields"),
        ("myfields=z", "fields= 出现在中间"),
    ],
)
@pytest.mark.parametrize("type_value", ["pattern", "route"])
async def test_pattern_injection_is_rejected(
    client, auth_headers, pattern, case, type_value
):
    """
    ``pattern`` 含空格或 ``fields=`` 必须 400 —— 否则可以伪造审计记录。

    **两个分支都测**（``pattern`` 与 ``route``）：两条路径都把 pattern 拼进
    审计 detail，所以都受同一类注入影响。

    **为什么这些输入真的危险**（实测，不是推测）：
    ```
    pattern='a b'             → detail='id=pattern:a b'          → 解析 id='pattern:a'
    pattern='fields=y'        → detail='id=pattern:fields=y'     → 解析 fields=['y']
    pattern='x fields=["fake"]' → detail='id=pattern:x fields=["fake"]'
                                                              → 解析 fields=['fake']
    ```
    **最后一条尤其危险**：伪造的 ``fields=["fake"]`` 是 JSON 数组形态，
    正是 v0.4.2 起生成资源审计的格式，**看起来完全合法**。
    """
    cache = get_cache()
    cache.set("rbac09c-inj", "v", timeout=300)
    try:
        resp = await client.delete(
            "/api/v1/cache",
            params={"type": type_value, "pattern": pattern},
            headers=auth_headers,
        )
        assert resp.status_code == 400, (
            f"{type_value} 分支：{case}，应 400，实际 {resp.status_code}: {resp.text}"
        )
        assert resp.json().get("error") == "VALIDATION_ERROR", (
            f"错误码应为 VALIDATION_ERROR，实际 {resp.json().get('error')!r}"
        )
        assert cache.exists("rbac09c-inj"), (
            f"{case}：被拒绝后缓存不应被删（说明校验在删除之前生效）"
        )
    finally:
        cache.delete("rbac09c-inj")


@pytest.mark.parametrize(
    "pattern",
    [
        "user_rl:*",
        "login_rl_acct:123",
        "a:b",
        "a,b",
        "a=b",
        "a*b",
        "a\tb",
        "a\nb",
    ],
)
async def test_benign_patterns_are_not_rejected(client, auth_headers, pattern):
    """
    **反向对照**：合法 pattern 不能被误拒。

    这条和上面那条是一对 —— 只测「危险输入被拒」不够，还要证明
    「安全输入没被误伤」，否则「拒绝一切」也能通过。

    特别包括 ``a\\tb`` 和 ``a\\nb``：实测它们**不破坏** detail 结构
    （``split(" ", 1)`` 只认 ASCII 空格），所以不该被拒。
    """
    resp = await client.delete(
        "/api/v1/cache",
        params={"type": "pattern", "pattern": pattern},
        headers=auth_headers,
    )
    assert resp.status_code == 200, (
        f"合法 pattern {pattern!r} 不应被拒，实际 {resp.status_code}: {resp.text}"
    )
    await _clear_audit_rows()


# ----------------------------------------------------------------------
# 3. 三个合法分支仍然可用（收紧入口不能改坏功能）
# ----------------------------------------------------------------------

async def test_type_route_clears_route_cache(client, auth_headers):
    """``type=route`` 返回 200 并给出清理数量。"""
    resp = await client.delete("/api/v1/cache?type=route", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    assert "路由缓存键" in resp.json().get("message", ""), (
        f"message 应说明清理的是路由缓存，实际 {resp.text}"
    )


async def test_type_pattern_deletes_matching_keys(client, auth_headers):
    """``type=pattern`` 只删匹配的键，不碰其他键。"""
    cache = get_cache()
    cache.set("rbac09c-match-a", "v", timeout=300)
    cache.set("rbac09c-match-b", "v", timeout=300)
    cache.set("rbac09c-keep", "v", timeout=300)
    try:
        resp = await client.delete(
            "/api/v1/cache?type=pattern&pattern=rbac09c-match-*", headers=auth_headers
        )
        assert resp.status_code == 200, resp.text
        assert not cache.exists("rbac09c-match-a"), "匹配的键应被删除"
        assert not cache.exists("rbac09c-match-b"), "匹配的键应被删除"
        assert cache.exists("rbac09c-keep"), "不匹配的键不应被删除"
    finally:
        for k in ("rbac09c-match-a", "rbac09c-match-b", "rbac09c-keep"):
            cache.delete(k)


async def test_type_all_clears_everything(client, auth_headers):
    """``type=all`` 清空所有键。"""
    cache = get_cache()
    cache.set("rbac09c-a", "v", timeout=300)
    cache.set("rbac09c-b", "v", timeout=300)

    resp = await client.delete("/api/v1/cache?type=all", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    assert not cache.exists("rbac09c-a"), "all 应清空所有键"
    assert not cache.exists("rbac09c-b"), "all 应清空所有键"

    await _clear_audit_rows()


# ----------------------------------------------------------------------
# 4. 非 admin 对三个分支都 403（权限未因改动松动）
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "query",
    ["?type=route", "?type=pattern&pattern=*", "?type=all"],
)
async def test_non_admin_403_for_all_types(client, normal_auth_headers, query):
    """
    非 admin 对**每个** ``type`` 都 403，包括 ``all``。

    ``type`` 变成必填后，容易出的错是「新加的参数校验走在权限检查之前」——
    那样非 admin 会拿到 400（因参数不对）而不是 403（因权限不足），
    **把「没权限」伪装成「参数错误」**。这条钉住顺序：权限在前。
    """
    resp = await client.delete(f"/api/v1/cache{query}", headers=normal_auth_headers)
    assert resp.status_code == 403, (
        f"非 admin 带 {query} 应 403（权限检查先于参数校验），"
        f"实际 {resp.status_code}: {resp.text}"
    )
