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
    assert "id=all" in (row.detail or ""), (
        f"detail 应含 id=all（全量清空的显式标记），实际 {row.detail!r}"
    )
    assert row.account_id is not None, (
        "审计必须带操作者 account（谁清的空缓存是可追溯性的核心）"
    )


@pytest.mark.parametrize(
    "query,case",
    [
        ("?type=route", "route 分支"),
        ("?type=pattern&pattern=rbac09c-*", "pattern 分支"),
    ],
)
async def test_non_all_types_do_not_write_audit(client, auth_headers, query, case):
    """
    **正向对照**：``route`` 与 ``pattern`` 不写审计。

    只测「all 写了」不够 —— 如果实现变成「每条都写」，那个测试仍然通过。
    必须同时证明「别的分支没写」，才能确认审计是**按分支触发的**，
    不是**无条件触发的**。

    为什么这两个分支不该写：它们都是**定范围**的删除，删掉的东西可由
    ``pattern`` 重建；``all`` 是**无范围**的，事后无法知道删了什么。
    """
    await _clear_audit_rows()

    resp = await client.delete(f"/api/v1/cache{query}", headers=auth_headers)
    assert resp.status_code == 200, resp.text

    count = await _audit_count()
    assert count == 0, (
        f"{case} 不应写审计（只有 type=all 写），实际写了 {count} 条"
    )


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
