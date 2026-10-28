#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
缓存资源的写方法：注册、405 兜底、权限（RBAC-09）。

背景
====
``app/api/resources/cache.py`` 的三个视图类里，``delete`` / ``put`` / ``delete``
三个方法**实现完整且有测试价值**，但 ``register_view`` 只传了 ``["GET"]``——
**能力实现了，从未对外注册**。请求一律 405。

判据依据（不是「设计如此」）
==========================
同一个仓库里其他资源用同一个 ``register_view`` 支持多方法：

* ``compression.py`` 的 ``/config`` → ``["GET", "PUT"]``
* ``database.py`` 的 ``/query-plan`` → ``["GET", "POST"]``
* ``database.py`` 的 ``/connection-pool`` → ``["GET", "PUT"]``

``cache.py`` 是全仓唯一一个「视图有写方法但注册只给 GET」的文件。

本文件的测试有三层目的，缺一层都不算验到位
==========================================

1. **注册生效**：写方法不再是 405。
2. **405 兜底没被破坏**：未声明的方法（PATCH / POST）仍 405，且 ``Allow`` 头
   反映了新的方法集合。**补注册最容易在这里出事** —— ``route_methods.py:139``
   按 ``hasattr(view, m.lower())`` 算 ``implemented``，算错会让兜底分支吃掉
   本应生效的方法，或反之。
3. **权限真的生效**：非 admin 身份必须 403 而不是 200。**这条最容易假绿** ——
   ``@check_permissions`` 装饰在 ``HTTPMethodView.delete`` 上，
   如果 Sanic 没有正常分派到该方法，403 断言会因为「根本没执行到」而误判。
   本文件用「admin 拿到 200、普通用户拿到 403」成对断言来排除这一情形。
"""

import pytest

from app.api.resources.cache import cache_resource, cache_key_resource
from app.cache import get_cache


# ----------------------------------------------------------------------
# 405 兜底：未声明的方法
# ----------------------------------------------------------------------

@pytest.mark.parametrize("method", ["PATCH", "POST"])
async def test_undeclared_methods_still_405(client, auth_headers, method):
    """
    补注册后，未声明的方法必须仍是 405（不能变 500 或 404）。

    这是本项最容易被破坏的不变量：``register_view`` 的兜底路由是「除
    ``implemented`` 之外的全部方法」，补注册改变了 ``implemented`` 的构成，
    兜底分支必须相应收窄。断言 ``Allow`` 头同时验证收窄是正确的，
    而不是「全部方法都被兜底吃掉」。

    **只测 PATCH / POST**：``route_methods.py:56`` 的 ``ALL_HTTP_METHODS``
    只含 ``GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS`` —— ``TRACE`` 不在其中，
    它不由兜底路由处理（Sanic 自己返 405 但不带项目的 ``Allow`` 头），
    断言 ``Allow`` 会在那种情况下失败。**测一个不归兜底管的方法，
    测的不是本项改动的行为。**
    """
    resp = await client.request(method, "/api/v1/cache", headers=auth_headers)
    assert resp.status_code == 405, (
        f"{method} /api/v1/cache 应 405（未声明），实际 {resp.status_code}"
    )
    allow = resp.headers.get("allow", "")
    for declared in ("GET", "DELETE"):
        assert declared in allow, (
            f"Allow 头应包含已声明的 {declared}，实际 {allow!r}"
        )
    for undeclared in ("PATCH", "POST"):
        assert undeclared not in allow, (
            f"Allow 头不应包含未声明的 {undeclared}，实际 {allow!r}"
        )


# ----------------------------------------------------------------------
# 注册生效：三个写方法
# ----------------------------------------------------------------------

async def test_delete_all_cache_is_registered(client, auth_headers):
    """``DELETE /cache`` 不再是 405 —— 这是本项要修的核心缺陷。"""
    resp = await client.delete("/api/v1/cache", headers=auth_headers)
    assert resp.status_code != 405, (
        "DELETE /api/v1/cache 仍是 405：注册没生效"
    )
    assert resp.status_code == 200, (
        f"admin 清理缓存应 200，实际 {resp.status_code}: {resp.text}"
    )


async def test_put_existing_key_is_registered(client, auth_headers):
    """``PUT /cache/keys/<key>`` 不再是 405，且能改过期时间。"""
    cache = get_cache()
    cache.set("rbac09-put", "v", timeout=300)
    try:
        resp = await client.put(
            "/api/v1/cache/keys/rbac09-put", json={"timeout": 60}, headers=auth_headers
        )
        assert resp.status_code != 405, "PUT /cache/keys/<key> 仍是 405：注册没生效"
        assert resp.status_code == 200, (
            f"改过期时间应 200，实际 {resp.status_code}: {resp.text}"
        )
    finally:
        cache.delete("rbac09-put")


async def test_delete_single_key_is_registered(client, auth_headers):
    """``DELETE /cache/keys/<key>`` 不再是 405，且真的删掉了键。"""
    cache = get_cache()
    cache.set("rbac09-del", "v", timeout=300)
    resp = await client.delete("/api/v1/cache/keys/rbac09-del", headers=auth_headers)
    assert resp.status_code != 405, "DELETE /cache/keys/<key> 仍是 405：注册没生效"
    assert resp.status_code == 200, (
        f"删键应 200，实际 {resp.status_code}: {resp.text}"
    )
    assert not cache.exists("rbac09-del"), "接口返回 200 但键仍存在"


# ----------------------------------------------------------------------
# 错误路径
# ----------------------------------------------------------------------

async def test_delete_missing_key_returns_404(client, auth_headers):
    """删不存在的键 → 404（区分「键不存在」与「接口不存在」）。"""
    resp = await client.delete(
        "/api/v1/cache/keys/rbac09-definitely-missing", headers=auth_headers
    )
    assert resp.status_code == 404, (
        f"删不存在的键应 404，实际 {resp.status_code}: {resp.text}"
    )


@pytest.mark.parametrize(
    "body,reason",
    [
        ({}, "空对象缺 timeout"),
        ({"timeout": "60"}, "timeout 是字符串"),
        ({"timeout": 1.5}, "timeout 是浮点"),
        ({"timeout": True}, "timeout 是布尔（Python 里 bool 是 int 子类）"),
    ],
)
async def test_put_bad_timeout_returns_400(client, auth_headers, body, reason):
    """``PUT`` 的 ``timeout`` 校验：缺失或类型错 → 400。"""
    cache = get_cache()
    cache.set("rbac09-bad", "v", timeout=300)
    try:
        resp = await client.put(
            "/api/v1/cache/keys/rbac09-bad", json=body, headers=auth_headers
        )
        assert resp.status_code == 400, (
            f"{reason} 应 400，实际 {resp.status_code}: {resp.text}"
        )
    finally:
        cache.delete("rbac09-bad")


async def test_put_missing_key_returns_404(client, auth_headers):
    """``PUT`` 一个不存在的键 → 404（不是 400，参数是合法的）。"""
    resp = await client.put(
        "/api/v1/cache/keys/rbac09-missing-for-put",
        json={"timeout": 60},
        headers=auth_headers,
    )
    assert resp.status_code == 404, (
        f"改不存在键的过期时间应 404，实际 {resp.status_code}: {resp.text}"
    )


# ----------------------------------------------------------------------
# 权限：非 admin 必须 403（这条最容易假绿）
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "method,url,body",
    [
        ("delete", "/api/v1/cache", None),
        ("put", "/api/v1/cache/keys/rbac09-perm", {"timeout": 60}),
        ("delete", "/api/v1/cache/keys/rbac09-perm", None),
    ],
)
async def test_non_admin_gets_403(
    client, auth_headers, normal_auth_headers, method, url, body
):
    """
    非 admin 调三个写方法都必须 403，**且同一请求 admin 拿到非 403**。

    **为什么要成对断言**：只断言「普通用户 403」无法区分两种情况 ——
    ① 权限装饰器真的拦住了，② 请求根本没走到视图（比如路由没注册，
    被别的中间件拦下）。加上 admin 那半边才能排除 ②：如果 admin 也 403，
    说明是中间件在拦，不是权限点在拦。
    """
    cache = get_cache()
    cache.set("rbac09-perm", "v", timeout=300)

    kwargs = {"headers": normal_auth_headers}
    if body is not None:
        kwargs["json"] = body
    resp_user = await getattr(client, method)(url, **kwargs)
    assert resp_user.status_code == 403, (
        f"普通用户 {method.upper()} {url} 应 403，实际 {resp_user.status_code}: {resp_user.text}"
    )

    kwargs = {"headers": auth_headers}
    if body is not None:
        kwargs["json"] = body
    resp_admin = await getattr(client, method)(url, **kwargs)
    assert resp_admin.status_code != 403, (
        f"admin {method.upper()} {url} 不应 403（否则说明是中间件在拦，"
        f"权限点没生效），实际 {resp_admin.status_code}"
    )

    cache.delete("rbac09-perm")


@pytest.mark.parametrize(
    "method,url",
    [
        ("get", "/api/v1/cache"),
        ("get", "/api/v1/cache/keys"),
        ("get", "/api/v1/cache/keys/rbac09-read"),
    ],
)
async def test_read_methods_also_require_admin(client, normal_auth_headers, method, url):
    """
    **读方法同样要求 admin** —— 这是既有行为，不是本项改的。

    为什么这条要在这里：本项给三个写方法「补注册」，读者容易以为权限要求
    是新加的。**实际 ``CacheResource.get`` 也有 ``@check_permissions("system", "admin")``**
    （`cache.py:106`），整套缓存资源一直是 admin-only。
    补注册后写方法沿用同一约束，没有引入新的鉴权面。

    当有人把装饰器从某个方法上误删时，这条会红。
    """
    resp = await getattr(client, method)(url, headers=normal_auth_headers)
    assert resp.status_code == 403, (
        f"普通用户 {method.upper()} {url} 应 403（缓存资源整体 admin-only），"
        f"实际 {resp.status_code}: {resp.text}"
    )
