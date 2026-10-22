#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
OpenAPI 规范不应包含 405 兜底路由引入的"实际不支持的方法"。

背景：``register_view`` 会为每个 URI 额外注册一条名为 ``*_method_not_allowed``
的兜底路由，它的方法集是该 URI **不支持**的那些（DELETE/GET/OPTIONS/PATCH/POST）。
若 OpenAPI 生成把它收进规范，会把不存在的操作写进 swagger（例如
``GET /api/v1/logs`` 只有 GET，却显示 delete/patch/post/put）。

修复：``app/docs/openapi.py`` 的 ``_process_route`` 跳过这类兜底路由。
"""
import json

import pytest


async def _get_spec(client):
    response = await client.get("/swagger.json")
    assert response.status_code == 200, f"/swagger.json 返回 {response.status_code}"
    return response.json()


async def test_openapi_does_not_include_405_fallback_methods(client):
    """只支持 GET 的 URI，在 OpenAPI 里只应出现 get。"""
    spec = await _get_spec(client)
    paths = spec.get("paths", {})
    assert paths, "OpenAPI 规范里没有任何 path"

    # 这两个 URI 实际只支持 GET（其余方法会命中 405 兜底）
    for uri in ("/api/v1/logs", "/api/v1/files"):
        if uri not in paths:
            continue
        methods = {m.lower() for m in paths[uri]}
        assert "get" in methods, f"{uri} 应当有 get"
        for bogus in ("delete", "patch", "post", "put"):
            assert bogus not in methods, (
                f"{uri} 的 OpenAPI 里出现了 {bogus} —— "
                f"405 兜底路由的方法被写进了规范（该 URI 实际只支持 GET）"
            )


async def test_openapi_keeps_real_write_methods(client):
    """真正支持写方法的 URI，其方法不能被兜底路由覆盖掉。"""
    spec = await _get_spec(client)
    paths = spec.get("paths", {})
    for uri, expected in (("/api/v1/settings", "post"), ("/api/v1/roles", "post")):
        if uri not in paths:
            continue
        methods = {m.lower() for m in paths[uri]}
        assert expected in methods, (
            f"{uri} 的 OpenAPI 里应保留真实的 {expected}，实际是 {sorted(methods)}"
        )


async def test_openapi_has_no_405_operation_anywhere(client):
    """规范里不应出现 405 这个伪操作。"""
    spec = await _get_spec(client)
    paths = spec.get("paths", {})
    for uri, ops in paths.items():
        for method in ops:
            assert str(method).lower() != "405", (
                f"{uri} 出现了 405 操作 —— 兜底路由被写进了 OpenAPI"
            )


async def test_openapi_still_has_real_operations(client):
    """跳过兜底路由不能误伤真实操作。"""
    spec = await _get_spec(client)
    paths = spec.get("paths", {})
    # 真实存在的写操作应仍在
    assert any(
        "post" in {m.lower() for m in ops} for ops in paths.values()
    ), "OpenAPI 里应至少有一个 POST 操作"
    assert any(
        "put" in {m.lower() for m in ops} for ops in paths.values()
    ), "OpenAPI 里应至少有一个 PUT 操作"
