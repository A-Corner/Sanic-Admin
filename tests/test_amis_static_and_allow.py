#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
L2 与 L4 的回归测试。

L2：AMIS 目录下的开发文件（server.js、package.json、nodemon.json、README.md）
    不应被静态访问；含空字节的路径不应导致 500。
L4：405 响应应带 Allow 头，列出该 URI 实际支持的方法。
"""
import asyncio
import os
import tempfile
from pathlib import Path

import pytest

from app import create_app
from app.config import config_to_dict, get_config

#: 不应对外公开的 AMIS 开发文件
PRIVATE_FILES = ("server.js", "package.json", "nodemon.json", "README.md")


# 说明：本文件直接使用 conftest 提供的 ``client`` fixture（httpx.ASGITransport 路线）。
# 不用 ``app.test_client``：后者会走 Sanic 自己的生命周期，与 conftest 手动执行的
# ``_startup`` / ``_server_event`` 冲突，导致 teardown 时
# ``_server_event("shutdown", ...)`` 抛 TypeError。
# conftest 的 ``_build_config`` 不覆盖 AMIS_DIR，应用会挂载
# ``get_config("testing")`` 的默认值 BASE_DIR/amis —— 正是仓库内的 amis 目录。


# ---------------------------------------------------------------------------
# L2：开发文件不应对外公开
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", PRIVATE_FILES)
async def test_amis_dev_files_are_not_public(client, name):
    """AMIS 下的开发文件必须 404（不能被静态访问）。"""
    response = await client.get(f"/amis/{name}")
    assert response.status_code == 404, (
        f"/amis/{name} 返回 {response.status_code}，开发文件不应被公开访问"
    )


@pytest.mark.parametrize("name", PRIVATE_FILES)
async def test_amis_dev_files_not_leak_content(client, name):
    """开发文件的正文也不应出现在响应里。"""
    response = await client.get(f"/amis/{name}")
    body = response.text
    assert "amis-boilerplate" not in body
    assert "zero-dependency" not in body


# ---------------------------------------------------------------------------
# L2：AMIS 页面本身必须仍然可用
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/amis/login.html",
    "/amis/index.html",
    "/amis/pages/site.json",
    "/amis/sdk/sdk.js",
    "/amis/css/main.css",
])
async def test_amis_pages_still_served(client, path):
    """挡开发文件不能误伤正常页面。"""
    response = await client.get(path)
    assert response.status_code == 200, f"{path} 返回 {response.status_code}"


async def test_amis_index_serves_login_page(client):
    """/amis/ 应显示登录页（与 v0.2.0 行为一致）。"""
    response = await client.get("/amis/")
    assert response.status_code == 200
    assert "login" in response.text.lower()


# ---------------------------------------------------------------------------
# L2：含空字节的路径不应 500
# ---------------------------------------------------------------------------

async def test_amis_null_byte_path_is_client_error(client):
    """``/amis/%00`` 曾因空字节拼磁盘路径抛 ValueError 而 500，应改为 4xx。"""
    response = await client.get("/amis/%00")
    assert response.status_code in (400, 404), (
        f"/amis/%00 返回 {response.status_code}，应是 4xx 而不是 5xx"
    )


async def test_null_byte_path_never_5xx(client):
    """任何路径都不应因空字节变成 5xx。"""
    for path in ("/amis/%00", "/%00", "/api/v1/accounts/%00"):
        response = await client.get(path)
        assert response.status_code < 500, (
            f"{path} 返回 {response.status_code}，不应是 5xx"
        )


# ---------------------------------------------------------------------------
# L4：405 响应带 Allow 头
# ---------------------------------------------------------------------------

async def test_405_response_has_allow_header(client, auth_headers):
    """方法不匹配时应返回 405 并带 Allow 头。

    必须**已认证**才测得到 405：405 兜底路由同样挂在 v1_bp 上、同样经过
    api_bp 的组级认证中间件，未认证时先得到 401（这本身是正确行为 ——
    不泄露路由是否存在）。
    """
    response = await client.request(
        "PUT", "/api/v1/roles", json={}, headers=auth_headers
    )
    assert response.status_code == 405, f"期望 405，实际 {response.status_code}"
    allow = response.headers.get("allow")
    assert allow, "405 响应缺少 Allow 头（RFC 9110 要求）"


async def test_allow_header_lists_actual_methods(client, auth_headers):
    """Allow 头应包含该 URI 实际支持的方法。"""
    response = await client.request(
        "PATCH", "/api/v1/roles", json={}, headers=auth_headers
    )
    assert response.status_code == 405
    allow = response.headers.get("allow", "")
    methods = {m.strip() for m in allow.split(",") if m.strip()}
    assert "GET" in methods, f"Allow 头 {allow!r} 应包含 GET"
    assert "POST" in methods, f"Allow 头 {allow!r} 应包含 POST"
    assert "PATCH" not in methods, f"Allow 头 {allow!r} 不应包含实际不支持的 PATCH"


async def test_405_without_auth_returns_401(client):
    """未认证时方法不匹配应得 401 而非 405 —— 不泄露路由存在性。"""
    response = await client.request("PUT", "/api/v1/roles", json={})
    assert response.status_code == 401, (
        f"未认证请求得到 {response.status_code}，应是 401"
    )
