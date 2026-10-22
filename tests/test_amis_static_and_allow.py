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


def _build_config(tmp_path: Path) -> dict:
    cfg = config_to_dict(get_config("testing"))
    cfg.update({
        "TESTING": True,
        "DEBUG": False,
        "ENV": "testing",
        "DATABASE_URL": f"sqlite://{tmp_path / 'test.sqlite3'}",
        "UPLOAD_DIR": str(tmp_path / "uploads"),
        "UPLOAD_FOLDER": str(tmp_path / "uploads"),
        "CACHE_TYPE": "memory",
        "CORS": False,
    })
    return cfg


@pytest.fixture()
async def amis_app(tmp_path):
    """指向仓库内 amis/ 目录的测试应用（AMIS_DIR 显式指定）。"""
    repo_root = Path(__file__).resolve().parent.parent
    amis_dir = repo_root / "amis"
    assert amis_dir.is_dir(), f"找不到 amis 目录：{amis_dir}"

    cfg = _build_config(tmp_path)
    cfg["AMIS_DIR"] = str(amis_dir)

    application = create_app(cfg)
    application.asgi = True
    await application._startup()
    loop = asyncio.get_running_loop()
    await application._server_event("init", "before", loop)
    await application._server_event("init", "after", loop)
    try:
        yield application
    finally:
        await application._server_event("shutdown", "before", loop)
        await application._server_event("shutdown", "after", loop)


# ---------------------------------------------------------------------------
# L2：开发文件不应对外公开
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", PRIVATE_FILES)
async def test_amis_dev_files_are_not_public(amis_app, name):
    """AMIS 下的开发文件必须 404（不能被静态访问）。"""
    _, response = await amis_app.test_client.get(f"/amis/{name}")
    assert response.status_code == 404, (
        f"/amis/{name} 返回 {response.status_code}，开发文件不应被公开访问"
    )


@pytest.mark.parametrize("name", PRIVATE_FILES)
async def test_amis_dev_files_not_leak_content(amis_app, name):
    """开发文件的正文也不应出现在响应里。"""
    _, response = await amis_app.test_client.get(f"/amis/{name}")
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
async def test_amis_pages_still_served(amis_app, path):
    """挡开发文件不能误伤正常页面。"""
    _, response = await amis_app.test_client.get(path)
    assert response.status_code == 200, f"{path} 返回 {response.status_code}"


async def test_amis_index_serves_login_page(amis_app):
    """/amis/ 应显示登录页（与 v0.2.0 行为一致）。"""
    _, response = await amis_app.test_client.get("/amis/")
    assert response.status_code == 200
    assert "login" in response.text.lower()


# ---------------------------------------------------------------------------
# L2：含空字节的路径不应 500
# ---------------------------------------------------------------------------

async def test_amis_null_byte_path_is_client_error(amis_app):
    """``/amis/%00`` 曾因空字节拼磁盘路径抛 ValueError 而 500，应改为 4xx。"""
    _, response = await amis_app.test_client.get("/amis/%00")
    assert response.status_code in (400, 404), (
        f"/amis/%00 返回 {response.status_code}，应是 4xx 而不是 5xx"
    )


async def test_null_byte_path_never_5xx(amis_app):
    """任何路径都不应因空字节变成 5xx。"""
    for path in ("/amis/%00", "/%00", "/api/v1/accounts/%00"):
        _, response = await amis_app.test_client.get(path)
        assert response.status_code < 500, (
            f"{path} 返回 {response.status_code}，不应是 5xx"
        )


# ---------------------------------------------------------------------------
# L4：405 响应带 Allow 头
# ---------------------------------------------------------------------------

async def test_405_response_has_allow_header(amis_app):
    """方法不匹配时应返回 405 并带 Allow 头。"""
    _, response = await amis_app.test_client.request(
        "PUT", "/api/v1/roles", json={}
    )
    assert response.status_code == 405, f"期望 405，实际 {response.status_code}"
    allow = response.headers.get("allow")
    assert allow, "405 响应缺少 Allow 头（RFC 9110 要求）"


async def test_allow_header_lists_actual_methods(amis_app):
    """Allow 头应包含该 URI 实际支持的方法。"""
    _, response = await amis_app.test_client.request(
        "PATCH", "/api/v1/roles", json={}
    )
    assert response.status_code == 405
    allow = response.headers.get("allow", "")
    methods = {m.strip() for m in allow.split(",") if m.strip()}
    assert "GET" in methods, f"Allow 头 {allow!r} 应包含 GET"
    assert "POST" in methods, f"Allow 头 {allow!r} 应包含 POST"
    assert "PATCH" not in methods, f"Allow 头 {allow!r} 不应包含实际不支持的 PATCH"
