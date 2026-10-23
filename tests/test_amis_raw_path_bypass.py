#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
AMIS 原始路径绕过测试（P5 F2 回归通道）。

背景：conftest 的 httpx 客户端在**构造 URL 时就把 dot-segment 规范化**，
``client.get("/amis/./server.js")`` 到达应用的已经是 ``/amis/server.js``——
常规通道永远测不到原始路径，这是 F1（dot-segment 绕过）当初漏测的根因。

本文件绕开 httpx，手工构造 ASGI scope（``path``/``raw_path`` 保留原始
dot-segment）直发应用，测的就是路由层看到的原始字符串。

诊断/复现工具：``editor-a/tmp/repro_f1.py``（http.client 原样发请求行）。
"""

import json

import pytest

#: F1 复现矩阵：原始路径含 dot-segment，规范化后都指向黑名单文件
DOT_SEGMENT_BYPASS_PATHS = [
    "/amis/./server.js",
    "/amis/pages/../server.js",
    "/amis/./SERVER.JS",
    "/amis/css/../server.js",
    "/amis/./package.json",
    "/amis/js/../nodemon.json",
    "/amis/./README.md",
    "/amis/images/../package-lock.json",
]


async def _raw_asgi_get(app, path):
    """绕过 httpx 的 URL 规范化，按原始 path 直发 ASGI scope。

    用 sanic-testing 自己的 ``TestASGIApp`` 驱动（与 client 夹具同一通道），
    唯一区别是 scope 里的 path 保留原始 dot-segment。
    """
    from sanic_testing.testing import TestASGIApp

    state = {"status": None, "headers": {}, "body": b""}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            state["status"] = message["status"]
            state["headers"] = {
                k.decode().lower(): v.decode() for k, v in message.get("headers", [])
            }
        elif message["type"] == "http.response.body":
            state["body"] += message.get("body", b"")

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"testserver"), (b"accept", b"*/*")],
        "client": ("127.0.0.1", 54321),
        "server": ("127.0.0.1", 80),
    }
    app.asgi = True
    asgi_app = await TestASGIApp.create(app, scope, receive, send)
    await asgi_app()
    return state["status"], state["body"]


@pytest.mark.parametrize("path", DOT_SEGMENT_BYPASS_PATHS)
async def test_dot_segment_bypass_cannot_reach_dev_files(app, path):
    """原始路径带 dot-segment 也必须 404：黑名单以规范化后的文件为准。"""
    status, body = await _raw_asgi_get(app, path)
    assert status == 404, (
        f"GET {path}（原始路径）返回 {status}，应 404；body 前 80 字节: {body[:80]!r}"
    )


@pytest.mark.parametrize("path", [
    "/amis/login.html",
    "/amis/css/main.css",
    "/amis/public/logo.png",
])
async def test_dot_segment_normal_files_still_served(app, path):
    """正常文件在原始通道下不受影响（对照组）。"""
    status, body = await _raw_asgi_get(app, path)
    assert status == 200, f"GET {path}（原始路径）返回 {status}"


async def test_plain_dev_file_still_blocked_on_raw_channel(app):
    """对照组：不带 dot-segment 的开发文件在原始通道下同样 404。"""
    status, body = await _raw_asgi_get(app, "/amis/server.js")
    assert status == 404
    payload = json.loads(body)
    assert payload.get("success") is False
