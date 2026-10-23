#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
请求体上限配置（v0.3 P1 任务 B）。

背景：``app/config.py`` 原有的 ``MAX_CONTENT_LENGTH = 16MB`` 是 Flask 风格的
名字，Sanic 23.6 **从不读取它**（Sanic 实际读取 ``REQUEST_MAX_SIZE``，默认
100MB）。本次把误导性配置移除，改为 Sanic 真实读取的 ``REQUEST_MAX_SIZE``。

超限行为的**真实服务实测**（POST >16MB body）不放在这里：
``httpx.ASGITransport`` 不经过 Sanic 的 HttpProtocol/Http1 连接层
（``sanic/asgi.py`` 完全不引用 ``request_max_size``），ASGI 客户端发多大的
body 都不会触发 ``PayloadTooLarge`` —— 在这里写超限断言就是假断言。
超限实测证据（响应码/响应体）记录在本 lane 的验证报告中。

这里只做两件能在 ASGI 层真实断言的事：

1. ``REQUEST_MAX_SIZE`` 已通过 ``create_app`` 注入 ``app.config``
   （正例断言；这是 Sanic 协议层读取的唯一入口）；
2. 误导性的 ``MAX_CONTENT_LENGTH`` 已从配置类中移除（防止回归）。
"""
import pytest

#: 与 app/config.py 中的定义一致
REQUEST_MAX_SIZE = 16 * 1024 * 1024


async def test_request_max_size_injected_into_app_config(app):
    """create_app 后 app.config 里必须有 Sanic 真实读取的 REQUEST_MAX_SIZE。"""
    assert app.config.REQUEST_MAX_SIZE == REQUEST_MAX_SIZE, (
        f"app.config.REQUEST_MAX_SIZE = {app.config.REQUEST_MAX_SIZE!r}，"
        f"应为 {REQUEST_MAX_SIZE}（16MB）"
    )


async def test_request_max_size_present_in_all_env_configs():
    """三个环境的配置类都必须带 REQUEST_MAX_SIZE（继承自 DefaultConfig）。"""
    from app.config import DevelopmentConfig, ProductionConfig, TestingConfig

    for cls in (DevelopmentConfig, TestingConfig, ProductionConfig):
        value = getattr(cls, "REQUEST_MAX_SIZE", None)
        assert value == REQUEST_MAX_SIZE, (
            f"{cls.__name__}.REQUEST_MAX_SIZE = {value!r}，应为 {REQUEST_MAX_SIZE}"
        )


async def test_misleading_max_content_length_removed():
    """从未被 Sanic 读取的 MAX_CONTENT_LENGTH 必须保持移除状态。"""
    from app.config import DefaultConfig

    assert not hasattr(DefaultConfig, "MAX_CONTENT_LENGTH"), (
        "MAX_CONTENT_LENGTH 已被证实从未被 Sanic 23.6 读取，"
        "不应重新出现在配置类里误导读者"
    )


async def test_payload_too_large_rendered_in_unified_format(app, client):
    """413 经统一错误处理渲染为 {"error": "PAYLOAD_TOO_LARGE"} 的 JSON。

    这测的是 app/middleware/error_handler.py 对 PayloadTooLarge 的映射（真实服务
    实测中，超限请求正是走到这个 handler，见本 lane 验证报告），不是在 ASGI 层
    伪造连接层的超限行为 —— 连接层的 REQUEST_MAX_SIZE 强制只存在于 Sanic 的
    HttpProtocol/Http1，ASGITransport 不经过它。
    """
    from sanic.exceptions import PayloadTooLarge

    @app.route("/__test_payload_too_large", methods=["POST"])
    async def boom(request):
        raise PayloadTooLarge("Request body exceeds the size limit")

    response = await client.post("/__test_payload_too_large", json={"x": 1})
    assert response.status_code == 413, (
        f"PayloadTooLarge 应渲染为 413，实际 {response.status_code}"
    )
    body = response.json()
    assert body["success"] is False
    assert body["error"] == "PAYLOAD_TOO_LARGE", (
        f"413 应映射为 PAYLOAD_TOO_LARGE，实际 {body.get('error')!r}"
    )
    assert "请求体" in body["message"], f"413 文案应说明是请求体过大，实际 {body.get('message')!r}"
