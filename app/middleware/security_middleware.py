#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
安全相关中间件：CORS、OPTIONS 预检处理（请求中间件）、CSRF 保护装饰器。

由原 ``app/middleware.py`` 的 CORS / OPTIONS / csrf_protect 迁入。
CORS 来源取自 ``CORS_ALLOWED_ORIGINS`` 配置：命中白名单时回显 Origin；白名单含 "*" 时返回 "*"
且不发送 Allow-Credentials（"*" 与 credentials 同时使用违反规范）。
"""

from functools import wraps

from sanic import Request, Sanic, response


def setup_security_middleware(app: Sanic) -> None:
    @app.middleware('response')
    async def add_cors_headers(request: Request, resp):
        allowed = app.config.get('CORS_ALLOWED_ORIGINS') or []
        origin = request.headers.get('Origin')
        headers = {}
        if '*' in allowed:
            headers['Access-Control-Allow-Origin'] = '*'
        elif origin and origin in allowed:
            headers['Access-Control-Allow-Origin'] = origin
            headers['Access-Control-Allow-Credentials'] = 'true'
            headers['Vary'] = 'Origin'
        if headers:
            headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
            headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            resp.headers.update(headers)

    @app.middleware('request')
    async def handle_preflight(request: Request):
        # 用请求中间件而非通配路由处理 OPTIONS，避免未知路径返回 405 而非 404
        if request.method == 'OPTIONS':
            return response.empty(status=204)


def csrf_protect():
    """CSRF 保护装饰器：非 GET 请求要求 X-CSRF-Token 头与 csrf_token cookie 一致。"""
    def decorator(handler):
        @wraps(handler)
        async def wrapper(request, *args, **kwargs):
            if request.method == 'GET':
                return await handler(request, *args, **kwargs)
            csrf_token = request.headers.get('X-CSRF-Token')
            stored_token = request.cookies.get('csrf_token')
            if not csrf_token or not stored_token or csrf_token != stored_token:
                return response.json(
                    {"error": "CSRF_ERROR", "message": "CSRF验证失败", "status": 403},
                    status=403,
                )
            return await handler(request, *args, **kwargs)
        return wrapper
    return decorator
