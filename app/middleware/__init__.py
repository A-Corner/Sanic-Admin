#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
中间件模块，提供请求处理过程中的拦截和处理功能

原 ``app/middleware.py`` 被本包同名遮蔽（Python 优先导入包），其内容已拆分迁入
``auth_middleware`` / ``error_handler`` / ``security_middleware`` 并删除原文件。
"""

import time

from sanic import Request, Sanic
from sanic.log import logger

from app.middleware.auth_middleware import AuthMiddleware
from app.middleware.error_handler import setup_error_handlers
from app.middleware.security_middleware import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    issue_csrf_token,
    setup_security_middleware,
)

__all__ = [
    "register_all_middlewares",
    "AuthMiddleware",
    "issue_csrf_token",
    "CSRF_COOKIE_NAME",
    "CSRF_HEADER_NAME",
]


def _setup_request_logging(app: Sanic) -> None:
    @app.middleware('request')
    async def log_request(request: Request):
        request.ctx.start_time = time.time()
        logger.debug(f"接收到请求: {request.method} {request.path}")

    @app.middleware('response')
    async def log_response(request: Request, response):
        if hasattr(request.ctx, 'start_time'):
            elapsed = time.time() - request.ctx.start_time
            logger.debug(f"请求完成: {request.method} {request.path} - {response.status} - {elapsed:.4f}s")


#: 应用级认证/强制改密中间件的优先级（高于蓝图中间件默认的 0）。
AUTH_MIDDLEWARE_PRIORITY = 100


def register_all_middlewares(app: Sanic) -> None:
    """
    注册所有中间件

    Args:
        app: Sanic应用实例
    """
    setup_error_handlers(app)
    setup_security_middleware(app)
    _setup_request_logging(app)
    # 显式 priority：Sanic 中数值大者先执行。强制改密检查必须先于 /api 蓝图组
    # 中间件（默认 priority=0，见 app/api/__init__.py），避免执行顺序随 app 实例
    # 注册先后而变（2FA 未完成的强制改密会话在 /api 上稳定得到 403）。
    app.middleware('request', priority=AUTH_MIDDLEWARE_PRIORITY)(AuthMiddleware())

    # 上传目录不再静态托管，文件下载走 /api/v1/files/<id>/download（自带鉴权），
    # 下载计数由该资源内部维护，不再需要全局下载计数中间件。

    logger.info("所有中间件注册完成")
