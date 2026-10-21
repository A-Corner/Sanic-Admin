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
from app.middleware.security_middleware import setup_security_middleware, csrf_protect

__all__ = ["register_all_middlewares", "AuthMiddleware", "csrf_protect"]


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


def register_all_middlewares(app: Sanic) -> None:
    """
    注册所有中间件

    Args:
        app: Sanic应用实例
    """
    setup_error_handlers(app)
    setup_security_middleware(app)
    _setup_request_logging(app)
    app.middleware('request')(AuthMiddleware())

    # 文件下载计数中间件属于 app.api.resources.upload（B1d 负责修复），缺失时降级
    try:
        from app.api.resources.upload import FileDownloadCounterMiddleware
        app.middleware('request')(FileDownloadCounterMiddleware())
    except Exception as e:
        if app.config.get("ENV") == "production":
            from app.config import ConfigError
            raise ConfigError(f"生产环境拒绝降级启动：文件下载计数中间件不可用（待 B1d 修复）: {e!r}") from e
        logger.warning(f"[降级] 文件下载计数中间件未启用（app.api.resources.upload 不可用，待 B1d 修复）: {e!r}")

    logger.info("所有中间件注册完成")
