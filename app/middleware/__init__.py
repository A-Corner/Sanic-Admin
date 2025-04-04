#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
中间件模块，提供请求处理过程中的拦截和处理功能
"""

from sanic import Sanic
from sanic.log import logger
from app.middleware.auth_middleware import AuthMiddleware
from app.middleware.error_handler import setup_error_handlers
from app.middleware.security_middleware import setup_security_middleware
from app.api.resources.upload import FileDownloadCounterMiddleware


def register_all_middlewares(app: Sanic) -> None:
    """
    注册所有中间件
    
    Args:
        app: Sanic应用实例
    """
    # 设置错误处理器
    setup_error_handlers(app)
    
    # 设置安全中间件
    setup_security_middleware(app)
    
    # 认证中间件
    auth_middleware = AuthMiddleware()
    app.middleware('request')(auth_middleware)
    
    # 文件下载计数中间件
    file_download_counter = FileDownloadCounterMiddleware()
    app.middleware('request')(file_download_counter)
    
    logger.info("所有中间件注册完成") 