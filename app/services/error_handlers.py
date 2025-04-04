#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
错误处理器模块，定义全局异常处理器
"""
from sanic import Sanic
from sanic.log import logger
from sanic.exceptions import SanicException, NotFound, InvalidUsage, MethodNotSupported
from app.services.exceptions import SecurityError
from app.services.utils import json


def register_error_handlers(app: Sanic):
    """
    注册全局异常处理器
    
    Args:
        app: Sanic应用实例
    """
    
    @app.exception(SecurityError)
    async def on_security_error(request, exception):
        """
        处理安全错误
        """
        logger.error(f"安全错误: {exception}")
        return exception.json
    
    @app.exception(NotFound)
    async def on_not_found(request, exception):
        """
        处理404错误
        """
        return json("资源不存在", {"path": request.path}, status=404)
    
    @app.exception(InvalidUsage)
    async def on_invalid_usage(request, exception):
        """
        处理参数错误
        """
        return json("无效的请求参数", {"error": str(exception)}, status=400)
    
    @app.exception(MethodNotSupported)
    async def on_method_not_supported(request, exception):
        """
        处理不支持的HTTP方法
        """
        return json(
            "不支持的HTTP方法", 
            {
                "method": request.method,
                "supported_methods": exception.args[0]
            }, 
            status=405
        )
    
    @app.exception(SanicException)
    async def on_sanic_exception(request, exception):
        """
        处理Sanic异常
        """
        logger.error(f"Sanic异常: {exception}")
        return json("服务器错误", {"error": str(exception)}, status=500)
    
    @app.exception(Exception)
    async def on_general_exception(request, exception):
        """
        处理一般异常
        """
        logger.error(f"未处理的异常: {exception}", exc_info=True)
        return json("服务器内部错误", {"error": "内部服务器错误"}, status=500)