#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
中间件模块，提供请求处理中间件，包括认证、授权和异常处理
"""

import traceback
import time
import json
from functools import wraps
from sanic import Sanic, Request, response
from sanic.log import logger
from sanic.exceptions import SanicException
from app.services.exceptions import BaseError, AuthenticationError, AuthorizationError
from app.models import Session


async def authenticate_request(request: Request):
    """
    从请求中获取认证信息
    
    从请求头或Cookie中提取认证信息，查找对应的会话，并将其附加到请求上下文
    
    Args:
        request: Sanic请求对象
        
    Returns:
        None
    """
    # 从Authorization头或Cookie获取会话ID
    session_id = None
    auth_header = request.headers.get('Authorization')
    
    # 尝试从Authorization头中获取Bearer令牌
    if auth_header and auth_header.startswith('Bearer '):
        session_id = auth_header.split('Bearer ')[1]
    
    # 如果Authorization头中没有令牌，尝试从Cookie中获取
    if not session_id and request.cookies and 'session_id' in request.cookies:
        session_id = request.cookies.get('session_id')
    
    # 如果找到了会话ID，查找对应的会话
    if session_id:
        try:
            # 查找会话并检查是否有效
            session = await Session.get_valid_session(session_id)
            
            if session:
                # 将会话附加到请求上下文
                request.ctx.authentication_session = session
        except Exception as e:
            logger.error(f"认证处理时出错: {str(e)}")
            # 认证错误不应该中断请求处理，而是让视图函数决定如何处理


def register_authentication_middleware(app: Sanic):
    """
    注册认证中间件
    
    Args:
        app: Sanic应用实例
    """
    @app.middleware('request')
    async def authentication_middleware(request: Request):
        """
        认证中间件，在请求处理前尝试进行用户认证
        """
        await authenticate_request(request)


def register_error_middleware(app: Sanic):
    """
    注册错误处理中间件
    
    Args:
        app: Sanic应用实例
    """
    @app.exception(BaseError)
    async def handle_custom_exception(request: Request, exception: BaseError):
        """
        处理自定义异常
        """
        return response.json(
            exception.to_dict(),
            status=exception.status_code
        )
    
    @app.exception(SanicException)
    async def handle_sanic_exception(request: Request, exception: SanicException):
        """
        处理Sanic框架异常
        """
        status_code = getattr(exception, 'status_code', 500)
        message = str(exception)
        
        error_dict = {
            "error": "SANIC_ERROR",
            "message": message,
            "status": status_code
        }
        
        return response.json(error_dict, status=status_code)
    
    @app.exception(Exception)
    async def handle_generic_exception(request: Request, exception: Exception):
        """
        处理未捕获的异常
        """
        # 记录详细的错误信息到日志
        logger.error(f"未处理的异常: {str(exception)}")
        logger.error(traceback.format_exc())
        
        error_dict = {
            "error": "INTERNAL_ERROR",
            "message": "服务器内部错误",
            "status": 500
        }
        
        # 在开发环境中提供更详细的错误信息
        if app.config.DEBUG:
            error_dict["detail"] = str(exception)
            error_dict["traceback"] = traceback.format_exc()
        
        return response.json(error_dict, status=500)


def register_logging_middleware(app: Sanic):
    """
    注册日志中间件
    
    Args:
        app: Sanic应用实例
    """
    @app.middleware('request')
    async def log_request(request: Request):
        """
        记录请求信息
        """
        request.ctx.start_time = time.time()
        logger.debug(f"接收到请求: {request.method} {request.path}")
    
    @app.middleware('response')
    async def log_response(request: Request, response):
        """
        记录响应信息
        """
        if hasattr(request.ctx, 'start_time'):
            elapsed = time.time() - request.ctx.start_time
            logger.debug(f"请求完成: {request.method} {request.path} - {response.status} - {elapsed:.4f}s")


def register_cors_middleware(app: Sanic):
    """
    注册CORS中间件
    
    Args:
        app: Sanic应用实例
    """
    @app.middleware('response')
    async def add_cors_headers(request: Request, response):
        """
        添加CORS头
        """
        response.headers.update({
            'Access-Control-Allow-Origin': app.config.CORS_ORIGIN,
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Credentials': 'true'
        })


def register_all_middlewares(app: Sanic):
    """
    注册所有中间件
    
    Args:
        app: Sanic应用实例
    """
    register_authentication_middleware(app)
    register_error_middleware(app)
    register_logging_middleware(app)
    register_cors_middleware(app)
    
    # 添加OPTIONS请求处理
    @app.route('/<path:path>', methods=['OPTIONS'])
    async def handle_options(request: Request, path):
        return response.empty(status=204)


def csrf_protect():
    """
    CSRF保护装饰器
    
    要求在非GET请求中验证CSRF令牌
    
    Returns:
        装饰器函数
    """
    def decorator(handler):
        @wraps(handler)
        async def wrapper(request, *args, **kwargs):
            # 对GET请求不进行CSRF检查
            if request.method == 'GET':
                return await handler(request, *args, **kwargs)
            
            # 从请求头获取CSRF令牌
            csrf_token = request.headers.get('X-CSRF-Token')
            
            # 从cookie中获取存储的CSRF令牌
            stored_token = request.cookies.get('csrf_token')
            
            # 验证CSRF令牌
            if not csrf_token or not stored_token or csrf_token != stored_token:
                return response.json(
                    {
                        "error": "CSRF_ERROR",
                        "message": "CSRF验证失败",
                        "status": 403
                    },
                    status=403
                )
            
            return await handler(request, *args, **kwargs)
        
        return wrapper
    
    return decorator 