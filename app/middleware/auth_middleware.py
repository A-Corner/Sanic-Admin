#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
认证中间件：从请求中提取会话并附加到 request.ctx.authentication_session。

由原 ``app/middleware.py`` 的 ``authenticate_request`` 迁入。
"""

from sanic import Request
from sanic.log import logger


async def authenticate_request(request: Request) -> None:
    """
    从 Authorization 头（Bearer）或 Cookie 中提取会话 ID，查找有效会话并附加到请求上下文。
    认证失败不中断请求，由视图函数决定如何处理。
    """
    session_id = None
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        session_id = auth_header.split('Bearer ', 1)[1]

    if not session_id and request.cookies and 'session_id' in request.cookies:
        session_id = request.cookies.get('session_id')

    if not session_id:
        return

    try:
        # 延迟导入：app.models 由后续批次（B1b）补齐，缺失时只影响认证，不影响启动
        from app.models import Session

        session = await Session.get_valid_session(session_id)
        if session:
            request.ctx.authentication_session = session
    except Exception as e:
        logger.error(f"认证处理时出错: {str(e)}")


class AuthMiddleware:
    """可调用的请求中间件，包装 authenticate_request。"""

    async def __call__(self, request: Request) -> None:
        await authenticate_request(request)
