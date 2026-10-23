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

    if not session_id and request.cookies:
        # Cookie 名以会话模型实际下发的为准（Session.encode 使用 cookie_name）
        from app.models import AuthenticationSession
        session_id = request.cookies.get(AuthenticationSession.cookie_name)

    if not session_id:
        return

    try:
        # 延迟导入，避免中间件包与模型包循环依赖
        from app.models import Session

        session = await Session.get_valid_session(session_id)
        if session:
            request.ctx.authentication_session = session
    except Exception as e:
        logger.error(f"认证处理时出错: {str(e)}")


#: 强制改密拦截的白名单：改密、登出、登录（改密后重登）、会话信息查询。
#: 拦截面限定在 /api/ 前缀——保护对象是数据面 API；管理台静态页不拦，
#: 用户仍能打开页面并在 AMIS 里看到 403 提示后走改密对话框。


async def enforce_password_change(request: Request) -> None:
    """
    首次登录强制改密：must_change_password=True 的会话访问 /api/ 下非白名单
    路径时返回 403 PASSWORD_CHANGE_REQUIRED，直至完成改密。
    """
    session = getattr(request.ctx, "authentication_session", None)
    if session is None:
        return
    bearer = session.bearer
    if bearer is None or not getattr(bearer, "must_change_password", False):
        return
    path = request.path
    if not path.startswith("/api/"):
        return
    from sanic.exceptions import SanicException

    # 由全局错误处理器渲染为统一信封（error=PASSWORD_CHANGE_REQUIRED，403）
    raise SanicException("首次登录必须修改密码", status_code=403)


class AuthMiddleware:
    """可调用的请求中间件：会话提取 + 首次登录强制改密拦截。"""

    async def __call__(self, request: Request) -> None:
        await authenticate_request(request)
        await enforce_password_change(request)
