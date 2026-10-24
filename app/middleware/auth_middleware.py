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
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        session_id = auth_header.split("Bearer ", 1)[1]

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


#: 强制改密默认拦截**全部**路径（fail-closed：/auth/associated 等会话信息
#: 端点若漏拦会被用来侧探账户状态），仅放行完成改密与基本导航所必需的
#: 白名单：认证流程（login/logout/change-password）、管理台静态页（/amis）、
#: 健康检查与 API 文档。


#: 强制改密白名单（前缀匹配）：完成改密与基本导航所必需的最小集合。
PASSWORD_CHANGE_EXEMPT_PREFIXES = (
    "/auth/login",
    "/auth/logout",
    "/auth/change-password",
    # 2FA 流程：get_valid_session 不区分二次验证是否完成，标志为 True 的用户
    # 必须能先完成 2FA（拿到已验证会话）才能调用 change-password
    "/auth/validate-2fa",
    "/amis",
    "/health",
    "/static",
    "/docs",
    "/redoc",
    "/swagger",
    "/favicon",
)


async def enforce_password_change(request: Request) -> None:
    """
    首次登录强制改密：``must_change_password=True`` 的会话访问非豁免路径时返回
    403 ``PASSWORD_CHANGE_REQUIRED``，直至完成改密。

    **豁免机制的真实形态**（此前的注释写成「白名单放行 login/logout/...」，
    容易被读成有一份覆盖全部认证端点的显式清单，实际是靠
    :data:`PASSWORD_CHANGE_EXEMPT_PREFIXES` 做的前缀匹配）：

    * 命中豁免前缀之一 → 放行；
    * 其余**一律拦截**（fail-closed），不区分路径是否在 ``/api/`` 下。

    因此有一条部署约定必须守住：**数据面端点必须全部挂在 ``/api/`` 前缀下**。
    前缀豁免只覆盖认证流程与静态页，若将来有新数据端点挂到其它前缀，它不会被
    「数据面白名单」拦下——本函数仍是 fail-closed 的，但审计与限流这类按
    ``/api/`` 前置判断的逻辑会漏掉它。
    """
    session = getattr(request.ctx, "authentication_session", None)
    if session is None:
        return
    bearer = session.bearer
    if bearer is None or not getattr(bearer, "must_change_password", False):
        return
    path = request.path
    for prefix in PASSWORD_CHANGE_EXEMPT_PREFIXES:
        if path == prefix or path.startswith(prefix + "/") or path.startswith(prefix + "."):
            return
    from app.services.exceptions import PasswordChangeRequiredError

    raise PasswordChangeRequiredError()


class AuthMiddleware:
    """可调用的请求中间件：会话提取 + 首次登录强制改密拦截。"""

    async def __call__(self, request: Request) -> None:
        await authenticate_request(request)
        await enforce_password_change(request)
