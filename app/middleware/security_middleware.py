#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
安全相关中间件：CORS、OPTIONS 预检处理、CSRF 保护（双提交 cookie）。

由原 ``app/middleware.py`` 的 CORS / OPTIONS / csrf_protect 迁入。
CORS 来源取自 ``CORS_ALLOWED_ORIGINS`` 配置：命中白名单时回显 Origin；白名单含 "*" 时返回 "*"
且不发送 Allow-Credentials（"*" 与 credentials 同时使用违反规范）。

CSRF 采用双提交 cookie（double-submit cookie）：登录成功时下发独立 ``csrf_token``
cookie（非 HttpOnly，SameSite=Lax）并在 ``X-CSRF-Token`` 响应头返回同值；此后所有
携带会话 cookie 的写请求（非 GET/HEAD/OPTIONS）必须让 ``X-CSRF-Token`` 请求头与
cookie 值一致，否则 403。

防线定位：会话 cookie 已是 SameSite=Lax（app/config.py），本机制是纵深防御增量，
主要覆盖 Lax 挡不住的跨站顶级 POST 提交场景。

适用范围判定（按 CSRF 威胁模型收窄，避免误伤）：

* 只约束**写方法**——CSRF 攻击只能伪造写请求；
* 只约束**凭会话 cookie 认证的请求**——不带 ``session`` cookie 的请求没有
  可被 CSRF 利用的浏览器自动携带凭据（未认证请求由认证层返回 401/403）；
* 带显式 ``Authorization`` 头的请求豁免——跨站攻击者无法让浏览器携带自定义
  请求头（需 CORS 预检通过），此类请求天然免疫 CSRF；
* 登录前端点（/auth/login、/auth/register）豁免——此时还没有 csrf token。
"""

import secrets

from sanic import Request, Sanic, response

from app.middleware._headers import append_vary

#: 双提交 cookie 与请求头名称（与前端 amis/index.html 保持一致）
CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"

#: CSRF 校验的豁免路径前缀：登录前尚无 token 可校验
CSRF_EXEMPT_PREFIXES = ("/auth/login", "/auth/register")

#: 会话 cookie 名称。与 ``AuthenticationSession.cookie_name`` 同值；
#: 由 tests/test_csrf.py 的一致性用例守护，改名时两处必须同步。
SESSION_COOKIE_NAME = "session"


def issue_csrf_token(resp, secure: bool = False) -> str:
    """
    生成 CSRF token 并以双提交方式下发：写入 ``csrf_token`` cookie（非 HttpOnly，
    前端 JS 需读它回填请求头），同时在 ``X-CSRF-Token`` 响应头返回同值供非浏览器
    API 客户端使用。

    Args:
        resp: Sanic 响应对象
        secure: 是否加 Secure 标记（跟随会话 cookie 的环境配置）

    Returns:
        str: 本次下发的 token
    """
    token = secrets.token_urlsafe(32)
    resp.add_cookie(
        CSRF_COOKIE_NAME,
        token,
        httponly=False,
        secure=secure,
        samesite="Lax",
    )
    resp.headers[CSRF_HEADER_NAME] = token
    return token


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
        if '*' not in allowed:
            append_vary(resp.headers, 'Origin')  # 无论是否命中白名单，响应都随 Origin 变化
        if headers:
            headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-CSRF-Token'
            headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            resp.headers.update(headers)

    @app.middleware('request')
    async def handle_preflight(request: Request):
        # 用请求中间件而非通配路由处理 OPTIONS，避免未知路径返回 405 而非 404
        if request.method == 'OPTIONS':
            return response.empty(status=204)

    @app.middleware('request')
    async def enforce_csrf(request: Request):
        # 注册在 handle_preflight 之后：OPTIONS 预检已在上面短路返回 204。
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return None
        path = request.path
        if any(path == p or path.startswith(p + '/') for p in CSRF_EXEMPT_PREFIXES):
            return None
        # 只约束凭会话 cookie 认证的请求（CSRF 的唯一被利用面）；带显式
        # Authorization 头的客户端免疫 CSRF，无会话 cookie 的请求交由认证层处理。
        if request.headers.get('Authorization'):
            return None
        if not request.cookies.get(SESSION_COOKIE_NAME):
            return None

        cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
        header_token = request.headers.get(CSRF_HEADER_NAME)
        if (
            not cookie_token
            or not header_token
            or not secrets.compare_digest(header_token, cookie_token)
        ):
            return response.json(
                {
                    "success": False,
                    "message": "CSRF 验证失败，请刷新页面重新登录",
                    "error": "CSRF_TOKEN_INVALID",
                },
                status=403,
            )
        return None
