#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
认证路由模块，定义所有认证相关的路由
"""
from sanic import Blueprint
from app.config import settings
from app.models import CaptchaSession, AuthenticationSession
from app.services.utils import json
from app.auth.authentication import (
    login,
    register,
    requires_authentication,
    logout,
    fulfill_second_factor,
    get_session_token,
)
from app.auth.rate_limit import LoginRateLimiter, client_ip
from app.auth.verification import (
    request_two_step_verification,
    verify_account,
    request_captcha,
)
from app.middleware.security_middleware import issue_csrf_token
from app.services.exceptions import CredentialsError


# 创建认证相关蓝图
auth_bp = Blueprint('auth', url_prefix='/auth')
capt_bp = Blueprint('capt', url_prefix='/capt')
two_step_bp = Blueprint('two-step', url_prefix='/two-step')
role_bp = Blueprint('roles', url_prefix='/roles')
account_bp = Blueprint('account', url_prefix='/account')


def _delivery_code(request, code: str):
    """
    验证码只应通过邮件/短信/图片送达用户本人，不能出现在 API 响应里。
    本项目尚未接入投递渠道：仅 DEBUG/测试环境把验证码放进响应体，方便联调；
    其他环境不返回（客户端拿不到验证码，相关流程需先接入投递渠道）。
    """
    return code if request.app.config.get("DEBUG") else None


# 认证路由
@auth_bp.post("/")
@requires_authentication()
async def on_authenticate(request):
    """
    认证客户端会话和账户
    """
    response = json(
        "认证成功!",
        request.ctx.authentication_session.bearer.json
    )
    request.ctx.authentication_session.encode(response)
    return response


# 注册路由
@auth_bp.post("/register")
async def on_register(request):
    """
    使用电子邮件和密码注册账户
    """
    account = await register(request)

    two_step_session = await request_two_step_verification(request, account)
    response = json(
        "注册成功! 需要验证。",
        _delivery_code(request, two_step_session.code)
    )
    two_step_session.encode(response)
    return response


# 验证账户路由
@auth_bp.post("/verify")
async def on_verify(request):
    """
    验证客户端账户
    """
    two_step_session = await verify_account(request)
    return json(
        "您的账户已验证，现在可以登录!",
        two_step_session.bearer.json
    )


# 登录路由
@auth_bp.post("/login")
async def on_login(request):
    """
    使用电子邮件和密码登录
    """
    # 登录限流：按（提交的用户名/邮箱 + IP）维度限制失败次数。
    # 只在 cache 可用时启用（before_server_start 已初始化 app.ctx.cache）；
    # 未提交登录标识时跳过（参数校验会以 400 拒绝，不属于暴力破解面）。
    limiter = LoginRateLimiter.from_request(request)
    identity = limiter.submitted_identity(request)
    ip = client_ip(request)
    if identity:
        await limiter.raise_if_blocked(identity, ip)

    # 是否启用二次验证只由服务端配置决定，忽略客户端参数
    two_factor_authentication = bool(getattr(settings, "REQUIRE_TWO_FACTOR", False))
    try:
        authentication_session = await login(
            request, require_second_factor=two_factor_authentication
        )
    except CredentialsError:
        # 仅凭据错误计入失败次数（未验证/禁用等账户状态问题不属于口令猜测）
        if identity:
            await limiter.record_failure(identity, ip)
        raise

    # 成功登录清零该维度的失败计数
    if identity:
        await limiter.clear(identity, ip)

    if two_factor_authentication:
        two_step_session = await request_two_step_verification(
            request, authentication_session.bearer
        )
        response = json(
            "登录成功! 需要两步验证。",
            _delivery_code(request, two_step_session.code),
        )
        two_step_session.encode(response)
    else:
        response = json("登录成功!", authentication_session.bearer.json)

    authentication_session.encode(response)
    # 下发 CSRF token（双提交 cookie + 响应头），此后凭会话 cookie 的写请求须回传
    # X-CSRF-Token 头（见 app/middleware/security_middleware.py 的 enforce_csrf）。
    issue_csrf_token(
        response,
        secure=bool(request.app.config.get("SESSION_COOKIE_SECURE", True)),
    )
    return response


# 完成两步验证路由
@auth_bp.post("/validate-2fa")
async def on_two_factor_authentication(request):
    """
    完成客户端认证会话的二次验证
    """
    authentication_session = await fulfill_second_factor(request)
    response = json(
        "两步验证已完成! 您现在已通过验证。",
        authentication_session.bearer.json,
    )
    authentication_session.encode(response)
    return response


# 注销路由
@auth_bp.post("/logout")
async def on_logout(request):
    """
    注销当前登录的账户
    """
    authentication_session = await logout(request)
    return json("注销成功!", authentication_session.bearer.json)


# 获取关联认证会话路由
@auth_bp.post("/associated")
@requires_authentication()
async def on_get_associated_authentication_sessions(request):
    """
    获取与已登录账户关联的认证会话
    """
    authentication_sessions = await AuthenticationSession.get_associated(
        request.ctx.authentication_session.bearer
    )
    return json(
        "已获取关联的认证会话!",
        [auth_session.json for auth_session in authentication_sessions],
    )


# 请求验证码路由
@capt_bp.get("/request")
async def on_captcha_request(request):
    """
    请求验证码
    """
    captcha_session = await request_captcha(request)
    response = json("验证码请求成功!", _delivery_code(request, captcha_session.code))
    captcha_session.encode(response)
    return response


# 请求验证码图像路由
@capt_bp.get("/image")
async def on_captcha_image(request):
    """
    请求验证码图像
    """
    captcha_session = await CaptchaSession.decode(
        get_session_token(request, CaptchaSession.cookie_name, CaptchaSession.header_name)
    )
    return await captcha_session.generate_image()