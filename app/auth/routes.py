#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
认证路由模块，定义所有认证相关的路由
"""
from argon2 import PasswordHasher
from sanic import Blueprint
from app.models import Account, CaptchaSession, AuthenticationSession
from app.services.utils import json
from app.auth.authentication import (
    login,
    register,
    requires_authentication,
    logout,
    fulfill_second_factor,
)
from app.auth.authorization import (
    assign_role,
    check_permissions,
    check_roles,
)
from app.auth.verification import (
    request_two_step_verification,
    requires_two_step_verification,
    verify_account,
    request_captcha,
    requires_captcha,
)


# 创建认证相关蓝图
auth_bp = Blueprint('auth', url_prefix='/auth')
capt_bp = Blueprint('capt', url_prefix='/capt')
two_step_bp = Blueprint('two-step', url_prefix='/two-step')
role_bp = Blueprint('roles', url_prefix='/roles')
account_bp = Blueprint('account', url_prefix='/account')


# 密码哈希工具
password_hasher = PasswordHasher()


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
    account = await register(
        request,
        verified=request.form.get("verified") == "true",
        disabled=request.form.get("disabled") == "true",
    )
    
    if not account.verified:
        two_step_session = await request_two_step_verification(request, account)
        response = json(
            "注册成功! 需要验证。",
            two_step_session.code
        )
        two_step_session.encode(response)
    else:
        response = json("注册成功!", account.json)
    
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
    two_factor_authentication = request.args.get("two-factor-authentication") == "true"
    authentication_session = await login(
        request, require_second_factor=two_factor_authentication
    )
    
    if two_factor_authentication:
        two_step_session = await request_two_step_verification(
            request, authentication_session.bearer
        )
        response = json(
            "登录成功! 需要两步验证。",
            two_step_session.code,
        )
        two_step_session.encode(response)
    else:
        response = json("登录成功!", authentication_session.bearer.json)
    
    authentication_session.encode(response)
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
@requires_authentication
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
    response = json("验证码请求成功!", captcha_session.code)
    captcha_session.encode(response)
    return response


# 请求验证码图像路由
@capt_bp.get("/image")
async def on_captcha_image(request):
    """
    请求验证码图像
    """
    captcha_session = await CaptchaSession.decode(
        request.cookies.get("session") or request.token
    )
    
    if not captcha_session:
        return json("无效的验证码会话", status=400)
    
    return await captcha_session.generate_image()