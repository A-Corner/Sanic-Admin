# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# File       : auth.py
# Time       ：13/9/2023 10:03 am
# Author     ：author A-Corner
# version    ：python 3.11
# Description：
"""
# This is a Python script for authentication and authorization.
# 这是一个用于身份验证和授权的Python脚本。

from argon2 import PasswordHasher  # Password hashing library 密码哈希库
from sanic import text, Blueprint  # Sanic framework libraries Sanic框架库
# Import various functions from the Sanic Security module  导入Sanic Security模块的各个功能
from authentication import (
    login,  # Login function 登录功能
    register,  # Registration function 注册功能
    requires_authentication,  # Decorator for requiring authentication 需要身份验证的装饰器
    logout,  # Logout function 注销功能
    fulfill_second_factor,  # Complete second-factor authentication 完成二次验证
)
from authorization import (
    assign_role,  # Assign a role 分配角色
    check_permissions,  # Check permissions 检查权限
    check_roles,  # Check roles 检查角色
)
from exceptions import CredentialsError  # Security-related exceptions 安全相关异常
# Database models 数据库模型
from models import Account, CaptchaSession, AuthenticationSession
from utils import json  # JSON utility JSON工具
from verification import (
    request_two_step_verification,  # Request two-step verification 请求两步验证
    # Decorator for requiring two-step verification 需要两步验证的装饰器
    requires_two_step_verification,
    verify_account,  # Verify an account 验证账户
    request_captcha,  # Request a captcha 请求验证码
    requires_captcha,  # Decorator for requiring a captcha 需要验证码的装饰器
)

auth_bp = Blueprint('auth', url_prefix='auth')
capt_bp = Blueprint('capt', url_prefix='capt')
two_step_bp = Blueprint('two-step', url_prefix='two-step')
role_bp = Blueprint('roles', url_prefix='roles')
account_bp = Blueprint('account', url_prefix='account')
password_hasher = PasswordHasher()


@auth_bp.post("/")
@requires_authentication()
async def on_authenticate(request):
    # Authentication route 身份验证路由
    """
    Authenticate client session and account.
    认证客户端会话和账户。
    """
    response = json("Authentication successful!",
                    request.ctx.authentication_session.bearer.json)
    request.ctx.authentication_session.encode(response)
    return response

# Registration route 注册账户路由


@auth_bp.post("/register")
async def on_register(request):
    """
    Register an account with email and password.
    使用电子邮件和密码注册账户。
    """
    # Call the registration function to create an account
    account = await register(
        request,
        # Whether verified 是否已验证
        verified=request.form.get("verified") == "true",
        # Whether disabled 是否已禁用
        disabled=request.form.get("disabled") == "true",
    )
    # If the account is not verified, request two-step verification
    if not account.verified:
        two_step_session = await request_two_step_verification(request, account)
        response = json(
            "Registration successful! Verification is required.",
            two_step_session.code
        )
        two_step_session.encode(response)
    else:
        response = json("Registration successful!", account.json)
    return response


# Account verification route 验证账户路由
@auth_bp.post("verify")
async def on_verify(request):
    """
    Verify the client account.
    验证客户端账户。
    """
    two_step_session = await verify_account(request)
    return json(
        "Your account has been verified, and you can now log in!",
        two_step_session.bearer.json
    )


# Login route 登录路由
@auth_bp.post("login")
async def on_login(request):
    """
    Log in with email and password.
    使用电子邮件和密码登录账户。
    """
    two_factor_authentication = request.args.get(
        "two-factor-authentication") == "true"  # Whether two-step authentication is required 是否需要两步验证
    authentication_session = await login(
        request, require_second_factor=two_factor_authentication
    )   # Call the login function 调用登录函数
    print(f"「Login Verification Result」-- > {authentication_session}")
    if two_factor_authentication:
        two_step_session = await request_two_step_verification(
            request, authentication_session.bearer
        )
        response = json(
            "Login successful! Two-step verification is required.",
            two_step_session.code,
        )
        two_step_session.encode(response)
    else:
        response = json("Login successful!",
                        authentication_session.bearer.json)
    authentication_session.encode(response)
    print(
        f"\n「Debug Output」{__name__} -- > {request.headers.get('Authorization')}")
    return response


# Two-step authentication completion route 完成二次验证路由
@auth_bp.post("validate-2fa")
async def on_two_factor_authentication(request):
    """
    Complete the second-factor requirement of the client authentication session.
    完成客户端认证会话的二次因素要求。
    """
    authentication_session = await fulfill_second_factor(request)
    response = json(
        "The second factor of the authentication session has been completed! You are now verified.",
        authentication_session.bearer.json,
    )
    authentication_session.encode(response)
    return response


# Logout route 注销路由
@auth_bp.post("logout")
async def on_logout(request):
    """
    Log out the currently logged-in account.
    注销当前登录的账户。
    """
    authentication_session = await logout(request)
    return json("Logout successful!", authentication_session.bearer.json)


# Get associated authentication sessions route 获取关联的认证会话路由
@auth_bp.post("associated")
@requires_authentication
async def on_get_associated_authentication_sessions(request):
    """
    Retrieve authentication sessions associated with the logged-in account.
    检索与已登录账户相关联的认证会话。
    """
    authentication_sessions = await AuthenticationSession.get_associated(
        request.ctx.authentication_session.bearer
    )
    return json(
        "Associated authentication sessions have been retrieved!",
        [auth_session.json for auth_session in authentication_sessions],
    )


# Request captcha route 请求验证码路由
@capt_bp.get("/capt/request")
async def on_captcha_request(request):
    """
    Request a captcha solution in the response.
    在响应中请求验证码解决方案。
    """
    captcha_session = await request_captcha(request)
    response = json("Captcha request successful!", captcha_session.code)
    captcha_session.encode(response)
    return response


# Request captcha image route 请求验证码图像路由
@capt_bp.get("/capt/image")
async def on_captcha_image(request):
    """
    Request a captcha image.
    请求验证码图像。
    """
    captcha_session = CaptchaSession()
    code = captcha_session.code
    response = captcha_session.get_image()
    captcha_session.encode(response)
    print(code)
    return response


# Captcha verification route 验证码路由
@capt_bp.post("/capt/")
@requires_captcha
async def on_captcha_attempt(request):
    """
    Attempt captcha verification.
    尝试验证码验证。
    """
    return json("Captcha successful!", request.ctx.captcha_session.json)


# Request two-step verification route 请求两步验证路由
@two_step_bp.post("request")
async def on_request_verification(request):
    """
    Request a two-step verification code in the response.
    在响应中请求两步验证代码。
    """
    two_step_session = await request_two_step_verification(request)
    response = json("Verification request successful!", two_step_session.code)
    two_step_session.encode(response)
    return response


# Attempt two-step verification challenge route 尝试两步验证挑战路由
@two_step_bp.post("/")
@requires_two_step_verification
async def on_verification_attempt(request):
    """
    Attempt a two-step verification challenge.
    尝试两步验证挑战。
    """
    return json(
        "Two-step verification attempt successful!", request.ctx.two_step_session.json
    )


# Authorization check route 检查授权路由
@role_bp.post("/")
@requires_authentication
async def on_authorization(request):
    """
    Check if the client has sufficient roles and permissions.
    检查客户端是否有足够的角色和权限。
    """
    await check_roles(request, request.form.get("role"))
    if request.form.get("permissions_required"):
        await check_permissions(
            request, *request.form.get("permissions_required").split(", ")
        )
    return text("Account is allowed.")


# Role assignment route 分配角色路由
@role_bp.post("assign")
@requires_authentication
async def on_role_assign(request):
    """
    Assign a role to an authenticated account.
    将角色分配给已认证的账户。
    """
    await assign_role(
        request.form.get("name"),
        request.ctx.authentication_session.bearer,
        request.form.get("permissions"),
        "Role for testing purposes."
    )
    return text("Role has been assigned.")


# Account creation route 创建账户路由
@account_bp.post("/")
async def on_account_creation(request):
    """
    Quickly create an account.
    快速创建账户。
    """
    if await Account.filter(email=request.form.get("email").lower()).exists():
        raise CredentialsError(
            "An account with this email already exists.", 409)
    elif await Account.filter(username=request.form.get("username")).exists():
        raise CredentialsError(
            "An account with this username already exists.", 409)
    account = await Account.create(
        username=request.form.get("username"),
        email=request.form.get("email").lower(),
        password=password_hasher.hash("password"),
        verified=True,
        disabled=False,
    )
    return json("Account creation successful!", account.json)
