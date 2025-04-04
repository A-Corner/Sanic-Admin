#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
身份验证模块，提供用户登录、注册和会话管理功能
"""
import functools
import time
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sanic.request import Request
from tortoise.exceptions import DoesNotExist
from app.models import Account, AuthenticationSession, TwoStepSession
from app.services.utils import get_code
from app.services.exceptions import (
    CredentialsError,
    NotFoundError,
    UnverifiedError,
    DisabledError,
    DeletedError,
    SessionNotFoundError
)
from app.config import BaseConfig


# 密码哈希工具
password_hasher = PasswordHasher()


async def register(request: Request, verified: bool = False, disabled: bool = False):
    """
    注册新账户
    
    Args:
        request: Sanic请求对象，包含表单或JSON数据
        verified: 账户是否已验证
        disabled: 账户是否已禁用
        
    Returns:
        Account: 新创建的账户实例
        
    Raises:
        CredentialsError: 如果提供的凭据无效或不完整
    """
    # 支持表单和JSON格式的请求数据
    username = request.form.get("username") or request.json.get("username")
    email = request.form.get("email") or request.json.get("email")
    password = request.form.get("password") or request.json.get("password")
    phone = request.form.get("phone") or request.json.get("phone")
    
    # 验证基本凭据
    if not username or not email or not password:
        raise CredentialsError("用户名、电子邮件和密码是必填项")
    
    # 检查账户是否已存在
    try:
        existing_by_email = await Account.filter(email=email).exists()
        if existing_by_email:
            raise CredentialsError("该邮箱已被注册")
        
        existing_by_username = await Account.filter(username=username).exists()
        if existing_by_username:
            raise CredentialsError("该用户名已被注册")
        
        if phone:
            existing_by_phone = await Account.filter(phone=phone).exists()
            if existing_by_phone:
                raise CredentialsError("该手机号已被注册")
    except Exception as e:
        raise CredentialsError(f"注册验证失败: {str(e)}")
    
    # 哈希密码
    hashed_password = password_hasher.hash(password)
    
    # 创建新账户
    account = await Account.create(
        username=username,
        email=email,
        phone=phone,
        password=hashed_password,
        verified=verified,
        disabled=disabled
    )
    
    return account


async def create_initial_admin_account(app):
    """
    创建初始管理员账户（如果不存在）
    
    Args:
        app: Sanic应用实例
    """
    try:
        await Account.get(email=BaseConfig.INITIAL_ADMIN_EMAIL)
    except DoesNotExist:
        # 创建管理员账户
        admin = await Account.create(
            username="SAdmin",
            email=BaseConfig.INITIAL_ADMIN_EMAIL,
            password=password_hasher.hash(BaseConfig.INITIAL_ADMIN_PASSWORD),
            verified=True,
            disabled=False
        )
        
        # 为管理员创建角色
        from app.models import Role
        admin_role = await Role.get_or_none(name="admin")
        if not admin_role:
            admin_role = await Role.create(
                name="admin",
                description="管理员角色",
                permissions={
                    "users": ["create", "read", "update", "delete"],
                    "roles": ["create", "read", "update", "delete"],
                    "settings": ["read", "update"]
                }
            )
        
        # 分配角色
        await admin.roles.add(admin_role)


async def login(request: Request, require_second_factor: bool = False):
    """
    用户登录
    
    Args:
        request: Sanic请求对象，包含表单或JSON数据
        require_second_factor: 是否要求二次验证
        
    Returns:
        AuthenticationSession: 新创建的认证会话
        
    Raises:
        CredentialsError: 如果提供的凭据无效或不完整
        UnverifiedError: 如果账户未经验证
        DisabledError: 如果账户已禁用
    """
    # 支持表单和JSON格式的请求数据
    username = request.form.get("username") or request.json.get("username")
    email = request.form.get("email") or request.json.get("email")
    password = request.form.get("password") or request.json.get("password")
    
    # 验证基本凭据
    if not password or (not username and not email):
        raise CredentialsError("必须提供用户名/邮箱和密码")
    
    try:
        # 优先通过邮箱查找账户
        if email:
            account = await Account.get_via_email(email)
        # 如果配置允许，也可以通过用户名查找
        elif username and BaseConfig.ALLOW_LOGIN_WITH_USERNAME:
            account = await Account.get_via_username(username)
        else:
            raise CredentialsError("不支持通过用户名登录")
        
        # 验证密码
        try:
            password_hasher.verify(account.password, password)
        except VerifyMismatchError:
            raise CredentialsError("密码不正确")
        
        # 验证账户状态
        account.validate()
        
        # 创建新的认证会话
        authentication_session = await AuthenticationSession.create_from_request(
            request, account, require_second_factor
        )
        
        return authentication_session
        
    except NotFoundError:
        raise CredentialsError("找不到使用此凭据的账户")
    except (UnverifiedError, DisabledError, DeletedError) as e:
        raise e
    except Exception as e:
        raise CredentialsError(f"登录失败: {str(e)}")


async def logout(request: Request):
    """
    注销用户
    
    Args:
        request: Sanic请求对象
        
    Returns:
        AuthenticationSession: 禁用的认证会话
        
    Raises:
        SessionNotFoundError: 如果找不到认证会话
    """
    token = request.cookies.get("session") or request.token
    if not token:
        raise SessionNotFoundError("未找到会话令牌")
    
    authentication_session = await AuthenticationSession.decode(token)
    await authentication_session.disable()
    
    return authentication_session


async def fulfill_second_factor(request: Request):
    """
    完成二次验证
    
    Args:
        request: Sanic请求对象
        
    Returns:
        AuthenticationSession: 更新的认证会话，二次验证标记为已完成
        
    Raises:
        SessionNotFoundError: 如果找不到认证会话或二步验证会话
        CredentialsError: 如果二步验证码不匹配
    """
    # 获取认证会话
    auth_token = request.cookies.get("session") or request.token
    if not auth_token:
        raise SessionNotFoundError("未找到认证会话令牌")
    
    authentication_session = await AuthenticationSession.decode(auth_token)
    
    # 获取二步验证会话
    two_step_token = request.form.get("two_step_token") or request.json.get("two_step_token")
    if not two_step_token:
        raise SessionNotFoundError("未找到二步验证会话令牌")
    
    two_step_session = await TwoStepSession.decode(two_step_token)
    
    # 验证二步验证码
    code = request.form.get("code") or request.json.get("code")
    if not code or code != two_step_session.code:
        raise CredentialsError("验证码不正确")
    
    # 更新认证会话，标记二次验证已完成
    authentication_session.second_factor_verified = True
    await authentication_session.save(update_fields=["second_factor_verified"])
    
    # 禁用二步验证会话
    await two_step_session.disable()
    
    return authentication_session


def requires_authentication(require_second_factor: bool = True):
    """
    需要身份验证的装饰器
    
    Args:
        require_second_factor: 是否要求二次验证
        
    Returns:
        函数装饰器
    """
    def decorator(handler):
        @functools.wraps(handler)
        async def wrapper(request, *args, **kwargs):
            token = request.cookies.get("session") or request.token
            if not token:
                return handler(request, *args, **kwargs)
            
            try:
                authentication_session = await AuthenticationSession.decode(token)
                
                # 验证二次因素要求
                if require_second_factor and authentication_session.requires_second_factor:
                    if not authentication_session.second_factor_verified:
                        raise SessionNotFoundError("需要完成二次验证")
                
                # 将会话保存到请求上下文中
                request.ctx.authentication_session = authentication_session
                
                return await handler(request, *args, **kwargs)
            except Exception as e:
                return handler(request, *args, **kwargs)
        
        return wrapper
    
    return decorator 