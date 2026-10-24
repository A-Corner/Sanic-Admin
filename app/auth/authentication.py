#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
身份验证模块，提供用户登录、注册和会话管理功能
"""
import functools
from sanic.log import logger
from sanic.request import Request
from tortoise.exceptions import DoesNotExist
from app.models import Account, Role, AuthenticationSession, TwoStepSession
from app.services.utils import get_request_value
from app.services.exceptions import (
    AuthenticationError,
    CredentialsError,
    NotFoundError,
    ResourceAlreadyExistsError,
    SessionNotFoundError,
    ValidationError,
)
from app.config import BaseConfig


def get_session_token(request: Request, cookie_name: str = "session", header=None):
    """
    从请求中提取会话令牌：优先 Cookie，其次 Authorization: Bearer（或指定的请求头）。
    """
    token = request.cookies.get(cookie_name)
    if token:
        return token
    if header:
        return request.headers.get(header)
    return request.token


MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


def _text_field(value, name: str, max_len: int, required: bool = True, min_len: int = 1):
    """校验请求字段必须是字符串且长度在范围内；不合法抛出 ValidationError(400)。"""
    if value is None or value == "":
        if required:
            raise ValidationError(f"{name}是必填项")
        return None
    if not isinstance(value, str):
        raise ValidationError(f"{name}必须是字符串")
    if len(value) < min_len:
        raise ValidationError(f"{name}长度不能少于 {min_len} 位")
    if len(value) > max_len:
        raise ValidationError(f"{name}长度不能超过 {max_len} 位")
    return value


async def register(request: Request):
    """
    注册新账户（新账户总是未验证、未禁用，状态由服务端决定，不接受客户端指定）

    Args:
        request: Sanic请求对象，包含表单或JSON数据

    Returns:
        Account: 新创建的账户实例

    Raises:
        ValidationError: 如果提供的凭据不完整
        ResourceAlreadyExistsError: 如果邮箱/用户名/手机号已被注册
    """
    username = _text_field(get_request_value(request, "username"), "用户名", 32)
    email = _text_field(get_request_value(request, "email"), "电子邮件", 255)
    password = _text_field(get_request_value(request, "password"), "口令",
                           MAX_PASSWORD_LENGTH, min_len=MIN_PASSWORD_LENGTH)
    phone = _text_field(get_request_value(request, "phone"), "手机号", 14, required=False)

    if await Account.filter(email=email).exists():
        raise ResourceAlreadyExistsError("该邮箱已被注册")
    if await Account.filter(username=username).exists():
        raise ResourceAlreadyExistsError("该用户名已被注册")
    if phone and await Account.filter(phone=phone).exists():
        raise ResourceAlreadyExistsError("该手机号已被注册")

    account = Account(
        username=username,
        email=email,
        phone=phone,
        verified=False,
        disabled=False,
    )
    account.set_password(password)
    await account.save()
    return account


def _admin_role_permissions():
    """
    内置 admin 角色的初始权限：取自统一权限注册表的全量权限。

    历史上这里写死 ``{"users": [...], "roles": [...], "settings": [...]}``，
    与注册表里的资源名（``account`` / ``role`` / ``setting`` 等）完全对不上：
    注册表里没有 ``users`` / ``roles`` / ``settings`` 这三个资源，
    所以新装环境的 admin 角色实际上**一个真实权限都没有**。
    （初始管理员自己还能用，只是因为 ``Account.is_admin=True`` 会短路放行。）

    这里改为从 ``app.auth.permissions`` 注册表取全量权限，
    与 ``app.auth.authorization.sync_admin_role_permissions`` 的惰性同步口径一致。

    ``app.auth.permissions`` 是纯数据与纯函数模块（只 import ``typing``，不导入任何模型），
    因此这里 import 它不会产生循环依赖。为避免模块导入期的加载顺序问题，
    采用函数内延迟 import。

    Returns:
        dict: ``{资源: ["all"]}`` 形式的权限字典
    """
    from app.auth.permissions import admin_all_permissions

    return admin_all_permissions()


async def create_initial_admin_account(app=None):
    """
    创建初始管理员账户（如果不存在），口令取自环境变量 INITIAL_ADMIN_PASSWORD
    （见 ``app.config.BaseConfig``），不使用任何硬编码口令。

    Args:
        app: Sanic应用实例（保留参数，当前未使用）

    Returns:
        Account: 初始管理员账户
    """
    try:
        return await Account.get(email=BaseConfig.INITIAL_ADMIN_EMAIL)
    except DoesNotExist:
        pass

    admin = Account(
        username="SAdmin",
        email=BaseConfig.INITIAL_ADMIN_EMAIL,
        verified=True,
        disabled=False,
        is_admin=True,
        # 环境变量注入的口令只是交付通道，首次登录强制改为只有持有者知道的口令
        must_change_password=True,
    )
    admin.set_password(BaseConfig.INITIAL_ADMIN_PASSWORD)
    await admin.save()

    admin_role = await Role.get_or_none(name="admin")
    if not admin_role:
        admin_role = await Role.create(
            name="admin",
            description="管理员角色",
            permissions=_admin_role_permissions(),
        )
    await admin.roles.add(admin_role)
    logger.info(f"已创建初始管理员账户: {admin.email}")
    return admin


async def login(request: Request, require_second_factor: bool = False):
    """
    用户登录

    Args:
        request: Sanic请求对象，包含表单或JSON数据
        require_second_factor: 是否要求二次验证

    Returns:
        AuthenticationSession: 新创建的认证会话

    Raises:
        CredentialsError: 凭据缺失或不正确（账户不存在与口令错误不作区分，避免账户枚举）
        UnverifiedError / DisabledError / DeletedError: 账户状态不可用
    """
    username = _text_field(get_request_value(request, "username"), "用户名", 32, required=False)
    email = _text_field(get_request_value(request, "email"), "电子邮件", 255, required=False)
    password = _text_field(get_request_value(request, "password"), "口令",
                           MAX_PASSWORD_LENGTH, min_len=MIN_PASSWORD_LENGTH)
    if not username and not email:
        raise ValidationError("必须提供用户名或邮箱")

    try:
        if email:
            account = await Account.get_via_email(email)
        elif BaseConfig.ALLOW_LOGIN_WITH_USERNAME:
            account = await Account.get_via_username(username)
        else:
            raise CredentialsError("不支持通过用户名登录")
    except NotFoundError:
        # 与口令错误同等耗时，避免通过响应时间枚举账户
        Account.verify_dummy_password(password)
        raise CredentialsError("用户名或密码错误")

    if not account.verify_password(password):
        raise CredentialsError("用户名或密码错误")

    # 口令正确后再检查账户状态（未验证/禁用/已删除）
    account.validate()

    authentication_session = await AuthenticationSession.create_from_request(
        request, account, require_second_factor
    )
    return authentication_session


async def logout(request: Request):
    """
    注销用户

    Returns:
        AuthenticationSession: 禁用的认证会话

    Raises:
        SessionNotFoundError: 如果找不到认证会话令牌
    """
    token = get_session_token(request)
    if not token:
        raise SessionNotFoundError("未找到会话令牌")

    authentication_session = await AuthenticationSession.decode(token)
    await authentication_session.fetch_related("bearer")
    await authentication_session.disable()
    return authentication_session


async def fulfill_second_factor(request: Request):
    """
    完成二次验证

    请求需携带认证会话令牌，以及两步验证会话令牌（``two_step_token`` 参数，
    或 two_step_session Cookie / X-Two-Step-Token 头）与验证码 ``code``。

    Returns:
        AuthenticationSession: 更新的认证会话，二次验证标记为已完成
    """
    auth_token = get_session_token(request)
    if not auth_token:
        raise SessionNotFoundError("未找到认证会话令牌")
    authentication_session = await AuthenticationSession.decode(auth_token)

    two_step_token = (
        get_request_value(request, "two_step_token")
        or get_session_token(request, TwoStepSession.cookie_name, TwoStepSession.header_name)
    )
    if not two_step_token:
        raise SessionNotFoundError("未找到二步验证会话令牌")
    two_step_session = await TwoStepSession.decode(two_step_token)

    # 两步验证会话必须属于同一账户
    if two_step_session.bearer_id != authentication_session.bearer_id:
        raise SessionNotFoundError("二步验证会话与认证会话不匹配")

    await two_step_session.check_code(get_request_value(request, "code"))

    authentication_session.second_factor_verified = True
    await authentication_session.save(update_fields=["second_factor_verified"])
    await authentication_session.fetch_related("bearer")
    await two_step_session.disable()
    return authentication_session


async def authenticate_request(request: Request, require_second_factor: bool = True):
    """
    校验请求的认证会话，成功时写入 ``request.ctx.authentication_session``。

    Args:
        request: Sanic请求对象
        require_second_factor: 会话要求二次验证时，是否必须已完成

    Returns:
        AuthenticationSession: 已加载 bearer 的认证会话

    Raises:
        AuthenticationError: 未携带令牌，或令牌/会话/账户不可用
    """
    session = getattr(request.ctx, "authentication_session", None)
    if session is None:
        token = get_session_token(request)
        if not token:
            raise AuthenticationError("需要登录")
        session = await AuthenticationSession.decode(token)

    # 账户可能在会话签发后被禁用或删除
    await session.fetch_related("bearer")
    if session.bearer is None:
        raise SessionNotFoundError("会话未关联账户")
    session.bearer.validate()

    if require_second_factor and session.second_factor_pending:
        raise AuthenticationError("需要完成二次验证")

    request.ctx.authentication_session = session
    return session


async def get_authenticated_account(request: Request) -> Account:
    """
    获取当前请求已认证的账户（未认证时抛出 AuthenticationError）。
    """
    session = await authenticate_request(request)
    return session.bearer


def find_request(args):
    for arg in args:
        if isinstance(arg, Request):
            return arg
    raise TypeError("被装饰的处理函数必须接收 Request 参数")


def requires_authentication(handler=None, *, require_second_factor: bool = True):
    """
    需要身份验证的装饰器，可写作 ``@requires_authentication`` 或 ``@requires_authentication()``。

    未认证时抛出 AuthenticationError（401），不会放行到被装饰的处理函数。

    Args:
        handler: 被装饰函数（无括号用法）
        require_second_factor: 是否要求已完成二次验证
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            await authenticate_request(find_request(args), require_second_factor)
            return await func(*args, **kwargs)
        return wrapper

    if callable(handler):
        return decorator(handler)
    return decorator
