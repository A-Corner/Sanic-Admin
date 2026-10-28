#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
验证模块，提供账户验证、两步验证、图形验证码，以及基于令牌的账户激活/密码重置

两类机制：

* 会话式（TwoStepSession / CaptchaSession）：验证码绑定在短期会话里，令牌经 Cookie / 请求头下发，
  供注册验证、登录二次验证、验证码使用。
* 令牌式（VerificationToken）：一次性随机令牌，供账户激活、密码重置（通过邮件等渠道投递）。
"""

import functools
import secrets
from sanic.request import Request
from app.models import (
    Account,
    AuthenticationSession,
    CaptchaSession,
    TwoStepSession,
    VerificationToken,
)
from app.services.utils import get_expiration_date, get_request_value
from app.services.exceptions import (
    VerificationError,
    TokenExpiredError,
    TokenInvalidError,
    SessionNotFoundError,
)
from app.auth.authentication import get_session_token, find_request


# ---------------------------------------------------------------- 会话式验证


async def request_two_step_verification(request: Request, account: Account) -> TwoStepSession:
    """
    为账户创建两步验证会话（验证码需通过邮件/短信等渠道送达用户，路由层负责投递）

    Returns:
        TwoStepSession: 新建的两步验证会话
    """
    return await TwoStepSession.create_from_request(request, bearer=account)


async def _decode_two_step_session(request: Request) -> TwoStepSession:
    token = get_request_value(request, "two_step_token") or get_session_token(
        request, TwoStepSession.cookie_name, TwoStepSession.header_name
    )
    if not token:
        raise SessionNotFoundError("未找到二步验证会话令牌")
    session = await TwoStepSession.decode(token)
    await session.fetch_related("bearer")
    return session


async def verify_account(request: Request) -> TwoStepSession:
    """
    用两步验证码验证账户，成功后账户置为已验证。

    Returns:
        TwoStepSession: 已使用（已禁用）的两步验证会话，bearer 已加载

    Raises:
        VerificationError: 账户已验证
        TokenInvalidError: 验证码不正确
    """
    session = await _decode_two_step_session(request)
    account = session.bearer
    if account is None:
        raise SessionNotFoundError("验证会话未关联账户")
    if account.verified:
        raise VerificationError("账户已验证")

    await session.check_code(get_request_value(request, "code"))

    account.verified = True
    await account.save(update_fields=["verified"])
    await session.disable()
    return session


def requires_two_step_verification(func):
    """
    要求请求携带有效两步验证会话与正确验证码的装饰器；通过后会话作废，
    并写入 ``request.ctx.two_step_session``。
    """

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        request = find_request(args)
        session = await _decode_two_step_session(request)
        await session.check_code(get_request_value(request, "code"))
        await session.disable()
        request.ctx.two_step_session = session
        return await func(*args, **kwargs)

    return wrapper


async def request_captcha(request: Request) -> CaptchaSession:
    """
    创建图形验证码会话

    Returns:
        CaptchaSession: 新建的验证码会话
    """
    return await CaptchaSession.create_from_request(request)


def requires_captcha(func):
    """
    要求请求携带有效验证码会话与正确验证码（``code`` 参数）的装饰器；通过后会话作废，
    并写入 ``request.ctx.captcha_session``。
    """

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        request = find_request(args)
        token = get_session_token(request, CaptchaSession.cookie_name, CaptchaSession.header_name)
        if not token:
            raise SessionNotFoundError("未找到验证码会话令牌")
        session = await CaptchaSession.decode(token)
        await session.check_code(get_request_value(request, "code"))
        await session.disable()
        request.ctx.captcha_session = session
        return await func(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------- 令牌式验证


async def generate_verification_token(account: Account, token_type: str, expiry_hours: int = 24):
    """
    生成验证令牌（同账户同类型的旧令牌作废）

    Args:
        account: 账户实例
        token_type: 令牌类型，如 'activation', 'password_reset'
        expiry_hours: 令牌过期时间（小时）

    Returns:
        VerificationToken: 生成的验证令牌实例
    """
    await VerificationToken.filter(account_id=account.id, token_type=token_type).delete()

    return await VerificationToken.create(
        account=account,
        token=secrets.token_urlsafe(32),
        token_type=token_type,
        expires_at=get_expiration_date(expiry_hours * 3600),
    )


async def validate_token(token: str, token_type: str):
    """
    验证令牌有效性

    Raises:
        TokenInvalidError: 令牌无效
        TokenExpiredError: 令牌已过期
    """
    verification_token = await VerificationToken.filter(token=token, token_type=token_type, used=False).first()
    if not verification_token:
        raise TokenInvalidError("无效的验证令牌")

    if verification_token.is_expired:
        await verification_token.delete()
        raise TokenExpiredError("验证令牌已过期")

    return verification_token


async def activate_account(token: str):
    """
    激活（验证）账户

    Raises:
        TokenInvalidError / TokenExpiredError: 令牌无效或过期
        VerificationError: 账户已验证
    """
    verification_token = await validate_token(token, "activation")
    account = await verification_token.account.get()

    if account.verified:
        await verification_token.delete()
        raise VerificationError("账户已验证")

    account.verified = True
    await account.save(update_fields=["verified"])
    await verification_token.delete()
    return account


async def reset_password(token: str, new_password: str):
    """
    重置密码

    Raises:
        TokenInvalidError / TokenExpiredError: 令牌无效或过期
    """
    verification_token = await validate_token(token, "password_reset")
    account = await verification_token.account.get()

    account.set_password(new_password)
    await account.save(update_fields=["password"])
    await verification_token.delete()
    # 口令已变更：作废该账户全部既有登录会话
    await AuthenticationSession.filter(bearer=account, disabled=False).update(disabled=True)
    return account


# ---------------------------------------------------------------- 密码重置（AUTH-03）

#: 重置令牌有效期（秒）。CPL 建议 30 分钟。
PASSWORD_RESET_TTL_SECONDS = 30 * 60


async def request_password_reset(email: str) -> None:
    """
    发起密码重置：邮箱存在则生成一次性令牌并通过投递后端送出。

    **不返回任何「邮箱是否存在」的信号**——调用方（路由层）无论本函数内部
    走到哪条分支，都返回相同的 200。

    ## 关于时间侧信道（如实声明，不假装防住）

    本实现**接受**时间侧信道：邮箱存在时多做了「生成 token + 投递」两件事，
    耗时必然大于邮箱不存在的分支。彻底消除它需要「两条分支做等量工作」
    （例如对不存在的邮箱也生成 token 并投递到一个丢弃地址），代价是每次
    未命中的请求都要产生一次投递副作用——对一个公开端点来说，那反而变成了
    可被滥用的资源消耗面。

    **本函数防住的是响应差异**（状态码、响应体、错误码），**不防时序分析**。
    这一点在 `docs/` 与测试注释里都写明，不声称「完全不可枚举」。

    Args:
        email: 提交的邮箱（原样使用，不做大小写归一——账户表的 email 是
               区分大小写的唯一字段，归一化会造成「能命中却报不存在」）
    """
    from app.services.delivery import deliver

    account = await Account.filter(email=email, deleted=False).first()
    if account is None:
        # 刻意「什么都不做」并正常返回：与命中分支的唯一差别是下面这段不执行。
        # 时间差异见函数 docstring 的声明。
        return

    # 复用既有令牌生成：同账户同类型旧令牌会被作废（单次有效的前提之一）
    token = await VerificationToken.create(
        account=account,
        token=secrets.token_urlsafe(32),
        token_type="password_reset",
        expires_at=get_expiration_date(PASSWORD_RESET_TTL_SECONDS),
    )

    await deliver(
        to=email,
        subject="重置你的口令",
        body=(
            f"你的口令重置令牌是：{token.token}\n"
            f"请在 {PASSWORD_RESET_TTL_SECONDS // 60} 分钟内使用，令牌仅可使用一次。\n"
            "如果这不是你发起的，请忽略本消息。"
        ),
    )
    # 旧令牌清理：generate 语义是「同账户同类型唯一」，这里用 create 直接建，
    # 因此手动作废该账户其他未用的重置令牌，保持「只有最新一个有效」。
    await (
        VerificationToken.filter(account_id=account.id, token_type="password_reset", used=False)
        .exclude(id=token.id)
        .update(used=True)
    )
