#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
验证模块，提供账户验证、两步验证、图形验证码，以及基于令牌的密码重置

两类机制：

* 会话式（TwoStepSession / CaptchaSession）：验证码绑定在短期会话里，令牌经 Cookie / 请求头下发，
  供注册验证、登录二次验证、验证码使用。
* 令牌式（VerificationToken）：一次性随机令牌，供密码重置（通过邮件等渠道投递）。
"""

import functools
import hashlib
import secrets

from sanic.request import Request
from tortoise.transactions import in_transaction

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
        token_type: 令牌类型，目前生产使用的为 'password_reset'
        expiry_hours: 令牌过期时间（小时）

    Returns:
        VerificationToken: 生成的验证令牌实例。**注意 `token` 字段的语义**：
        对 ``password_reset`` 类型，库里存的是 sha256 哈希，明文放在
        ``vt.plain_token`` 上（见下）；其余类型仍存明文，行为不变。
    """
    await VerificationToken.filter(account_id=account.id, token_type=token_type).delete()

    raw = secrets.token_urlsafe(32)
    stored = _hash_reset_token(raw) if token_type == "password_reset" else raw
    vt = await VerificationToken.create(
        account=account,
        token=stored,
        token_type=token_type,
        expires_at=get_expiration_date(expiry_hours * 3600),
    )
    # 明文只存在于内存对象上，供调用方投递；不落库。
    # 非 password_reset 类型两者相同，赋值不影响既有行为。
    vt.plain_token = raw
    return vt


async def validate_token(token: str, token_type: str, *, consume: bool = False):
    """
    验证令牌有效性。

    Args:
        token: 令牌原文
        token_type: 令牌类型
        consume: 为 True 时**原子地**把令牌标记为已使用。用于「单次有效」必须
            杜绝并发重放的场景（密码重置）。实现是 `UPDATE ... WHERE used=False`
            并检查影响行数——两个并发调用只有一个能拿到 1，另一个拿到 0 并抛
            `TokenInvalidError`。**不要用「先查后改」**：那两步之间没有锁，
            两个并发请求会双双重置成功。

    Raises:
        TokenInvalidError: 令牌无效 / 已被使用
        TokenExpiredError: 令牌已过期
    """
    # password_reset 的令牌在库里存的是 sha256 哈希，查询前先转换。
    # 其余类型仍是明文，保持既有行为不变。
    lookup = _hash_reset_token(token) if token_type == "password_reset" else token

    if consume:
        # 原子认领：先按条件更新，再回读。顺序反了就回到「先查后改」的竞态。
        affected = await VerificationToken.filter(token=lookup, token_type=token_type, used=False).update(used=True)
        if not affected:
            raise TokenInvalidError("无效的验证令牌（或已被使用）")
        verification_token = await VerificationToken.filter(token=lookup, token_type=token_type).first()
        if verification_token is None:  # pragma: no cover - 认领成功后不可能查不到
            raise TokenInvalidError("无效的验证令牌")
        if verification_token.is_expired:
            # 过期令牌已无价值，删掉并明确报过期（用户需要重新申请）
            await verification_token.delete()
            raise TokenExpiredError("验证令牌已过期")
        return verification_token

    verification_token = await VerificationToken.filter(token=lookup, token_type=token_type, used=False).first()
    if not verification_token:
        raise TokenInvalidError("无效的验证令牌")

    if verification_token.is_expired:
        await verification_token.delete()
        raise TokenExpiredError("验证令牌已过期")

    return verification_token


async def reset_password(token: str, new_password: str):
    """
    重置密码

    **校验顺序**：先做口令校验（纯内存、无副作用），再认领令牌。
    反过来的话，用户提交弱口令时令牌已被标记 used，抛错后必须重新申请一次重置——
    令牌被一个必然失败的输入白白烧掉。

    顺序说明：口令强度校验（纯内存、抛 ValidationError）先于令牌认领。
    若先认领，用户提交一次不合规口令就会消耗令牌，须重新走 request 流程；
    截获令牌者也可故意用弱口令消耗令牌，构成对单次重置的拒绝服务。
    当前选择「不烧令牌」一侧：校验失败时令牌保持未认领。残余攻击面是
    持令牌者可用合规口令完成一次重置——但那正是持有令牌本身已赋予的能力，
    既不放大权限，也不构成账户接管。

    Raises:
        TokenInvalidError / TokenExpiredError: 令牌无效或过期
        ValidationError: 新口令不达标（**不消耗令牌**，可用同一令牌重试）
    """
    # 1. 只读校验：确认令牌有效并取到账户，但不置 used。
    peeked = await validate_token(token, "password_reset", consume=False)
    account = await peeked.account.get()

    # 2. 口令校验 + 哈希（仅改内存字段，不落库）。set_password 抛 ValidationError 时
    #    令牌仍未被认领，用户可以拿同一个令牌换一个合规口令重试。
    account.set_password(new_password)

    # 3. 认领 + 落库必须在同一个事务里。
    #    `validate_token(consume=True)` 会把令牌原子置为 used；若随后的
    #    `account.save()` 失败（DB 错误、约束冲突等），令牌已被烧掉、口令却没改，
    #    用户拿着一个已作废的令牌，且无法用同一令牌重试——只能重新走一次申请。
    #    包进 in_transaction()：任一步失败整体回滚，令牌回到 used=False，
    #    用户可原样重试。认领仍靠 `UPDATE ... WHERE used=False` 的影响行数保证
    #    并发下只有一个能成功。
    async with in_transaction():
        verification_token = await validate_token(token, "password_reset", consume=True)
        await account.save(update_fields=["password"])
        await verification_token.delete()
        # 口令已变更：作废该账户全部既有登录会话
        await AuthenticationSession.filter(bearer=account, disabled=False).update(disabled=True)
    return account


# ---------------------------------------------------------------- 密码重置（AUTH-03）

#: 重置令牌有效期（秒）。CPL 建议 30 分钟。
PASSWORD_RESET_TTL_SECONDS = 30 * 60


def _hash_reset_token(raw: str) -> str:
    """
    重置令牌的存储形态：sha256 hex。

    **为什么存哈希而不是明文**：`VerificationToken.token` 若是明文，一次数据库
    备份泄露或只读注入就足以接管 30 分钟内任意账户——token 与口令不同，它不可逆
    的成本为零。sha256 对 256bit 随机输入足够（无需加盐：输入本身熵极高，
    不存在字典攻击面）。

    查询走数据库等值匹配（`token` 列有索引），不做内存字符串比较，因此这里
    **不适用** `secrets.compare_digest`（它是给内存中的密文/摘要比较用的）。
    令牌本身是 `secrets.token_urlsafe(32)` 的 256bit 随机值，时序信道既无法
    缩小搜索空间也无法命中，故不额外做常量时间比较。

    返回 64 字符 hex，适配 `token` 字段的 `max_length=128`。
    """
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


async def request_password_reset(email: str) -> bool:
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
        # 返回 True：对调用方（审计）而言「无需投递」不是失败。
        return True

    # **先作废旧令牌，再建新的**（顺序关键）：
    # 反过来的话，在「建新」与「作废旧」之间存在一个窗口，账户同时持有两个
    # 有效令牌；若此时两次并发 request 交错，还会互相把对方的新令牌标记 used，
    # 用户两张全失效。
    await VerificationToken.filter(account_id=account.id, token_type="password_reset", used=False).update(used=True)

    raw_token = secrets.token_urlsafe(32)
    # 存哈希：库泄露不直接等于账户接管（见 _hash_reset_token 的说明）
    token = await VerificationToken.create(
        account=account,
        token=_hash_reset_token(raw_token),
        token_type="password_reset",
        expires_at=get_expiration_date(PASSWORD_RESET_TTL_SECONDS),
    )

    delivered = await deliver(
        to=email,
        subject="重置你的口令",
        body=(
            f"你的口令重置令牌是：{raw_token}\n"
            f"请在 {PASSWORD_RESET_TTL_SECONDS // 60} 分钟内使用，令牌仅可使用一次。\n"
            "如果这不是你发起的，请忽略本消息。"
        ),
    )
    return delivered
