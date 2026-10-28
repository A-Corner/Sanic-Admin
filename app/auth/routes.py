#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
认证路由模块，定义所有认证相关的路由
"""

from sanic import Blueprint
from app.config import settings
from app.models import CaptchaSession, AuthenticationSession
from app.services.utils import get_request_value, json
from app.auth.authentication import (
    login,
    register,
    requires_authentication,
    logout,
    fulfill_second_factor,
    get_session_token,
)
from app.auth.rate_limit import LoginRateLimiter
from app.auth.verification import (
    request_two_step_verification,
    verify_account,
    request_captcha,
    request_password_reset,
    reset_password,
)
from app.middleware.security_middleware import issue_csrf_token
from app.services.exceptions import (
    CredentialsError,
    PasswordChangeRequiredError,
    RateLimitExceededError,
    TokenExpiredError,
    TokenInvalidError,
    ValidationError,
)


# 创建认证相关蓝图
auth_bp = Blueprint("auth", url_prefix="/auth")
capt_bp = Blueprint("capt", url_prefix="/capt")
two_step_bp = Blueprint("two-step", url_prefix="/two-step")
role_bp = Blueprint("roles", url_prefix="/roles")
account_bp = Blueprint("account", url_prefix="/account")


def _mask_identity(identity: str) -> str:
    """把登录标识脱敏后写进审计：只保留域名或首尾字符。

    审计需要「是谁在尝试」以便事后归因，但不能留下完整邮箱或用户名——
    日志往往比口令库更容易被读到。
    """
    text = str(identity or "").strip()
    if not text:
        return "-"
    if "@" in text:
        _, _, domain = text.partition("@")
        return f"***@{domain}"
    # 非邮箱标识：短标识（≤4）只留长度，避免把整个用户名暴露在日志里；
    # 较长的才保留前 2 位便于人工归因。
    if len(text) <= 4:
        return f"***({len(text)})"
    return f"{text[:2]}***({len(text)})"


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
    response = json("认证成功!", request.ctx.authentication_session.bearer.json)
    request.ctx.authentication_session.encode(response)
    return response


# whoami 路由（SA-v042-SPECWRITE，docs/mcp-write-path.md §10）
@auth_bp.get("/whoami")
@requires_authentication()
async def on_whoami(request):
    """
    返回当前会话的账户 ID 与合并权限，供 MCP 写入路径做 spec:write 校验。

    约束（CPL 裁定 2026-10-24）：

    - 走现有鉴权链：``@requires_authentication()`` 默认拒绝
      ``second_factor_pending`` 的会话（401），无需额外代码路径；
    - ``must_change_password=True`` 一律拒绝：本路径**不在**
      ``PASSWORD_CHANGE_EXEMPT_PREFIXES`` 豁免白名单里——全局中间件
      ``enforce_password_change`` 已按 fail-closed 拦截（403）；handler 内
      显式再查一道纵深防御（直接调 handler 的测试不经过中间件）；
    - 返回最小化：只有 ``account_id`` 与 ``permissions``，不含邮箱、用户名等；
    - 复用现有审计（``record_auth_event``），IP 采信口径同登录限流；
      审计不含 token（audit 模块硬约束）。

    权限语义与 ``has_permission`` 一致：``is_admin`` 账户返回
    ``admin_all_permissions()``（直通语义），普通账户返回角色合并结果——
    MCP 侧只做 ``spec:write`` 的集合判断，不复制 RBAC 归一化规则。
    """
    from app.services.audit import record_auth_event

    bearer = request.ctx.authentication_session.bearer
    if getattr(bearer, "must_change_password", False):
        await record_auth_event(request, "whoami", account=bearer, status="failure", detail="password_change_required")
        raise PasswordChangeRequiredError()

    if bearer.is_admin:
        from app.auth.permissions import admin_all_permissions

        permissions = admin_all_permissions()
    else:
        from app.auth.authorization import get_account_permissions

        permissions = await get_account_permissions(bearer)

    await record_auth_event(request, "whoami", account=bearer, status="success")
    return json("当前账户与权限", {"account_id": bearer.id, "permissions": permissions})


# 注册路由
@auth_bp.post("/register")
async def on_register(request):
    """
    使用电子邮件和密码注册账户
    """
    account = await register(request)

    two_step_session = await request_two_step_verification(request, account)
    response = json("注册成功! 需要验证。", _delivery_code(request, two_step_session.code))
    two_step_session.encode(response)
    return response


# 验证账户路由
@auth_bp.post("/verify")
async def on_verify(request):
    """
    验证客户端账户
    """
    two_step_session = await verify_account(request)
    return json("您的账户已验证，现在可以登录!", two_step_session.bearer.json)


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
    if identity:
        try:
            await limiter.raise_if_blocked(identity, request)
        except RateLimitExceededError:
            # 被限流拦下的尝试也要留痕，否则事后查不到「有人在这个窗口内被拒」
            from app.services.audit import record_auth_event

            await record_auth_event(
                request, "login_failure", status="failure", detail=f"限流拦截 identity={_mask_identity(identity)}"
            )
            raise

    # 是否启用二次验证只由服务端配置决定，忽略客户端参数
    two_factor_authentication = bool(getattr(settings, "REQUIRE_TWO_FACTOR", False))
    from app.services.audit import record_auth_event

    try:
        authentication_session = await login(request, require_second_factor=two_factor_authentication)
    except CredentialsError:
        # 仅凭据错误计入失败次数（未验证/禁用等账户状态问题不属于口令猜测）
        if identity:
            await limiter.record_failure(identity, request)
        await record_auth_event(
            request,
            "login_failure",
            status="failure",
            detail=f"凭据错误 identity={_mask_identity(identity) if identity else '-'}",
        )
        raise
    except Exception:
        # 其它登录失败（未验证/禁用/已删除等）：同样留痕后原样抛出
        await record_auth_event(
            request,
            "login_failure",
            status="failure",
            detail=f"账户状态不可用 identity={_mask_identity(identity) if identity else '-'}",
        )
        raise

    # 成功登录清零该维度的失败计数（登录成功时两个维度都清，属正常语义）
    if identity:
        await limiter.clear(identity, request)
    await record_auth_event(request, "login_success", account=authentication_session.bearer)

    # 首次登录强制改密标志随登录响应透出（AMIS 登录页据此弹改密对话框）
    must_change_password = bool(getattr(authentication_session.bearer, "must_change_password", False))

    if two_factor_authentication:
        two_step_session = await request_two_step_verification(request, authentication_session.bearer)
        # _delivery_code 返回 str（DEBUG）或 None，不是 dict：在此组装响应体
        data = {
            "code": _delivery_code(request, two_step_session.code),
            "must_change_password": must_change_password,
        }
        response = json("登录成功! 需要两步验证。", data)
        two_step_session.encode(response)
    else:
        data = dict(authentication_session.bearer.json)
        data["must_change_password"] = must_change_password
        response = json("登录成功!", data)

    authentication_session.encode(response)
    # 下发 CSRF token（双提交 cookie + 响应头），此后凭会话 cookie 的写请求须回传
    # X-CSRF-Token 头（见 app/middleware/security_middleware.py 的 enforce_csrf）。
    issue_csrf_token(
        response,
        secure=bool(request.app.config.get("SESSION_COOKIE_SECURE", True)),
    )
    return response


# 密码重置（AUTH-03）

#: 重置请求的限流前缀。**刻意与 `login_rl_*` 分开**——共用会让重置拖累登录。
RESET_RL_PREFIX = "pwreset_rl"


def _enforce_reset_rate_limit(request, email: str) -> None:
    """
    重置请求的限流：按（账户键 + IP）计数，**完全独立于登录限流**。

    复用 `LoginRateLimiter` 的 cache / 窗口参数，但键前缀自建，不走它的
    `_keys()`（那个方法无条件带 IP 键，跨动作耦合）。

    Raises:
        RateLimitExceededError: 窗口内重置请求次数已达上限
    """
    import time

    limiter = LoginRateLimiter.from_request(request)
    cache = limiter.cache
    window = limiter.window_seconds
    limit = limiter.max_attempts
    ip = limiter._client_ip(request)
    keys = [f"{RESET_RL_PREFIX}:acct:{email.strip().lower()}", f"{RESET_RL_PREFIX}:ip:{ip}"]

    now = time.time()
    cutoff = now - window
    for key in keys:
        recent = [ts for ts in (cache.get(key) or []) if ts > cutoff]
        if len(recent) >= limit:
            raise RateLimitExceededError(f"重置请求次数过多，请约 {max(window // 60, 1)} 分钟后再试")
    # 未被拦下才记一次（与登录语义一致：被拦的尝试不额外延长封锁）
    for key in keys:
        recent = [ts for ts in (cache.get(key) or []) if ts > cutoff]
        recent.append(now)
        cache.set(key, recent, timeout=window)


@auth_bp.post("/password-reset/request")
async def on_password_reset_request(request):
    """
    发起密码重置。

    **无论邮箱是否存在，一律返回 200 且响应体完全一致**——这是防账户枚举的
    最低要求。时间侧信道见 `request_password_reset()` 的 docstring：本端点
    防的是响应差异，不防时序分析，不声称完全不可枚举。

    限流：复用登录限流器按（标识 + IP）计数，避免被用作邮箱探测或投递滥用。
    """
    from app.services.audit import record_auth_event

    email = str(get_request_value(request, "email") or "").strip()
    if not email:
        return json("如果该邮箱已注册，重置说明将发送到该地址。")

    # **独立限流**：不能复用 `LoginRateLimiter`——它的 `_keys()` 无条件追加
    # `login_rl_ip:<ip>` 这个 IP 维度键（与 identity 无关），用户连试几次重置
    # 就会把同一出口 IP 下的登录计数一并打满，把两个不相干的动作耦合在一起。
    # 这里用独立前缀自建计数，只按 (重置, 账户键, IP) 计。
    _enforce_reset_rate_limit(request, email)

    delivered = await request_password_reset(email)
    # 投递失败要如实记 failure：真后端故障时用户看到「已发送」却永远收不到，
    # 审计若还写 success，事后无从排查。（deliver() 永不抛，只返回 bool。）
    await record_auth_event(
        request,
        "password_reset_request",
        status="failure" if delivered is False else "success",
        detail="投递失败" if delivered is False else None,
    )
    return json("如果该邮箱已注册，重置说明将发送到该地址。")


@auth_bp.post("/password-reset/confirm")
async def on_password_reset_confirm(request):
    """
    用令牌重置口令。令牌单次有效、TTL 30 分钟、用后即焚。

    失败一律 400 且不区分「令牌不存在」与「令牌已过期」之外的细节——
    前者泄露不了什么（令牌是随机的），后者对用户有实际意义（需要重新申请）。
    """
    from app.services.audit import record_auth_event

    token = str(get_request_value(request, "token") or "").strip()
    new_password = get_request_value(request, "new_password") or ""
    if not token or not new_password:
        raise ValidationError("令牌与新口令均为必填")

    try:
        account = await reset_password(token, new_password)
    except (TokenInvalidError, TokenExpiredError) as exc:
        await record_auth_event(request, "password_reset_confirm", status="failure", detail=type(exc).__name__)
        raise

    await record_auth_event(request, "password_reset_confirm", account=account, status="success")
    return json("口令已重置，请用新口令登录。")


# 修改密码路由
@auth_bp.post("/change-password")
async def on_change_password(request):
    """
    已登录用户修改自己的口令；清除 must_change_password 标志。

    必须携带有效会话（认证中间件已附加 authentication_session）；
    强制改密拦截（见 security_middleware）放行本端点与 logout，
    其余 /api/ 请求在标志清除前一律 403。

    SA-v034-L1 加固：
    * 当前口令试错按账户维度限速（复用登录限流器，窗口内失败 N 次返回 429）；
    * 新口令除长度外还要求至少两类字符，且不得为系统已知弱口令或与邮箱相同；
    * 改密成功后轮换当前会话 token（旧会话立即作废，新会话下发给客户端）。
    """
    from app.auth.authentication import (
        MAX_PASSWORD_LENGTH,
        MIN_PASSWORD_LENGTH,
        _text_field,
        validate_not_banlisted,
        validate_password_strength,
    )
    from app.services.audit import record_auth_event
    from app.services.exceptions import SessionValidationError

    session = getattr(request.ctx, "authentication_session", None)
    if session is None or session.bearer is None:
        raise SessionValidationError("未登录或会话已失效")

    # 账户启用 2FA 时，二次验证未完成的会话不得改密（否则仅凭口令即可绕过 2FA）
    if session.second_factor_pending:
        from app.services.exceptions import TwoFactorRequiredError

        await record_auth_event(
            request, "change_password_2fa_pending", account=session.bearer, status="failure", detail="2FA 未完成"
        )
        raise TwoFactorRequiredError()

    account = session.bearer

    # 当前口令试错限速：复用登录限流器（账户维度独立计数）。
    limiter = LoginRateLimiter.from_request(request)
    identity = account.email or account.username or str(account.id)
    try:
        await limiter.raise_if_blocked(identity, request)
    except RateLimitExceededError:
        # 被限流拦下的改密尝试也要留痕，与登录侧保持一致
        await record_auth_event(
            request,
            "change_password_failure",
            account=account,
            status="failure",
            detail=f"限流拦截 identity={_mask_identity(identity)}",
        )
        raise

    current_password = _text_field(get_request_value(request, "current_password"), "当前口令", 128)
    new_password = _text_field(
        get_request_value(request, "new_password"),
        "新口令",
        MAX_PASSWORD_LENGTH,
        min_len=MIN_PASSWORD_LENGTH,
    )
    confirm = get_request_value(request, "confirm_password")
    if confirm is not None and str(confirm) != new_password:
        raise ValidationError("两次输入的新口令不一致")
    if new_password == current_password:
        raise ValidationError("新口令不能与当前口令相同")

    # 强度：至少两类字符（大写/小写/数字/符号）
    strength_error = validate_password_strength(new_password)
    if strength_error:
        await record_auth_event(request, "change_password_failure", account=account, status="failure", detail="新口令强度不足")
        raise ValidationError(strength_error)

    # 禁止使用系统已知弱口令，或与自己的邮箱相同
    banned_error = validate_not_banlisted(new_password, account)
    if banned_error:
        await record_auth_event(
            request, "change_password_failure", account=account, status="failure", detail="新口令为已知弱口令"
        )
        raise ValidationError(banned_error)

    if not account.verify_password(current_password):
        await limiter.record_failure(identity, request)
        await record_auth_event(request, "change_password_failure", account=account, status="failure", detail="当前口令错误")
        raise CredentialsError("当前口令错误")

    # 只清该账户的计数：IP 键是同一出口下多个账户共享的，改密成功就把它清零，
    # 会让一个账户的正常操作替别人解封。
    await limiter.clear_account_only(identity)

    # 改密 + 轮换必须是一个原子动作：
    # 若先 save 口令、再建会话而建会话失败，密码已经变了、旧会话却还有效，
    # 用户处于「口令已改但拿不到新凭据」的不一致状态。整段放进同一个事务，
    # 任一步失败都回滚，口令与旧会话都保持原样。
    from tortoise.transactions import in_transaction

    async with in_transaction():
        account.set_password(new_password)
        account.must_change_password = False
        await account.save(update_fields=["password", "must_change_password"])

        # 先建新会话，再作废旧会话——顺序在事务内也有意义：
        # 新会话创建失败会直接抛出并回滚，不会留下「用户被登出且无凭据」的状态。
        new_session = await AuthenticationSession.create_from_request(request, bearer=account)

        # 作废该账户除新会话以外的全部会话（含发起改密的那个）。
        await (
            AuthenticationSession.filter(bearer=account, deleted=False, disabled=False)
            .exclude(id=new_session.id)
            .update(deleted=True)
        )
    response = json(
        "密码修改成功",
        {
            "must_change_password": False,
            "token_rotated": True,
        },
    )
    new_session.encode(response)
    issue_csrf_token(
        response,
        secure=bool(request.app.config.get("SESSION_COOKIE_SECURE", True)),
    )

    await record_auth_event(request, "change_password_success", account=account)
    return response


# 完成两步验证路由
@auth_bp.post("/validate-2fa")
async def on_two_factor_authentication(request):
    """
    完成客户端认证会话的二次验证
    """
    from app.services.audit import record_auth_event

    try:
        authentication_session = await fulfill_second_factor(request)
    except Exception:
        await record_auth_event(request, "two_step_failure", status="failure", detail="2FA 验证失败")
        raise
    await record_auth_event(request, "two_step_success", account=authentication_session.bearer)
    data = dict(authentication_session.bearer.json)
    data["must_change_password"] = bool(getattr(authentication_session.bearer, "must_change_password", False))
    response = json(
        "两步验证已完成! 您现在已通过验证。",
        data,
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

    from app.services.audit import record_auth_event

    await record_auth_event(request, "logout", account=authentication_session.bearer)
    return json("注销成功!", authentication_session.bearer.json)


# 获取关联认证会话路由
@auth_bp.post("/associated")
@requires_authentication()
async def on_get_associated_authentication_sessions(request):
    """
    获取与已登录账户关联的认证会话
    """
    authentication_sessions = await AuthenticationSession.get_associated(request.ctx.authentication_session.bearer)
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
