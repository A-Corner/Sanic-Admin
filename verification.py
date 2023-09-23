import functools
from contextlib import suppress
from sanic.request import Request
from exceptions import (
    JWTDecodeError,
    NotFoundError,
    VerifiedError,
)
from models import (
    Account,
    TwoStepSession,
    CaptchaSession,
)


async def request_two_step_verification(
    request: Request, account: Account = None
) -> TwoStepSession:
    """
    创建一个两步验证会话并停用客户端当前的两步验证会话（如果存在）。
    Args:
        request (Request): Sanic 请求参数。请求体应包含以下参数：email。
        account (Account): 与新验证会话相关联的帐户。如果为None，则从请求表单中的电子邮件或现有的两步验证会话中检索帐户。
    Raises:
        NotFoundError

    Returns:
         two_step_session
    """
    with suppress(NotFoundError, JWTDecodeError):   # 用于忽略指定的异常
        two_step_session = await TwoStepSession.decode(request)  # 解码两步验证会话
        if two_step_session.active:   # 如果两步验证会话处于活动状态
            await two_step_session.deactivate()  # 停用两步验证会话
        if not account:  # 如果没有帐户
            account = two_step_session.bearer   # 获取两步验证会话的载体
    if request.form.get("email") or not account:    # 如果请求表单中有电子邮件或没有帐户
        # 通过电子邮件获取帐户
        account = await Account.get_via_email(request.form.get("email"))
    # 创建新的两步验证会话
    two_step_session = await TwoStepSession.new(request, account)
    return two_step_session  # 返回两步验证会话


async def two_step_verification(request: Request) -> TwoStepSession:
    """
    验证两步验证尝试。
    Args:
        request (Request): Sanic 请求参数。请求体应包含以下参数：code。
    Raises:
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        UnverifiedError
        DisabledError
        ChallengeError
        MaxedOutChallengeError
    Returns:
         two_step_session
    """
    two_step_session = await TwoStepSession.decode(request)  # 解码两步验证会话
    two_step_session.validate()  # 验证两步验证会话
    two_step_session.bearer.validate()  # 验证载体-->帐户
    # 检查两步验证会话代码
    await two_step_session.check_code(request, request.form.get("code"))
    return two_step_session  # 返回两步验证会话


def requires_two_step_verification(arg=None):
    """
    验证两步验证尝试的装饰器。
    示例：
        此方法不会直接调用，而是用作装饰器：
            @app.post("api/verification/attempt")
            @requires_two_step_verification
            async def on_verified(request):
                response = json("Two-step verification attempt successful!", two_step_session.json())
                return response
    Raises:
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        UnverifiedError
        DisabledError
        ChallengeError
        MaxedOutChallengeError
    """

    def decorator(func):    # 装饰器
        @functools.wraps(func)  # 保留原始函数的名称和文档字符串
        async def wrapper(request, *args, **kwargs):    # 包装器
            # 验证两步验证尝试
            request.ctx.two_step_session = await two_step_verification(request)
            return await func(request, *args, **kwargs)  # 返回函数

        return wrapper

    if callable(arg):
        return decorator(arg)
    else:
        return decorator


async def verify_account(request: Request) -> TwoStepSession:
    """
    通过两步验证会话代码验证客户端帐户。
    验证帐户并将其标记为已验证
    Args:
        request (Request): Sanic 请求参数。请求体应包含以下参数：code。
    Raises:
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        ChallengeError
        MaxedOutChallengeError
        VerifiedError
    Returns:
         two_step_session
    """
    two_step_session = await TwoStepSession.decode(request)  # 解码两步验证会话
    if two_step_session.bearer.verified:    # 如果载体已验证
        raise VerifiedError()   # 抛出已验证错误
    two_step_session.validate()  # 验证两步验证会话
    # 检查两步验证会话代码
    await two_step_session.check_code(request, request.form.get("code"))
    two_step_session.bearer.verified = True   # 将载体标记为已验证
    await two_step_session.bearer.save(update_fields=["verified"])  # 保存载体
    return two_step_session  # 返回两步验证会话

# 创建验证码会话并停用客户端当前的验证码会话（如果存在）


async def request_captcha(request: Request) -> CaptchaSession:  # 请求验证码
    """
    创建验证码会话并停用客户端当前的验证码会话（如果存在）。

    Args:
        request (Request): Sanic 请求参数。

    Returns:
        captcha_session
    """
    with suppress(NotFoundError, JWTDecodeError):   # 用于忽略指定的异常
        captcha_session = await CaptchaSession.decode(request)  # 解码验证码会话
        if captcha_session.active:  # 如果验证码会话处于活动状态
            await captcha_session.deactivate()  # 停用验证码会话
    return await CaptchaSession.new(request)    # 创建新的验证码会话

# 验证验证码挑战尝试


async def captcha(request: Request) -> CaptchaSession:
    """
    验证验证码挑战尝试。

    Args:
        request (Request): Sanic 请求参数。请求体应包含以下参数：captcha。

    Raises:
        DeletedError
        ExpiredError
        DeactivatedError
        JWTDecodeError
        NotFoundError
        ChallengeError
        MaxedOutChallengeError

    Returns:
        captcha_session
    """
    captcha_session = await CaptchaSession.decode(request)  # 解码验证码会话
    captcha_session.validate()  # 验证验证码会话
    # 检查验证码
    await captcha_session.check_code(request, request.form.get("captcha"))
    return captcha_session  # 返回验证码会话

# 要求进行验证码挑战的装饰器


def requires_captcha(arg=None):
    """
    验证验证码挑战尝试的装饰器。
    示例：
        此方法不会直接调用，而是用作装饰器：

            @app.post("api/captcha/attempt")
            @requires_captcha
            async def on_captcha_attempt(request):
                return json("Captcha attempt successful!", captcha_session.json())
    Raises:
        DeletedError
        ExpiredError
        DeactivatedError
        JWTDecodeError
        NotFoundError
        ChallengeError
        MaxedOutChallengeError
    """

    def decorator(func):
        @functools.wraps(func)  # 保留原始函数的名称和文档字符串
        async def wrapper(request, *args, **kwargs):    # 包装器
            request.ctx.captcha_session = await captcha(request)    # 验证验证码挑战尝试
            return await func(request, *args, **kwargs)

        return wrapper

    if callable(arg):
        return decorator(arg)   # 返回装饰器
    else:
        return decorator    # 返回装饰器
