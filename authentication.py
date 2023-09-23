# 导入必要的模块和库
# Used for decoding Base64-encoded credentials (用于解码 Base64 编码的凭据)
import base64
import functools  # Used for creating decorators (用于创建装饰器)
# Regular expression library used for text validation (正则表达式库，用于验证文本格式)
import re

from argon2 import PasswordHasher  # Used for password hashing (用于密码哈希)
# Used for password verification exceptions (用于密码验证异常)
from argon2.exceptions import VerifyMismatchError
from sanic import Sanic  # Sanic Web Framework (Sanic Web 框架)
from sanic.log import logger  # Used for logging (用于记录日志)
from sanic.request import Request  # Handling HTTP requests (处理 HTTP 请求)
# Tortoise ORM exceptions (Tortoise ORM 异常)
from tortoise.exceptions import DoesNotExist
# Import security configuration (导入安全配置)
from configuration import config as security_config
from exceptions import (
    NotFoundError,
    CredentialsError,
    DeactivatedError,
    SecondFactorFulfilledError,
)  # Import custom exceptions (导入自定义异常)
# Import database models (导入数据库模型)
from models import Account, AuthenticationSession, TwoStepSession, Role
# Utility function for getting client IP address (用于获取客户端 IP 地址的实用函数)
from utils import get_ip

# Create a password hasher object for secure password storage and validation (创建密码哈希对象，用于安全存储和验证密码)
password_hasher = PasswordHasher()


def validate_email(email: str) -> str:
    """
    验证电子邮件格式。

    Args:
        email (str): 正在验证的电子邮件。

    Returns:
        email

    Raises:
        CredentialsError
    """
    if not re.search(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
        raise CredentialsError("Please use a valid email address.", 400)
    return email


def validate_username(username: str) -> str:
    """
    验证用户名格式。

    Args:
        username (str): 正在验证的用户名。

    Returns:
        username

    Raises:
        CredentialsError
    """
    if not re.search(r"^[A-Za-z0-9_-]{3,32}$", username):
        raise CredentialsError(
            "Username must be between 3-32 characters and cannot contain special characters other than _ or -.",
            400,
        )
    return username


# 验证电话号码格式
def validate_phone(phone: str) -> str:
    """
    验证电话号码格式。

    Args:
        phone (str): 正在验证的电话号码。

    Returns:
        phone

    Raises:
        CredentialsError
    """
    if phone and not re.search(
        r"^(\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}$", phone
    ):
        raise CredentialsError("Please use a valid phone number.", 400)
    return phone


def validate_password(password: str) -> str:
    """
    验证密码要求。

    Args:
        password (str): 正在验证的密码。

    Returns:
        password

    Raises:
        CredentialsError
    """
    if not re.search(r"^(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&+=!]).*$", password):
        raise CredentialsError(
            "Password must contain one uppercase letter, one number, and one special character",
            400,
        )
    return password


async def register(
    request: Request, verified: bool = False, disabled: bool = False
) -> Account:
    """
    注册一个新的可以登录的帐户。

    Args:
        request (Request): Sanic 请求参数。请求体应包含以下参数：email、username、password、phone（包括国家/地区代码）。
        verified (bool): 设置正在注册的帐户的验证要求。
        disabled (bool): 渲染正在注册的帐户不可用。

    Returns:
        account

    Raises:
        CredentialsError
    """
    # 检查是否存在具有相同电子邮件、用户名或电话号码的帐户
    email_lower = validate_email(request.form.get("email").lower())
    if await Account.filter(email=email_lower).exists():
        raise CredentialsError(
            "An account with this email already exists.", 409)
    elif await Account.filter(
        username=validate_username(request.form.get("username"))
    ).exists():
        raise CredentialsError(
            "An account with this username already exists.", 409)
    elif (
        request.form.get("phone")
        and await Account.filter(
            phone=validate_phone(request.form.get("phone"))
        ).exists()
    ):
        raise CredentialsError(
            "An account with this phone number already exists.", 409)
    validate_password(request.form.get("password"))
    return await Account.create(
        email=email_lower,
        username=request.form.get("username"),
        password=password_hasher.hash(request.form.get("password")),
        phone=request.form.get("phone"),
        verified=verified,
        disabled=disabled,
    )


async def login(
    request: Request, account: Account = None, require_second_factor: bool = False
) -> AuthenticationSession:
    """
    使用电子邮件或用户名（如果已启用）和密码登录。

    Args:
        request (Request): Sanic 请求参数。登录凭证通过授权头获取。
        account (Account): 正在登录的帐户，覆盖通过表单数据检索电子邮件或用户名的帐户。
        require_second_factor (bool): 决定登录时身份验证会话的第二因素要求。

    Returns:
        authentication_session

    Raises:
        CredentialsError
        NotFoundError
        DeletedError
        UnverifiedError
        DisabledError
    """
    logger.info(f"\n「调试信息」 -- > {request.headers}")
    if not request.headers.get("Authorization"):
        raise CredentialsError("No credentials provided.")
    if request.headers.get("Authorization", None):
        try:
            authorization_type, credentials = request.headers.get(
                "Authorization").split() or (None, None)
        except ValueError as e:
            raise CredentialsError("Invalid authorization header.") from e
    if authorization_type == "Basic":
        email_or_username, password = (
            base64.b64decode(credentials).decode().split(":")
        )
    else:
        raise CredentialsError("Invalid authorization type.")
    if not account:
        try:
            account = await Account.get_via_email(email_or_username.lower())
        except NotFoundError as e:
            if security_config.ALLOW_LOGIN_WITH_USERNAME:
                account = await Account.get_via_username(email_or_username)
            else:
                raise e
    try:
        password_hasher.verify(account.password, password)
        if password_hasher.check_needs_rehash(account.password):
            account.password = password_hasher.hash(password)
            await account.save(update_fields=["password"])
        account.validate()
        return await AuthenticationSession.new(
            request, account, requires_second_factor=require_second_factor
        )
    except VerifyMismatchError as exc:
        logger.warning(
            f"Client ({get_ip(request)}) login password attempt was incorrect."
        )
        raise CredentialsError("Incorrect password.", 401) from exc


async def logout(request: Request) -> AuthenticationSession:
    """
    注销客户端的身份验证会话。

    Args:
        request (Request): Sanic 请求参数。

    Raises:
        NotFoundError
        JWTDecodeError
        DeactivatedError

    Returns:
        authentication_session
    """
    authentication_session = await AuthenticationSession.decode(request)
    if not authentication_session.active:
        raise DeactivatedError("Already logged out.", 403)
    authentication_session.active = False
    await authentication_session.save(update_fields=["active"])
    return authentication_session


async def authenticate(request: Request) -> AuthenticationSession:
    """
    验证客户端的身份验证会话和帐户。

    Args:
        request (Request): Sanic 请求参数。

    Returns:
        authentication_session

    Raises:
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        UnverifiedError
        DisabledError
        SecondFactorRequiredError
    """
    authentication_session = await AuthenticationSession.decode(request)
    authentication_session.validate()
    authentication_session.bearer.validate()
    return authentication_session


async def fulfill_second_factor(request: Request) -> AuthenticationSession:
    """
    通过两步会话代码完成客户端身份验证会话的第二因素要求。

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
        SecondFactorFulfilledError

    Returns:
         authentication_session
    """
    authentication_session = await AuthenticationSession.decode(request)
    two_step_session = await TwoStepSession.decode(request)
    if not authentication_session.requires_second_factor:
        raise SecondFactorFulfilledError()
    two_step_session.validate()
    await two_step_session.check_code(request, request.form.get("code"))
    authentication_session.requires_second_factor = False
    await authentication_session.save(update_fields=["requires_second_factor"])
    return authentication_session


def requires_authentication(arg=None):
    """
    验证客户端的身份验证会话和帐户。

    示例：
        此方法不会直接调用，而是作为装饰器使用：

            @app.post('api/authenticate')
            @requires_authentication
            async def on_authenticate(request):
                return text('用户已经通过身份验证！')

    Raises:
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        UnverifiedError
        DisabledError
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(request, *args, **kwargs):
            request.ctx.authentication_session = await authenticate(request)
            return await func(request, *args, **kwargs)

        return wrapper

    return decorator(arg) if callable(arg) else decorator


def create_initial_admin_account(app: Sanic) -> None:
    """
    创建初始的管理员帐户，可以登录并具有完全的管理访问权限。

    Args:
        app (Sanic): 主要的 Sanic 应用程序实例。
    """
    @app.listener("before_server_start")
    async def generate(app, loop):
        try:
            role = await Role.filter(name="SAdmin").get()
        except DoesNotExist:
            role = await Role.create(
                description="Has permissions for control of any aspect of the API. Use with caution.",
                permissions="*:*",
                name="SAdmin",
            )
        try:
            account = await Account.filter(
                email=security_config.INITIAL_ADMIN_EMAIL
            ).get()
            await account.fetch_related("roles")
            if role not in account.roles:
                await account.roles.add(role)
                logger.warning(
                    'Role "SAdmin" for the initial admin account was removed and has been restored.'
                )
        except DoesNotExist:
            account = await Account.create(
                username="SAdmin",
                email=security_config.INITIAL_ADMIN_EMAIL,
                password=PasswordHasher().hash(security_config.INITIAL_ADMIN_PASSWORD),
                verified=True,
            )
            await account.roles.add(role)
            logger.info("Created initial admin account.")
