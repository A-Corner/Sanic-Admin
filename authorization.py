import functools  # Used for creating decorators (用于创建装饰器)
import logging  # Logging module (日志模块)
from fnmatch import fnmatch  # Used for pattern matching (用于模式匹配)

from sanic.request import Request  # Handling HTTP requests (处理 HTTP 请求)
# Tortoise ORM exceptions (Tortoise ORM 异常)
from tortoise.exceptions import DoesNotExist

# Import custom authentication function (导入自定义身份验证函数)
from authentication import authenticate
# Import custom authorization exception (导入自定义授权异常)
from exceptions import AuthorizationError
# Import database models (导入数据库模型)
from models import Account, AuthenticationSession, Role
# Utility function for getting client IP address (用于获取客户端 IP 地址的实用函数)
from utils import get_ip

# 检查客户端是否具有足够权限执行操作


async def check_permissions(
    request: Request, *required_permissions: str
) -> AuthenticationSession:
    """
    鉴权客户端并确定帐户是否具有足够的权限执行操作。

    Args:
        request (Request): Sanic 请求参数。
        *required_permissions (Tuple[str, ...]): 授权操作所需的权限。

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
        AuthorizationError
    """
    authentication_session = await authenticate(request)  # 鉴权客户端
    # 获取客户端的角色
    roles = await authentication_session.bearer.roles.filter(deleted=False).all()
    for role in roles:  # 遍历客户端的角色
        for required_permission, role_permission in zip(
            required_permissions, role.permissions.split(", ")
        ):  # 遍历客户端的角色的权限
            if fnmatch(required_permission, role_permission):  # 如果权限匹配
                return authentication_session  # 返回鉴权客户端
    logging.warning(f"客户端 ({get_ip(request)}) 权限不足。")
    raise AuthorizationError("权限不足，无法执行此操作。")

# 检查客户端是否具有足够的角色执行操作


async def check_roles(request: Request, *required_roles: str) -> AuthenticationSession:
    """
    鉴权客户端并确定帐户是否具有足够的角色执行操作。

    Args:
        request (Request): Sanic 请求参数。
        *required_roles (Tuple[str, ...]): 授权操作所需的角色。

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
        AuthorizationError
    """
    authentication_session = await authenticate(request)
    roles = await authentication_session.bearer.roles.filter(deleted=False).all()
    for role in roles:
        if role.name in required_roles:
            return authentication_session
    logging.warning(f"客户端 ({get_ip(request)}) 角色不足。")
    raise AuthorizationError("角色不足，无法执行此操作。")

# 要求具有特定权限的装饰器


def require_permissions(*required_permissions: str):
    """
    鉴权客户端并确定帐户是否具有足够的权限执行操作。

    Args:
        *required_permissions (Tuple[str, ...]): 授权操作所需的权限。

    Example:
        此方法不会直接调用，而是作为装饰器使用：

            @app.post("api/auth/perms")
            @require_permissions("admin:update", "employee:add")
            async def on_require_perms(request):
                return text("帐户允许执行操作。")

    Raises:
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        UnverifiedError
        DisabledError
        AuthorizationError
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(request, *args, **kwargs):
            request.ctx.authentication_session = await check_permissions(
                request, *required_permissions
            )
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator

# 要求具有特定角色的装饰器


def require_roles(*required_roles: str):
    """
    鉴权客户端并确定帐户是否具有足够的角色执行操作。

    Args:
        *required_roles (Tuple[str, ...]): 授权操作所需的角色。

    Example:
        此方法不会直接调用，而是作为装饰器使用：

            @app.post("api/auth/roles")
            @require_roles("Admin", "Moderator")
            async def on_require_roles(request):
                return text("帐户允许执行操作")

    Raises:
        NotFoundError
        JWTDecodeError
        DeletedError
        ExpiredError
        DeactivatedError
        UnverifiedError
        DisabledError
        AuthorizationError
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(request, *args, **kwargs):
            request.ctx.authentication_session = await check_roles(
                request, *required_roles
            )
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator

# 分配角色给帐户


async def assign_role(
    name: str, account: Account, permissions: str = None, description: str = None
) -> Role:
    """
    为帐户分配角色。如果角色不存在，则会创建。
    Args:
        name (str): 与帐户关联的角色名称。
        account (Account): 与创建的角色关联的帐户。
        permissions (str): 与帐户关联的角色的权限。权限必须用逗号分隔，并以通配符格式表示。
        description (str): 与帐户关联的角色的描述。

    Returns:
        role (Role): 创建或关联的角色实例。
    """
    try:
        role = await Role.filter(name=name).get()
    except DoesNotExist:
        role = await Role.create(
            description=description, permissions=permissions, name=name
        )
    await account.roles.add(role)
    return role
