#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
授权模块，提供基于角色的权限控制功能

权限数据格式：``{资源: [操作, ...]}``，操作含 ``"all"`` 表示该资源全部权限；
``Account.is_admin`` 为 True 的账户拥有全部权限。
"""
import functools
from sanic.log import logger
from sanic.request import Request
from app.models import Account, Role
from app.services.exceptions import (
    AuthorizationError,
    InsufficientPermissionsError,
    RoleRequiredError
)
from app.auth.authentication import authenticate_request, find_request
from app.auth.permissions import (
    admin_all_permissions,
    effective_permissions,
    permission_granted,
)


async def assign_role(account: Account, role: Role):
    """
    将角色分配给账户

    Returns:
        bool: 分配成功返回True，如果角色已分配则返回False
    """
    if await account.roles.filter(id=role.id).exists():
        return False
    await account.roles.add(role)
    return True


async def remove_role(account: Account, role: Role):
    """
    从账户中移除角色

    Returns:
        bool: 移除成功返回True，如果账户没有该角色则返回False
    """
    if not await account.roles.filter(id=role.id).exists():
        return False
    await account.roles.remove(role)
    return True


async def get_account_roles(account: Account):
    """
    获取账户的所有角色

    Returns:
        list: 角色列表
    """
    return await account.roles.all()


async def get_account_permissions(account: Account):
    """
    获取账户的所有权限，合并账户拥有的所有（未删除）角色的权限

    Returns:
        dict: 权限字典，格式为 {资源: [操作列表]}
    """
    roles = await account.roles.filter(deleted=False)

    permissions = {}
    for role in roles:
        for resource, actions in (role.permissions or {}).items():
            merged = set(permissions.get(resource, [])) | set(actions)
            permissions[resource] = sorted(merged)
    return permissions


#: 内置管理员角色名（app.auth.authentication.create_initial_admin_account 使用同一个名字）
ADMIN_ROLE_NAME = "admin"

#: 管理员角色权限是否已同步过。模块级标志位，避免每次请求都查库。
_admin_role_synced = False


async def sync_admin_role_permissions(force: bool = False) -> bool:
    """
    把内置 admin 角色同步为注册表里的全量权限。

    历史上 admin 角色的 permissions 写死为 ``{"users": [...], "roles": [...],
    "settings": [...]}``，与当前资源名（``account`` / ``setting`` 等）不一致，
    导致非 admin 账户即便被授予 admin 角色也拿不到实际权限。

    这里做**惰性同步**：首次需要时检查一次并写入，之后不再查库
    （用模块级标志位；进程重启后重新检查一次）。

    Args:
        force: 为 True 时忽略标志位强制重新同步

    Returns:
        bool: 是否发生了同步写入
    """
    global _admin_role_synced

    if _admin_role_synced and not force:
        return False

    role = await Role.filter(name=ADMIN_ROLE_NAME, deleted=False).first()
    if role is None:
        _admin_role_synced = True
        return False

    target = admin_all_permissions()
    if role.permissions == target:
        _admin_role_synced = True
        return False

    role.permissions = target
    await role.save(update_fields=["permissions"])
    _admin_role_synced = True
    logger.info(f"已同步内置 admin 角色权限为注册表全量权限（{len(target)} 个资源）")
    return True


async def has_role(account: Account, *role_names: str) -> bool:
    """
    检查账户是否具有指定角色之一（管理员账户视为拥有所有角色）
    """
    if account.is_admin:
        return True
    names = {role.name for role in await account.roles.filter(deleted=False)}
    return any(name in names for name in role_names)


async def has_permission(account: Account, resource: str, *actions: str) -> bool:
    """
    检查账户是否具有指定资源的全部指定操作权限（管理员账户拥有全部权限）

    权限判定使用 ``app.auth.permissions`` 的归一化口径：子资源（如
    ``system:database:connectionpool``）折叠到基资源（``system:database``）
    后再比对，使同一功能的读/写能被同一份授权覆盖。
    """
    if account.is_admin:
        return True

    # 惰性同步内置 admin 角色的权限（首次调用时写库，之后走标志位）
    await sync_admin_role_permissions()

    granted = await get_account_permissions(account)
    effective = effective_permissions(granted)
    return all(permission_granted(effective, resource, action) for action in actions)


def _guard(check, args, kwargs, func):
    """生成认证 + 授权检查后再调用处理函数的协程。"""
    async def run():
        session = await authenticate_request(find_request(args))
        await check(session.bearer)
        return await func(*args, **kwargs)
    return run()


def check_roles(*required_roles):
    """
    要求账户拥有指定角色之一的装饰器（未认证 401，无角色 403）
    """
    async def check(account):
        if not await has_role(account, *required_roles):
            raise RoleRequiredError(f"需要以下角色之一: {', '.join(required_roles)}")

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            return await _guard(check, args, kwargs, func)
        return wrapper
    return decorator


def check_permissions(resource, *required_actions, request: Request = None, check_only: bool = False):
    """
    要求账户拥有指定资源的全部指定操作权限。

    * 装饰器用法：``@check_permissions("role", "read")``，未认证 401，权限不足 403。
    * 函数用法：``await check_permissions("file", "manage", request=request, check_only=True)``，
      ``check_only=True`` 时返回 bool 而不抛出权限不足异常；未认证仍抛 401。
    """
    async def check(account):
        if not await has_permission(account, resource, *required_actions):
            actions = ", ".join(required_actions)
            raise InsufficientPermissionsError(f"没有 {resource} 的 {actions} 权限")

    if request is not None:
        async def run():
            session = await authenticate_request(request)
            try:
                await check(session.bearer)
            except AuthorizationError:
                if check_only:
                    return False
                raise
            return True
        return run()

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            return await _guard(check, args, kwargs, func)
        return wrapper
    return decorator


def requires_permission(permission: str):
    """
    要求账户拥有 ``"资源:操作"`` 形式权限的装饰器，最后一个冒号之后为操作，之前为资源，
    例如 ``"system:database:query"`` 表示资源 ``system:database`` 的 ``query`` 操作；
    不含冒号时按资源的 ``all`` 操作检查。
    """
    resource, sep, action = permission.rpartition(":")
    if not sep:
        resource, action = permission, "all"
    return check_permissions(resource, action)
