#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
授权模块，提供基于角色的权限控制功能

权限数据格式：``{资源: [操作, ...]}``，操作含 ``"all"`` 表示该资源全部权限；
``Account.is_admin`` 为 True 的账户拥有全部权限。
"""
import functools
from sanic.request import Request
from app.models import Account, Role
from app.services.exceptions import (
    AuthorizationError,
    InsufficientPermissionsError,
    RoleRequiredError
)
from app.auth.authentication import authenticate_request, find_request


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
    """
    if account.is_admin:
        return True
    granted = (await get_account_permissions(account)).get(resource)
    if not granted:
        return False
    if "all" in granted:
        return True
    return all(action in granted for action in actions)


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
