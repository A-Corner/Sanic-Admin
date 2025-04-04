#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
授权模块，提供基于角色的权限控制功能
"""
import functools
from sanic.request import Request
from app.models import Account, Role
from app.services.exceptions import (
    AuthorizationError,
    InsufficientPermissionsError,
    RoleRequiredError
)
from app.auth.authentication import requires_authentication


async def assign_role(account: Account, role: Role):
    """
    将角色分配给账户
    
    Args:
        account: 账户实例
        role: 角色实例
        
    Returns:
        bool: 分配成功返回True，如果角色已分配则返回False
    """
    # 检查是否已经分配了该角色
    if await account.roles.filter(id=role.id).exists():
        return False
    
    # 分配角色
    await account.roles.add(role)
    return True


async def remove_role(account: Account, role: Role):
    """
    从账户中移除角色
    
    Args:
        account: 账户实例
        role: 角色实例
        
    Returns:
        bool: 移除成功返回True，如果账户没有该角色则返回False
    """
    # 检查是否已经分配了该角色
    if not await account.roles.filter(id=role.id).exists():
        return False
    
    # 移除角色
    await account.roles.remove(role)
    return True


async def get_account_roles(account: Account):
    """
    获取账户的所有角色
    
    Args:
        account: 账户实例
        
    Returns:
        list: 角色列表
    """
    return await account.roles.all()


async def get_account_permissions(account: Account):
    """
    获取账户的所有权限
    
    合并账户拥有的所有角色的权限
    
    Args:
        account: 账户实例
        
    Returns:
        dict: 权限字典，格式为 {资源: [操作列表]}
    """
    roles = await account.roles.all()
    
    # 合并所有角色的权限
    permissions = {}
    for role in roles:
        for resource, actions in role.permissions.items():
            if resource not in permissions:
                permissions[resource] = []
            
            # 合并操作列表，去重
            permissions[resource] = list(set(permissions[resource] + actions))
    
    return permissions


def check_roles(*required_roles):
    """
    检查账户是否具有指定角色的装饰器
    
    Args:
        *required_roles: 所需角色名称列表
        
    Returns:
        函数装饰器
    """
    def decorator(handler):
        @functools.wraps(handler)
        @requires_authentication()
        async def wrapper(request, *args, **kwargs):
            # 确保请求中有认证会话
            if not hasattr(request.ctx, "authentication_session"):
                raise AuthorizationError("需要认证")
            
            account = request.ctx.authentication_session.bearer
            
            # 获取账户的所有角色
            account_roles = await account.roles.all()
            account_role_names = [role.name for role in account_roles]
            
            # 检查是否有所需的任何一个角色
            for role_name in required_roles:
                if role_name in account_role_names:
                    return await handler(request, *args, **kwargs)
            
            raise RoleRequiredError(f"需要以下角色之一: {', '.join(required_roles)}")
        
        return wrapper
    
    return decorator


def check_permissions(resource, *required_actions):
    """
    检查账户是否具有指定资源的指定操作权限的装饰器
    
    Args:
        resource: 资源名称
        *required_actions: 所需操作列表
        
    Returns:
        函数装饰器
    """
    def decorator(handler):
        @functools.wraps(handler)
        @requires_authentication()
        async def wrapper(request, *args, **kwargs):
            # 确保请求中有认证会话
            if not hasattr(request.ctx, "authentication_session"):
                raise AuthorizationError("需要认证")
            
            account = request.ctx.authentication_session.bearer
            
            # 获取账户的所有权限
            permissions = await get_account_permissions(account)
            
            # 检查是否有资源的权限
            if resource not in permissions:
                raise InsufficientPermissionsError(f"没有 {resource} 的权限")
            
            # 检查是否有所需的所有操作权限
            account_actions = permissions[resource]
            if "all" in account_actions:  # 全部权限
                return await handler(request, *args, **kwargs)
            
            for action in required_actions:
                if action not in account_actions:
                    raise InsufficientPermissionsError(f"没有 {resource} 的 {action} 权限")
            
            return await handler(request, *args, **kwargs)
        
        return wrapper
    
    return decorator


def has_role(account: Account, role_name: str):
    """
    检查账户是否具有指定角色
    
    Args:
        account: 账户实例
        role_name: 角色名称
        
    Returns:
        bool: 如果账户具有指定角色，则返回True，否则返回False
    """
    async def _check():
        roles = await account.roles.all()
        return any(role.name == role_name for role in roles)
    
    return _check


def has_permission(account: Account, resource: str, action: str):
    """
    检查账户是否具有指定资源的指定操作权限
    
    Args:
        account: 账户实例
        resource: 资源名称
        action: 操作名称
        
    Returns:
        bool: 如果账户具有指定权限，则返回True，否则返回False
    """
    async def _check():
        permissions = await get_account_permissions(account)
        
        # 检查是否有资源的权限
        if resource not in permissions:
            return False
        
        # 检查是否有操作权限
        account_actions = permissions[resource]
        return "all" in account_actions or action in account_actions
    
    return _check 