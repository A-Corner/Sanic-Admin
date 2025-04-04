#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
角色API资源模块，提供角色和权限管理功能
"""

from sanic.request import Request
from app.api import CRUDResource, APIResponse, v1_bp
from app.models import Role, Account
from app.api.validators import (
    validate_request,
    validate_path_param,
    Required,
    Length,
    Type,
    OneOf
)
from app.auth.authorization import check_permissions, check_roles
from typing import Dict, Any, List


class RoleResource(CRUDResource):
    """
    角色资源
    
    提供角色CRUD操作
    """
    model_class = Role
    resource_name = "角色"
    
    # 默认排序和分页
    default_sort_field = "name"
    default_sort_direction = "asc"
    default_page_size = 20
    
    # 搜索和过滤字段
    searchable_fields = ["name", "description"]
    
    # 创建和更新字段
    allowed_create_fields = ["name", "description", "permissions"]
    allowed_update_fields = ["description", "permissions"]
    
    # 必需字段
    required_create_fields = ["name", "permissions"]
    required_update_fields = []
    
    @classmethod
    def format_model(cls, model: Role) -> Dict[str, Any]:
        """
        格式化角色模型为字典
        
        Args:
            model: 角色模型实例
            
        Returns:
            Dict[str, Any]: 格式化的字典
        """
        return {
            "id": model.id,
            "name": model.name,
            "description": model.description,
            "permissions": model.permissions,
            "created_at": model.created_at,
            "updated_at": model.updated_at
        }
    
    async def get(self, request: Request, role_id: str = None):
        """
        获取角色或角色列表
        
        Args:
            request: Sanic请求对象
            role_id: 角色ID，如果不提供则获取列表
            
        Returns:
            Response: Sanic响应
        """
        # 使用权限检查装饰器
        @check_permissions("role", "read")
        async def get_role(request, role_id=None):
            return await super(RoleResource, self).get(request, role_id)
            
        return await get_role(request, role_id)
    
    async def post(self, request: Request):
        """
        创建新角色
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应
        """
        # 验证请求参数和权限
        @validate_request({
            "name": [Required(), Length(min_=2, max_=50)],
            "description": [Length(max_=200)],
            "permissions": [Required(), Type(dict)]
        })
        @check_permissions("role", "create")
        async def create_role(request):
            data = request.validated_data
            
            # 检查角色名是否已存在
            if await Role.filter(name=data["name"]).exists():
                return APIResponse.error(
                    message="角色名已存在",
                    error_code="ROLE_EXISTS",
                    status_code=400
                )
            
            # 验证权限格式
            permissions = data["permissions"]
            if not isinstance(permissions, dict):
                return APIResponse.error(
                    message="权限必须是字典格式，如 {'resource': ['action1', 'action2']}",
                    error_code="INVALID_PERMISSIONS_FORMAT",
                    status_code=400
                )
            
            # 验证权限值是否都是列表
            for resource, actions in permissions.items():
                if not isinstance(actions, list):
                    return APIResponse.error(
                        message=f"资源'{resource}'的操作必须是列表格式",
                        error_code="INVALID_ACTIONS_FORMAT",
                        status_code=400
                    )
            
            # 创建角色
            role = await Role.create(**data)
            
            return APIResponse.created(
                data=self.format_model(role),
                message="角色创建成功",
                location=f"/api/v1/roles/{role.id}"
            )
            
        return await create_role(request)
    
    async def put(self, request: Request, role_id: str):
        """
        更新角色
        
        Args:
            request: Sanic请求对象
            role_id: 角色ID
            
        Returns:
            Response: Sanic响应
        """
        # 验证请求参数和权限
        @validate_request({
            "description": [Length(max_=200)],
            "permissions": [Type(dict)]
        })
        @validate_path_param("role_id", [Required(), Type(int)])
        @check_permissions("role", "update")
        async def update_role(request, role_id):
            data = request.validated_data
            
            # 获取角色
            try:
                role = await self.get_model_by_id(role_id)
            except Exception as e:
                return APIResponse.error(
                    message=str(e),
                    error_code="ROLE_NOT_FOUND",
                    status_code=404
                )
            
            # 防止修改内置角色
            if role.name in ["admin", "user"]:
                return APIResponse.error(
                    message="不允许修改内置角色",
                    error_code="CANNOT_MODIFY_BUILTIN_ROLE",
                    status_code=403
                )
            
            # 验证权限格式
            if "permissions" in data:
                permissions = data["permissions"]
                if not isinstance(permissions, dict):
                    return APIResponse.error(
                        message="权限必须是字典格式，如 {'resource': ['action1', 'action2']}",
                        error_code="INVALID_PERMISSIONS_FORMAT",
                        status_code=400
                    )
                
                # 验证权限值是否都是列表
                for resource, actions in permissions.items():
                    if not isinstance(actions, list):
                        return APIResponse.error(
                            message=f"资源'{resource}'的操作必须是列表格式",
                            error_code="INVALID_ACTIONS_FORMAT",
                            status_code=400
                        )
            
            # 更新角色
            for key, value in data.items():
                setattr(role, key, value)
            
            await role.save()
            
            return APIResponse.success(
                data=self.format_model(role),
                message="角色更新成功"
            )
            
        return await update_role(request, role_id)
    
    async def delete(self, request: Request, role_id: str):
        """
        删除角色
        
        Args:
            request: Sanic请求对象
            role_id: 角色ID
            
        Returns:
            Response: Sanic响应
        """
        # 验证参数和权限
        @validate_path_param("role_id", [Required(), Type(int)])
        @check_permissions("role", "delete")
        async def delete_role(request, role_id):
            # 获取角色
            try:
                role = await self.get_model_by_id(role_id)
            except Exception as e:
                return APIResponse.error(
                    message=str(e),
                    error_code="ROLE_NOT_FOUND",
                    status_code=404
                )
            
            # 不允许删除内置角色
            if role.name in ["admin", "user"]:
                return APIResponse.error(
                    message="不允许删除内置角色",
                    error_code="CANNOT_DELETE_BUILTIN_ROLE",
                    status_code=403
                )
            
            # 检查是否有账户使用此角色
            accounts_count = await role.accounts.all().count()
            if accounts_count > 0:
                return APIResponse.error(
                    message=f"无法删除角色，因为有{accounts_count}个账户正在使用此角色",
                    error_code="ROLE_IN_USE",
                    status_code=400
                )
            
            # 删除角色
            await role.delete()
            
            return APIResponse.success(
                message="角色删除成功"
            )
            
        return await delete_role(request, role_id)


class RoleMembersResource(CRUDResource):
    """
    角色成员资源
    
    提供角色成员管理功能
    """
    model_class = Role
    resource_name = "角色成员"
    
    async def get(self, request: Request, role_id: str):
        """
        获取角色成员
        
        Args:
            request: Sanic请求对象
            role_id: 角色ID
            
        Returns:
            Response: Sanic响应
        """
        # 验证参数和权限
        @validate_path_param("role_id", [Required(), Type(int)])
        @check_permissions("role", "read")
        async def get_role_members(request, role_id):
            # 获取角色
            try:
                role = await self.get_model_by_id(role_id)
            except Exception as e:
                return APIResponse.error(
                    message=str(e),
                    error_code="ROLE_NOT_FOUND",
                    status_code=404
                )
            
            # 分页参数
            page, page_size = self.get_pagination_params(request)
            offset = (page - 1) * page_size
            
            # 获取角色成员
            accounts = await role.accounts.all().offset(offset).limit(page_size)
            total = await role.accounts.all().count()
            
            # 格式化账户数据
            from app.api.resources.account import AccountResource
            items = [AccountResource.format_model(account) for account in accounts]
            
            return APIResponse.list(
                items=items,
                total=total,
                page=page,
                page_size=page_size,
                message=f"获取'{role.name}'角色成员成功"
            )
            
        return await get_role_members(request, role_id)
    
    async def post(self, request: Request, role_id: str):
        """
        添加角色成员
        
        Args:
            request: Sanic请求对象
            role_id: 角色ID
            
        Returns:
            Response: Sanic响应
        """
        # 验证参数和权限
        @validate_request({
            "account_ids": [Required(), Type(list)]
        })
        @validate_path_param("role_id", [Required(), Type(int)])
        @check_permissions("role", "update")
        async def add_role_members(request, role_id):
            data = request.validated_data
            account_ids = data["account_ids"]
            
            # 验证账户ID列表
            if not all(isinstance(id_, int) for id_ in account_ids):
                return APIResponse.error(
                    message="账户ID列表必须包含整数",
                    error_code="INVALID_ACCOUNT_IDS",
                    status_code=400
                )
            
            # 获取角色
            try:
                role = await self.get_model_by_id(role_id)
            except Exception as e:
                return APIResponse.error(
                    message=str(e),
                    error_code="ROLE_NOT_FOUND",
                    status_code=404
                )
            
            # 获取账户
            accounts = await Account.filter(id__in=account_ids).all()
            
            # 检查是否所有账户都存在
            if len(accounts) != len(account_ids):
                found_ids = [account.id for account in accounts]
                missing_ids = [id_ for id_ in account_ids if id_ not in found_ids]
                return APIResponse.error(
                    message=f"以下账户ID不存在: {missing_ids}",
                    error_code="ACCOUNTS_NOT_FOUND",
                    status_code=404
                )
            
            # 添加账户到角色
            for account in accounts:
                await role.accounts.add(account)
            
            return APIResponse.success(
                message=f"已将{len(accounts)}个账户添加到'{role.name}'角色"
            )
            
        return await add_role_members(request, role_id)
    
    async def delete(self, request: Request, role_id: str, account_id: str):
        """
        移除角色成员
        
        Args:
            request: Sanic请求对象
            role_id: 角色ID
            account_id: 账户ID
            
        Returns:
            Response: Sanic响应
        """
        # 验证参数和权限
        @validate_path_param("role_id", [Required(), Type(int)])
        @validate_path_param("account_id", [Required(), Type(int)])
        @check_permissions("role", "update")
        async def remove_role_member(request, role_id, account_id):
            # 获取角色
            try:
                role = await self.get_model_by_id(role_id)
            except Exception as e:
                return APIResponse.error(
                    message=str(e),
                    error_code="ROLE_NOT_FOUND",
                    status_code=404
                )
            
            # 获取账户
            try:
                account = await Account.get(id=account_id)
            except Exception as e:
                return APIResponse.error(
                    message=f"账户不存在: {account_id}",
                    error_code="ACCOUNT_NOT_FOUND",
                    status_code=404
                )
            
            # 检查账户是否属于此角色
            if not await role.accounts.filter(id=account_id).exists():
                return APIResponse.error(
                    message=f"账户'{account.username}'不是'{role.name}'角色的成员",
                    error_code="NOT_ROLE_MEMBER",
                    status_code=400
                )
            
            # 移除账户
            await role.accounts.remove(account)
            
            return APIResponse.success(
                message=f"已将账户'{account.username}'从'{role.name}'角色中移除"
            )
            
        return await remove_role_member(request, role_id, account_id)


class AccountRolesResource(CRUDResource):
    """
    账户角色资源
    
    提供账户角色管理功能
    """
    model_class = Account
    resource_name = "账户角色"
    
    async def get(self, request: Request, account_id: str):
        """
        获取账户角色
        
        Args:
            request: Sanic请求对象
            account_id: 账户ID
            
        Returns:
            Response: Sanic响应
        """
        # 验证参数和权限
        @validate_path_param("account_id", [Required(), Type(int)])
        @check_permissions("account", "read")
        async def get_account_roles(request, account_id):
            # 获取账户
            try:
                account = await Account.get(id=account_id)
            except Exception as e:
                return APIResponse.error(
                    message=f"账户不存在: {account_id}",
                    error_code="ACCOUNT_NOT_FOUND",
                    status_code=404
                )
            
            # 获取账户的角色
            roles = await account.roles.all()
            
            # 格式化角色数据
            role_data = [RoleResource.format_model(role) for role in roles]
            
            return APIResponse.success(
                data=role_data,
                message=f"获取账户'{account.username}'的角色成功"
            )
            
        return await get_account_roles(request, account_id)
    
    async def post(self, request: Request, account_id: str):
        """
        添加账户角色
        
        Args:
            request: Sanic请求对象
            account_id: 账户ID
            
        Returns:
            Response: Sanic响应
        """
        # 验证参数和权限
        @validate_request({
            "role_ids": [Required(), Type(list)]
        })
        @validate_path_param("account_id", [Required(), Type(int)])
        @check_permissions("account", "update")
        async def add_account_roles(request, account_id):
            data = request.validated_data
            role_ids = data["role_ids"]
            
            # 验证角色ID列表
            if not all(isinstance(id_, int) for id_ in role_ids):
                return APIResponse.error(
                    message="角色ID列表必须包含整数",
                    error_code="INVALID_ROLE_IDS",
                    status_code=400
                )
            
            # 获取账户
            try:
                account = await Account.get(id=account_id)
            except Exception as e:
                return APIResponse.error(
                    message=f"账户不存在: {account_id}",
                    error_code="ACCOUNT_NOT_FOUND",
                    status_code=404
                )
            
            # 获取角色
            roles = await Role.filter(id__in=role_ids).all()
            
            # 检查是否所有角色都存在
            if len(roles) != len(role_ids):
                found_ids = [role.id for role in roles]
                missing_ids = [id_ for id_ in role_ids if id_ not in found_ids]
                return APIResponse.error(
                    message=f"以下角色ID不存在: {missing_ids}",
                    error_code="ROLES_NOT_FOUND",
                    status_code=404
                )
            
            # 添加角色到账户
            for role in roles:
                await account.roles.add(role)
            
            return APIResponse.success(
                message=f"已将{len(roles)}个角色添加到账户'{account.username}'"
            )
            
        return await add_account_roles(request, account_id)
    
    async def delete(self, request: Request, account_id: str, role_id: str):
        """
        移除账户角色
        
        Args:
            request: Sanic请求对象
            account_id: 账户ID
            role_id: 角色ID
            
        Returns:
            Response: Sanic响应
        """
        # 验证参数和权限
        @validate_path_param("account_id", [Required(), Type(int)])
        @validate_path_param("role_id", [Required(), Type(int)])
        @check_permissions("account", "update")
        async def remove_account_role(request, account_id, role_id):
            # 获取账户
            try:
                account = await Account.get(id=account_id)
            except Exception as e:
                return APIResponse.error(
                    message=f"账户不存在: {account_id}",
                    error_code="ACCOUNT_NOT_FOUND",
                    status_code=404
                )
            
            # 获取角色
            try:
                role = await Role.get(id=role_id)
            except Exception as e:
                return APIResponse.error(
                    message=f"角色不存在: {role_id}",
                    error_code="ROLE_NOT_FOUND",
                    status_code=404
                )
            
            # 检查账户是否拥有此角色
            if not await account.roles.filter(id=role_id).exists():
                return APIResponse.error(
                    message=f"账户'{account.username}'没有'{role.name}'角色",
                    error_code="NO_SUCH_ROLE",
                    status_code=400
                )
            
            # 移除角色
            await account.roles.remove(role)
            
            return APIResponse.success(
                message=f"已将'{role.name}'角色从账户'{account.username}'中移除"
            )
            
        return await remove_account_role(request, account_id, role_id)


# 注册路由
role_resource = RoleResource()
role_members_resource = RoleMembersResource()
account_roles_resource = AccountRolesResource()

v1_bp.add_route(role_resource.as_view(), "/roles/<role_id:int>", methods=["GET", "PUT", "DELETE"])
v1_bp.add_route(role_resource.as_view(), "/roles", methods=["GET", "POST"])

v1_bp.add_route(role_members_resource.as_view(), "/roles/<role_id:int>/members", methods=["GET", "POST"])
v1_bp.add_route(role_members_resource.as_view(), "/roles/<role_id:int>/members/<account_id:int>", methods=["DELETE"])

v1_bp.add_route(account_roles_resource.as_view(), "/accounts/<account_id:int>/roles", methods=["GET", "POST"])
v1_bp.add_route(account_roles_resource.as_view(), "/accounts/<account_id:int>/roles/<role_id:int>", methods=["DELETE"]) 