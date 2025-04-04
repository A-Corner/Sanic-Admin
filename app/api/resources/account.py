#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
账户API资源模块，提供账户相关的API端点
"""

from sanic.request import Request
from app.api import CRUDResource, APIResponse, v1_bp
from app.models import Account
from app.api.validators import (
    validate_request, 
    validate_path_param,
    Required, 
    Length, 
    Email, 
    Type, 
    OneOf
)
from app.auth.authorization import check_permissions
from typing import Dict, Any, List


class AccountResource(CRUDResource):
    """
    账户资源
    
    提供账户CRUD操作
    """
    model_class = Account
    resource_name = "账户"
    
    # 默认排序和分页
    default_sort_field = "created_at"
    default_sort_direction = "desc"
    default_page_size = 20
    
    # 搜索和过滤字段
    searchable_fields = ["username", "email", "first_name", "last_name"]
    filterable_fields = ["is_active", "is_admin", "created_at", "updated_at"]
    
    # 创建和更新字段
    allowed_create_fields = ["username", "email", "password", "first_name", "last_name", 
                           "phone", "is_active", "is_admin"]
    allowed_update_fields = ["email", "first_name", "last_name", "phone", "is_active"]
    
    # 必需字段
    required_create_fields = ["username", "email", "password"]
    required_update_fields = []
    
    @classmethod
    def format_model(cls, model: Account) -> Dict[str, Any]:
        """
        格式化账户模型为字典
        
        Args:
            model: 账户模型实例
            
        Returns:
            Dict[str, Any]: 格式化的字典
        """
        data = {
            "id": model.id,
            "username": model.username,
            "email": model.email,
            "first_name": model.first_name,
            "last_name": model.last_name,
            "phone": model.phone,
            "is_active": model.is_active,
            "is_admin": model.is_admin,
            "created_at": model.created_at,
            "updated_at": model.updated_at
        }
        
        # 不包含敏感字段
        data.pop("password", None)
        
        return data
    
    async def get(self, request: Request, account_id: str = None):
        """
        获取账户或账户列表
        
        Args:
            request: Sanic请求对象
            account_id: 账户ID，如果不提供则获取列表
            
        Returns:
            Response: Sanic响应
        """
        # 使用认证检查装饰器
        @check_permissions("account", "read")
        async def get_account(request, account_id=None):
            return await super(AccountResource, self).get(request, account_id)
            
        return await get_account(request, account_id)
    
    async def post(self, request: Request):
        """
        创建新账户
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应
        """
        # 验证请求参数
        @validate_request({
            "username": [Required(), Length(min_=3, max_=50)],
            "email": [Required(), Email()],
            "password": [Required(), Length(min_=6, max_=100)],
            "first_name": [Length(max_=50)],
            "last_name": [Length(max_=50)],
            "phone": [Length(max_=20)],
            "is_active": [Type(bool)],
            "is_admin": [Type(bool)]
        })
        @check_permissions("account", "create")
        async def create_account(request):
            data = request.validated_data
            
            # 检查用户名是否已存在
            if await Account.filter(username=data["username"]).exists():
                return APIResponse.error(
                    message="用户名已存在",
                    error_code="USERNAME_EXISTS",
                    status_code=400
                )
            
            # 检查邮箱是否已存在
            if await Account.filter(email=data["email"]).exists():
                return APIResponse.error(
                    message="邮箱已存在",
                    error_code="EMAIL_EXISTS",
                    status_code=400
                )
            
            # 创建账户
            account = await Account.create(**data)
            
            # 设置密码哈希
            account.set_password(data["password"])
            await account.save()
            
            return APIResponse.created(
                data=self.format_model(account),
                message="账户创建成功",
                location=f"/api/v1/accounts/{account.id}"
            )
            
        return await create_account(request)
    
    async def put(self, request: Request, account_id: str):
        """
        更新账户
        
        Args:
            request: Sanic请求对象
            account_id: 账户ID
            
        Returns:
            Response: Sanic响应
        """
        # 验证请求参数和权限
        @validate_request({
            "email": [Email()],
            "first_name": [Length(max_=50)],
            "last_name": [Length(max_=50)],
            "phone": [Length(max_=20)],
            "is_active": [Type(bool)]
        })
        @validate_path_param("account_id", [Required(), Type(int)])
        @check_permissions("account", "update")
        async def update_account(request, account_id):
            data = request.validated_data
            
            # 获取账户
            try:
                account = await self.get_model_by_id(account_id)
            except Exception as e:
                return APIResponse.error(
                    message=str(e),
                    error_code="ACCOUNT_NOT_FOUND",
                    status_code=404
                )
            
            # 检查邮箱是否已存在
            if "email" in data and data["email"] != account.email:
                if await Account.filter(email=data["email"]).exists():
                    return APIResponse.error(
                        message="邮箱已存在",
                        error_code="EMAIL_EXISTS",
                        status_code=400
                    )
            
            # 更新账户
            for key, value in data.items():
                # 不允许修改密码，需要使用专门的密码更新接口
                if key != "password":
                    setattr(account, key, value)
            
            await account.save()
            
            return APIResponse.success(
                data=self.format_model(account),
                message="账户更新成功"
            )
            
        return await update_account(request, account_id)
    
    async def delete(self, request: Request, account_id: str):
        """
        删除账户
        
        Args:
            request: Sanic请求对象
            account_id: 账户ID
            
        Returns:
            Response: Sanic响应
        """
        # 验证参数和权限
        @validate_path_param("account_id", [Required(), Type(int)])
        @check_permissions("account", "delete")
        async def delete_account(request, account_id):
            # 获取账户
            try:
                account = await self.get_model_by_id(account_id)
            except Exception as e:
                return APIResponse.error(
                    message=str(e),
                    error_code="ACCOUNT_NOT_FOUND",
                    status_code=404
                )
            
            # 不允许删除管理员账户
            if account.is_admin:
                return APIResponse.error(
                    message="不允许删除管理员账户",
                    error_code="DELETE_ADMIN_FORBIDDEN",
                    status_code=403
                )
            
            # 删除账户
            await account.delete()
            
            return APIResponse.success(
                message="账户删除成功"
            )
            
        return await delete_account(request, account_id)


class AccountPasswordResource(CRUDResource):
    """
    账户密码资源
    
    提供密码更新功能
    """
    model_class = Account
    resource_name = "账户密码"
    
    async def put(self, request: Request, account_id: str):
        """
        更新账户密码
        
        Args:
            request: Sanic请求对象
            account_id: 账户ID
            
        Returns:
            Response: Sanic响应
        """
        # 验证请求参数和权限
        @validate_request({
            "current_password": [Required()],
            "new_password": [Required(), Length(min_=6, max_=100)]
        })
        @validate_path_param("account_id", [Required(), Type(int)])
        @check_permissions("account", "update")
        async def update_password(request, account_id):
            data = request.validated_data
            current_password = data["current_password"]
            new_password = data["new_password"]
            
            # 获取账户
            try:
                account = await self.get_model_by_id(account_id)
            except Exception as e:
                return APIResponse.error(
                    message=str(e),
                    error_code="ACCOUNT_NOT_FOUND",
                    status_code=404
                )
            
            # 验证当前密码
            if not account.verify_password(current_password):
                return APIResponse.error(
                    message="当前密码不正确",
                    error_code="INVALID_PASSWORD",
                    status_code=400
                )
            
            # 设置新密码
            account.set_password(new_password)
            await account.save()
            
            return APIResponse.success(
                message="密码更新成功"
            )
            
        return await update_password(request, account_id)


class AccountMeResource(CRUDResource):
    """
    当前用户资源
    
    提供当前登录用户的信息和操作
    """
    model_class = Account
    resource_name = "当前用户"
    
    async def get(self, request: Request):
        """
        获取当前用户信息
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应
        """
        # 这个接口不需要额外的权限检查，只要用户已认证就可以
        if not hasattr(request.ctx, "authentication_session"):
            return APIResponse.error(
                message="未认证",
                error_code="UNAUTHORIZED",
                status_code=401
            )
        
        account = request.ctx.authentication_session.bearer
        
        # 获取用户的角色列表
        roles = await account.roles.all()
        role_data = [{"id": role.id, "name": role.name, "description": role.description} 
                    for role in roles]
        
        # 获取用户的权限
        from app.auth.authorization import get_account_permissions
        permissions = await get_account_permissions(account)
        
        # 格式化用户信息
        account_data = AccountResource.format_model(account)
        account_data["roles"] = role_data
        account_data["permissions"] = permissions
        
        return APIResponse.success(
            data=account_data,
            message="获取当前用户信息成功"
        )
    
    async def put(self, request: Request):
        """
        更新当前用户信息
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应
        """
        # 验证请求参数
        @validate_request({
            "email": [Email()],
            "first_name": [Length(max_=50)],
            "last_name": [Length(max_=50)],
            "phone": [Length(max_=20)]
        })
        async def update_me(request):
            # 检查用户是否已认证
            if not hasattr(request.ctx, "authentication_session"):
                return APIResponse.error(
                    message="未认证",
                    error_code="UNAUTHORIZED",
                    status_code=401
                )
            
            account = request.ctx.authentication_session.bearer
            data = request.validated_data
            
            # 检查邮箱是否已存在
            if "email" in data and data["email"] != account.email:
                if await Account.filter(email=data["email"]).exists():
                    return APIResponse.error(
                        message="邮箱已存在",
                        error_code="EMAIL_EXISTS",
                        status_code=400
                    )
            
            # 更新用户信息
            for key, value in data.items():
                # 不允许修改某些关键字段
                if key not in ["is_active", "is_admin", "username", "password"]:
                    setattr(account, key, value)
            
            await account.save()
            
            return APIResponse.success(
                data=AccountResource.format_model(account),
                message="用户信息更新成功"
            )
            
        return await update_me(request)


# 注册路由
account_resource = AccountResource()
account_password_resource = AccountPasswordResource()
account_me_resource = AccountMeResource()

v1_bp.add_route(account_resource.as_view(), "/accounts/<account_id:int>", methods=["GET", "PUT", "DELETE"])
v1_bp.add_route(account_resource.as_view(), "/accounts", methods=["GET", "POST"])
v1_bp.add_route(account_password_resource.as_view(), "/accounts/<account_id:int>/password", methods=["PUT"])
v1_bp.add_route(account_me_resource.as_view(), "/accounts/me", methods=["GET", "PUT"]) 