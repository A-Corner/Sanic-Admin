#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
用户个人信息API资源模块，提供个人资料管理功能
"""

from sanic.request import Request
from app.api import CRUDResource, APIResponse, v1_bp
from app.models import Account, Profile
from app.auth.authentication import get_authenticated_account
from app.api.validators import (
    validate_request,
    validate_path_param,
    Required,
    Length,
    Type,
    OneOf,
    Optional
)
from app.auth.authorization import check_permissions, check_roles
from typing import Dict, Any, List


class ProfileResource(CRUDResource):
    """
    用户个人信息资源
    
    提供用户个人资料CRUD操作
    """
    model_class = Profile
    resource_name = "个人资料"
    
    # 搜索和过滤字段
    searchable_fields = ["full_name", "mobile_phone", "address"]
    
    # 创建和更新字段
    allowed_update_fields = [
        "full_name", "nickname", "avatar", "mobile_phone", 
        "tel_phone", "gender", "birth_date", "address", 
        "work_start_date", "introduction", "homepage"
    ]
    
    @classmethod
    def format_model(cls, model: Profile) -> Dict[str, Any]:
        """
        格式化个人资料模型为字典
        
        Args:
            model: 个人资料模型实例
            
        Returns:
            Dict[str, Any]: 格式化的字典
        """
        return {
            "id": model.id,
            "account_id": model.account_id,
            "full_name": model.full_name,
            "nickname": model.nickname,
            "avatar": model.avatar,
            "mobile_phone": model.mobile_phone,
            "tel_phone": model.tel_phone,
            "gender": model.gender,
            "birth_date": model.birth_date.isoformat() if model.birth_date else None,
            "address": model.address,
            "work_start_date": model.work_start_date.isoformat() if model.work_start_date else None,
            "introduction": model.introduction,
            "homepage": model.homepage,
            "created_at": model.created_at,
            "updated_at": model.updated_at
        }
    
    async def get(self, request: Request, profile_id: str = None):
        """
        获取个人资料
        
        Args:
            request: Sanic请求对象
            profile_id: 个人资料ID，如果不提供则获取当前用户的资料
            
        Returns:
            Response: Sanic响应
        """
        # 使用权限检查装饰器
        @check_permissions("profile", "read")
        async def get_profile(request, profile_id=None):
            # 如果没有指定profile_id，获取当前用户的资料
            if not profile_id:
                account = await get_authenticated_account(request)
                if not account:
                    return APIResponse.error(
                        message="未认证的请求",
                        error_code="UNAUTHENTICATED",
                        status_code=401
                    )
                
                profile = await Profile.filter(account_id=account.id).first()
                if not profile:
                    # 如果不存在，创建一个空的个人资料
                    profile = await Profile.create(account_id=account.id)
                
                return APIResponse.success(
                    data=self.format_model(profile),
                    message="获取个人资料成功"
                )
            
            # 获取指定ID的个人资料
            try:
                profile_id = int(profile_id)
                profile = await self.get_model_by_id(profile_id)
            except Exception as e:
                return APIResponse.error(
                    message=str(e),
                    error_code="PROFILE_NOT_FOUND",
                    status_code=404
                )
            
            # 检查是否是当前用户或有管理权限
            account = await get_authenticated_account(request)
            if account.id != profile.account_id and not await check_permissions("profile", "manage", request=request, check_only=True):
                return APIResponse.error(
                    message="无权访问此个人资料",
                    error_code="PERMISSION_DENIED",
                    status_code=403
                )
            
            return APIResponse.success(
                data=self.format_model(profile),
                message="获取个人资料成功"
            )
            
        return await get_profile(request, profile_id)
    
    async def put(self, request: Request, profile_id: str = None):
        """
        更新个人资料
        
        Args:
            request: Sanic请求对象
            profile_id: 个人资料ID
            
        Returns:
            Response: Sanic响应
        """
        # 验证请求参数和权限
        @validate_request({
            "full_name": [Optional(), Length(max_=50)],
            "nickname": [Optional(), Length(max_=50)],
            "avatar": [Optional(), Length(max_=255)],
            "mobile_phone": [Optional(), Length(max_=20)],
            "tel_phone": [Optional(), Length(max_=20)],
            "gender": [Optional(), OneOf(["male", "female", "other", "unknown"])],
            "birth_date": [Optional(), Type(str)],
            "address": [Optional(), Length(max_=255)],
            "work_start_date": [Optional(), Type(str)],
            "introduction": [Optional(), Length(max_=500)],
            "homepage": [Optional(), Length(max_=255)]
        })
        @check_permissions("profile", "update")
        async def update_profile(request, profile_id=None):
            account = await get_authenticated_account(request)
            data = request.validated_data
            
            # 获取个人资料
            if profile_id:
                try:
                    profile_id = int(profile_id)
                    profile = await self.get_model_by_id(profile_id)
                    
                    # 检查是否有权限更新他人资料
                    if account.id != profile.account_id and not await check_permissions("profile", "manage", request=request, check_only=True):
                        return APIResponse.error(
                            message="无权更新此个人资料",
                            error_code="PERMISSION_DENIED",
                            status_code=403
                        )
                except Exception as e:
                    return APIResponse.error(
                        message=str(e),
                        error_code="PROFILE_NOT_FOUND",
                        status_code=404
                    )
            else:
                # 获取当前用户的个人资料
                profile = await Profile.filter(account_id=account.id).first()
                if not profile:
                    # 如果不存在，创建一个空的个人资料
                    profile = await Profile.create(account_id=account.id)
            
            # 更新个人资料
            for key, value in data.items():
                setattr(profile, key, value)
            
            await profile.save()
            
            return APIResponse.success(
                data=self.format_model(profile),
                message="更新个人资料成功"
            )
            
        return await update_profile(request, profile_id)


class MyProfileResource:
    """
    当前用户个人信息资源
    
    提供获取和更新当前用户个人资料的API
    """
    
    async def get(self, request: Request):
        """
        获取当前用户的个人资料
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应
        """
        profile_resource = ProfileResource()
        return await profile_resource.get(request)
    
    async def put(self, request: Request):
        """
        更新当前用户的个人资料
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应
        """
        profile_resource = ProfileResource()
        return await profile_resource.put(request)


# 注册路由
profile_resource = ProfileResource()
my_profile_resource = MyProfileResource()

v1_bp.add_route(profile_resource.as_view(), "/profiles/<profile_id:int>", methods=["GET", "PUT"])
v1_bp.add_route(my_profile_resource.get, "/me/profile", methods=["GET"])
v1_bp.add_route(my_profile_resource.put, "/me/profile", methods=["PUT"]) 