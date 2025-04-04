#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
系统设置API资源模块，提供系统参数配置管理功能
"""

from sanic.request import Request
from app.api import CRUDResource, APIResponse, v1_bp
from app.models import SystemSetting
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
from typing import Dict, Any, List, Optional as OptType
import json


class SettingResource(CRUDResource):
    """
    系统设置资源
    
    提供系统参数配置的CRUD操作
    """
    model_class = SystemSetting
    resource_name = "系统设置"
    
    # 默认排序和分页
    default_sort_field = "key"
    default_sort_direction = "asc"
    default_page_size = 50
    
    # 搜索和过滤字段
    searchable_fields = ["key", "description"]
    filterable_fields = ["category", "is_public"]
    
    # 创建和更新字段
    allowed_create_fields = ["key", "value", "value_type", "description", "category", "is_public"]
    allowed_update_fields = ["value", "value_type", "description", "category", "is_public"]
    
    # 必需字段
    required_create_fields = ["key", "value", "value_type"]
    required_update_fields = ["value"]
    
    @classmethod
    def format_model(cls, model: SystemSetting) -> Dict[str, Any]:
        """
        格式化系统设置模型为字典
        
        Args:
            model: 系统设置模型实例
            
        Returns:
            Dict[str, Any]: 格式化的字典
        """
        # 根据值类型格式化值
        formatted_value = model.value
        try:
            if model.value_type == "int":
                formatted_value = int(model.value)
            elif model.value_type == "float":
                formatted_value = float(model.value)
            elif model.value_type == "bool":
                formatted_value = model.value.lower() == "true"
            elif model.value_type == "json":
                formatted_value = json.loads(model.value)
        except (ValueError, json.JSONDecodeError):
            # 如果转换失败，保持原始字符串值
            pass
        
        return {
            "id": model.id,
            "key": model.key,
            "value": formatted_value,
            "raw_value": model.value,
            "value_type": model.value_type,
            "description": model.description,
            "category": model.category,
            "is_public": model.is_public,
            "created_at": model.created_at,
            "updated_at": model.updated_at
        }
    
    async def get(self, request: Request, setting_id: str = None):
        """
        获取系统设置或设置列表
        
        Args:
            request: Sanic请求对象
            setting_id: 设置ID，如果不提供则获取列表
            
        Returns:
            Response: Sanic响应
        """
        # 检查是否是获取公开设置的请求
        is_public_only = request.args.get("public_only", "false").lower() == "true"
        
        # 如果仅请求公开设置，则不需要权限检查
        if is_public_only:
            async def get_public_settings(request, setting_id=None):
                if setting_id:
                    try:
                        setting = await self.get_model_by_id(setting_id)
                        if not setting.is_public:
                            return APIResponse.error(
                                message="无权访问非公开设置",
                                error_code="PERMISSION_DENIED",
                                status_code=403
                            )
                        return APIResponse.success(
                            data=self.format_model(setting),
                            message="获取系统设置成功"
                        )
                    except Exception as e:
                        return APIResponse.error(
                            message=str(e),
                            error_code="SETTING_NOT_FOUND",
                            status_code=404
                        )
                else:
                    # 添加公开设置筛选条件
                    request.ctx.filter_conditions = {"is_public": True}
                    return await super(SettingResource, self).get(request)
                
            return await get_public_settings(request, setting_id)
        else:
            # 使用权限检查装饰器
            @check_permissions("setting", "read")
            async def get_setting(request, setting_id=None):
                return await super(SettingResource, self).get(request, setting_id)
                
            return await get_setting(request, setting_id)
    
    async def post(self, request: Request):
        """
        创建新的系统设置
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应
        """
        # 验证请求参数和权限
        @validate_request({
            "key": [Required(), Length(min_=1, max_=50)],
            "value": [Required()],
            "value_type": [Required(), OneOf(["string", "int", "float", "bool", "json"])],
            "description": [Optional(), Length(max_=255)],
            "category": [Optional(), Length(max_=50)],
            "is_public": [Optional(), Type(bool)]
        })
        @check_permissions("setting", "create")
        async def create_setting(request):
            data = request.validated_data
            
            # 检查键是否已存在
            if await SystemSetting.filter(key=data["key"]).exists():
                return APIResponse.error(
                    message="设置键已存在",
                    error_code="SETTING_KEY_EXISTS",
                    status_code=400
                )
            
            # 验证值类型匹配
            error = self._validate_value_type(data["value"], data["value_type"])
            if error:
                return APIResponse.error(
                    message=error,
                    error_code="INVALID_VALUE_TYPE",
                    status_code=400
                )
            
            # 如果是JSON类型，将对象转换为字符串存储
            if data["value_type"] == "json" and isinstance(data["value"], (dict, list)):
                data["value"] = json.dumps(data["value"])
            else:
                # 确保其他类型也转为字符串存储
                data["value"] = str(data["value"])
            
            # 设置默认分类和公开性
            if "category" not in data:
                data["category"] = "general"
            if "is_public" not in data:
                data["is_public"] = False
            
            # 创建设置
            setting = await SystemSetting.create(**data)
            
            return APIResponse.created(
                data=self.format_model(setting),
                message="创建系统设置成功",
                location=f"/api/v1/settings/{setting.id}"
            )
            
        return await create_setting(request)
    
    async def put(self, request: Request, setting_id: str):
        """
        更新系统设置
        
        Args:
            request: Sanic请求对象
            setting_id: 设置ID
            
        Returns:
            Response: Sanic响应
        """
        # 验证请求参数和权限
        @validate_request({
            "value": [Required()],
            "value_type": [Optional(), OneOf(["string", "int", "float", "bool", "json"])],
            "description": [Optional(), Length(max_=255)],
            "category": [Optional(), Length(max_=50)],
            "is_public": [Optional(), Type(bool)]
        })
        @validate_path_param("setting_id", [Required(), Type(int)])
        @check_permissions("setting", "update")
        async def update_setting(request, setting_id):
            data = request.validated_data
            
            # 获取设置
            try:
                setting = await self.get_model_by_id(setting_id)
            except Exception as e:
                return APIResponse.error(
                    message=str(e),
                    error_code="SETTING_NOT_FOUND",
                    status_code=404
                )
            
            # 如果提供了值类型，则验证值类型匹配
            value_type = data.get("value_type", setting.value_type)
            error = self._validate_value_type(data["value"], value_type)
            if error:
                return APIResponse.error(
                    message=error,
                    error_code="INVALID_VALUE_TYPE",
                    status_code=400
                )
            
            # 如果是JSON类型，将对象转换为字符串存储
            if value_type == "json" and isinstance(data["value"], (dict, list)):
                data["value"] = json.dumps(data["value"])
            else:
                # 确保其他类型也转为字符串存储
                data["value"] = str(data["value"])
            
            # 更新设置
            for key, value in data.items():
                setattr(setting, key, value)
            
            await setting.save()
            
            return APIResponse.success(
                data=self.format_model(setting),
                message="更新系统设置成功"
            )
            
        return await update_setting(request, setting_id)
    
    async def delete(self, request: Request, setting_id: str):
        """
        删除系统设置
        
        Args:
            request: Sanic请求对象
            setting_id: 设置ID
            
        Returns:
            Response: Sanic响应
        """
        # 验证参数和权限
        @validate_path_param("setting_id", [Required(), Type(int)])
        @check_permissions("setting", "delete")
        async def delete_setting(request, setting_id):
            # 获取设置
            try:
                setting = await self.get_model_by_id(setting_id)
            except Exception as e:
                return APIResponse.error(
                    message=str(e),
                    error_code="SETTING_NOT_FOUND",
                    status_code=404
                )
            
            # 删除设置
            await setting.delete()
            
            return APIResponse.success(
                message="删除系统设置成功"
            )
            
        return await delete_setting(request, setting_id)
    
    def _validate_value_type(self, value: Any, value_type: str) -> OptType[str]:
        """
        验证值是否匹配指定的类型
        
        Args:
            value: 要验证的值
            value_type: 值的类型
            
        Returns:
            Optional[str]: 如果验证失败，返回错误信息，否则返回None
        """
        try:
            if value_type == "int":
                int(value)
            elif value_type == "float":
                float(value)
            elif value_type == "bool":
                if not isinstance(value, bool) and str(value).lower() not in ["true", "false"]:
                    return "布尔值必须是 true 或 false"
            elif value_type == "json":
                if isinstance(value, (dict, list)):
                    # 已经是JSON对象，无需验证
                    pass
                else:
                    # 尝试解析JSON字符串
                    json.loads(str(value))
        except (ValueError, json.JSONDecodeError):
            return f"值 '{value}' 不符合类型 '{value_type}'"
        
        return None


class SettingByKeyResource:
    """
    按键获取设置资源
    
    提供通过键名获取系统设置的功能
    """
    
    async def get(self, request: Request, key: str):
        """
        通过键获取系统设置
        
        Args:
            request: Sanic请求对象
            key: 设置键名
            
        Returns:
            Response: Sanic响应
        """
        # 检查是否需要权限
        setting = await SystemSetting.filter(key=key).first()
        if not setting:
            return APIResponse.error(
                message=f"设置键 '{key}' 不存在",
                error_code="SETTING_NOT_FOUND",
                status_code=404
            )
        
        # 如果不是公开设置，则需要权限检查
        if not setting.is_public:
            @check_permissions("setting", "read")
            async def get_private_setting(request):
                return APIResponse.success(
                    data=SettingResource.format_model(setting),
                    message="获取系统设置成功"
                )
            
            return await get_private_setting(request)
        else:
            # 公开设置无需权限检查
            return APIResponse.success(
                data=SettingResource.format_model(setting),
                message="获取系统设置成功"
            )
    
    async def put(self, request: Request, key: str):
        """
        通过键更新系统设置
        
        Args:
            request: Sanic请求对象
            key: 设置键名
            
        Returns:
            Response: Sanic响应
        """
        # 验证请求参数和权限
        @validate_request({
            "value": [Required()]
        })
        @check_permissions("setting", "update")
        async def update_setting_by_key(request):
            data = request.validated_data
            
            # 获取设置
            setting = await SystemSetting.filter(key=key).first()
            if not setting:
                return APIResponse.error(
                    message=f"设置键 '{key}' 不存在",
                    error_code="SETTING_NOT_FOUND",
                    status_code=404
                )
            
            # 验证值类型匹配
            error = SettingResource._validate_value_type(data["value"], setting.value_type)
            if error:
                return APIResponse.error(
                    message=error,
                    error_code="INVALID_VALUE_TYPE",
                    status_code=400
                )
            
            # 如果是JSON类型，将对象转换为字符串存储
            if setting.value_type == "json" and isinstance(data["value"], (dict, list)):
                setting.value = json.dumps(data["value"])
            else:
                # 确保其他类型也转为字符串存储
                setting.value = str(data["value"])
            
            await setting.save()
            
            return APIResponse.success(
                data=SettingResource.format_model(setting),
                message="更新系统设置成功"
            )
            
        return await update_setting_by_key(request)


class SettingBulkResource:
    """
    批量设置资源
    
    提供批量获取和更新系统设置的功能
    """
    
    async def get(self, request: Request):
        """
        批量获取系统设置
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应
        """
        # 解析键名列表
        keys = request.args.get("keys", "").split(",")
        if not keys or keys == [""]:
            return APIResponse.error(
                message="必须提供设置键列表",
                error_code="MISSING_KEYS",
                status_code=400
            )
        
        # 检查是否仅获取公开设置
        public_only = request.args.get("public_only", "false").lower() == "true"
        
        # 查询设置
        query = SystemSetting.filter(key__in=keys)
        if public_only:
            query = query.filter(is_public=True)
            settings = await query.all()
        else:
            # 需要权限检查
            @check_permissions("setting", "read")
            async def get_settings_with_permission(request):
                return await query.all()
            
            settings = await get_settings_with_permission(request)
        
        # 格式化结果
        result = {setting.key: SettingResource.format_model(setting) for setting in settings}
        
        # 检查是否有未找到的键
        found_keys = {setting.key for setting in settings}
        missing_keys = [key for key in keys if key and key not in found_keys]
        
        return APIResponse.success(
            data={
                "settings": result,
                "missing_keys": missing_keys
            },
            message="批量获取系统设置成功"
        )
    
    async def put(self, request: Request):
        """
        批量更新系统设置
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应
        """
        @validate_request({
            "settings": [Required(), Type(dict)]
        })
        @check_permissions("setting", "update")
        async def update_bulk_settings(request):
            data = request.validated_data
            settings_data = data["settings"]
            
            if not settings_data:
                return APIResponse.error(
                    message="必须提供要更新的设置",
                    error_code="MISSING_SETTINGS",
                    status_code=400
                )
            
            # 获取所有相关设置
            keys = list(settings_data.keys())
            existing_settings = await SystemSetting.filter(key__in=keys).all()
            existing_keys = {setting.key: setting for setting in existing_settings}
            
            # 处理更新和错误
            updated = []
            errors = []
            
            for key, value in settings_data.items():
                if key not in existing_keys:
                    errors.append({
                        "key": key,
                        "error": "设置不存在"
                    })
                    continue
                
                setting = existing_keys[key]
                
                # 验证值类型
                error = SettingResource._validate_value_type(value, setting.value_type)
                if error:
                    errors.append({
                        "key": key,
                        "error": error
                    })
                    continue
                
                # 更新值
                if setting.value_type == "json" and isinstance(value, (dict, list)):
                    setting.value = json.dumps(value)
                else:
                    setting.value = str(value)
                
                await setting.save()
                updated.append(SettingResource.format_model(setting))
            
            return APIResponse.success(
                data={
                    "updated": updated,
                    "errors": errors
                },
                message=f"已成功更新 {len(updated)} 项设置，{len(errors)} 项失败"
            )
            
        return await update_bulk_settings(request)


# 注册路由
setting_resource = SettingResource()
setting_by_key_resource = SettingByKeyResource()
setting_bulk_resource = SettingBulkResource()

v1_bp.add_route(setting_resource.as_view(), "/settings/<setting_id:int>", methods=["GET", "PUT", "DELETE"])
v1_bp.add_route(setting_resource.as_view(), "/settings", methods=["GET", "POST"])
v1_bp.add_route(setting_by_key_resource.get, "/settings/key/<key:string>", methods=["GET"])
v1_bp.add_route(setting_by_key_resource.put, "/settings/key/<key:string>", methods=["PUT"])
v1_bp.add_route(setting_bulk_resource.get, "/settings/bulk", methods=["GET"])
v1_bp.add_route(setting_bulk_resource.put, "/settings/bulk", methods=["PUT"]) 