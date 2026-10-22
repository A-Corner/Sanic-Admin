#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
API模型文档生成器

用于从数据模型生成OpenAPI模式定义
"""

import inspect
import re
from typing import Dict, Any, Type, List, get_type_hints, get_origin, get_args
from pydantic import BaseModel, Field
from tortoise.models import Model
from tortoise.fields import Field as TortoiseField
from tortoise.fields.data import IntField, CharField, TextField, BooleanField, FloatField, JSONField, DatetimeField

# OpenAPI模式字典
_schemas: Dict[str, Dict[str, Any]] = {}


def register_schemas(schemas: Dict[str, Dict[str, Any]]) -> None:
    """
    注册模式到全局模式字典
    
    Args:
        schemas: 模式字典
    """
    global _schemas
    _schemas.update(schemas)


def get_schemas() -> Dict[str, Dict[str, Any]]:
    """
    获取所有已注册的模式
    
    Returns:
        模式字典
    """
    return _schemas


def register_model(model_class: Type[BaseModel], name: str = None) -> None:
    """
    从Pydantic模型生成模式并注册
    
    Args:
        model_class: Pydantic模型类
        name: 模式名称，默认使用模型类名
    """
    schema_name = name or model_class.__name__
    
    # 获取模型模式
    model_schema = model_class.model_json_schema()
    
    # 转换定义为OpenAPI格式
    openapi_schema = {
        "type": "object",
        "properties": {}
    }
    
    # 添加描述
    if model_class.__doc__:
        openapi_schema["description"] = inspect.getdoc(model_class)
    
    # 处理属性
    if "properties" in model_schema:
        openapi_schema["properties"] = model_schema["properties"]
    
    # 处理必需字段
    if "required" in model_schema:
        openapi_schema["required"] = model_schema["required"]
    
    # 注册模式
    _schemas[schema_name] = openapi_schema


def register_tortoise_model(model_class: Type[Model], name: str = None, 
                          exclude_fields: List[str] = None) -> None:
    """
    从Tortoise ORM模型生成模式并注册
    
    Args:
        model_class: Tortoise模型类
        name: 模式名称，默认使用模型类名
        exclude_fields: 要排除的字段列表
    """
    schema_name = name or model_class.__name__
    exclude_fields = exclude_fields or []
    
    # 创建模式
    openapi_schema = {
        "type": "object",
        "properties": {},
        "required": []
    }
    
    # 添加描述
    if model_class.__doc__:
        openapi_schema["description"] = inspect.getdoc(model_class)
    
    # 获取所有字段
    for field_name, field_obj in model_class._meta.fields_map.items():
        if field_name in exclude_fields:
            continue
        
        # 转换字段类型为OpenAPI类型
        field_schema = _tortoise_field_to_openapi(field_obj)
        
        # 添加字段描述
        if hasattr(field_obj, "description") and field_obj.description:
            field_schema["description"] = field_obj.description
        
        # 添加到属性
        openapi_schema["properties"][field_name] = field_schema
        
        # 检查是否是必需字段
        if not field_obj.null and not field_obj.default:
            openapi_schema["required"].append(field_name)
    
    # 如果没有必需字段，则删除required列表
    if not openapi_schema["required"]:
        del openapi_schema["required"]
    
    # 注册模式
    _schemas[schema_name] = openapi_schema


def _tortoise_field_to_openapi(field: TortoiseField) -> Dict[str, Any]:
    """
    将Tortoise ORM字段转换为OpenAPI模式
    
    Args:
        field: Tortoise字段对象
        
    Returns:
        OpenAPI字段模式
    """
    schema = {}
    
    # 判断字段类型
    if isinstance(field, IntField):
        schema["type"] = "integer"
        if hasattr(field, "constraints") and field.constraints.get("ge") is not None:
            schema["minimum"] = field.constraints.get("ge")
        if hasattr(field, "constraints") and field.constraints.get("le") is not None:
            schema["maximum"] = field.constraints.get("le")
    
    elif isinstance(field, (CharField, TextField)):
        schema["type"] = "string"
        if hasattr(field, "max_length") and field.max_length:
            schema["maxLength"] = field.max_length
    
    elif isinstance(field, BooleanField):
        schema["type"] = "boolean"
    
    elif isinstance(field, FloatField):
        schema["type"] = "number"
        schema["format"] = "float"
        if hasattr(field, "constraints") and field.constraints.get("ge") is not None:
            schema["minimum"] = field.constraints.get("ge")
        if hasattr(field, "constraints") and field.constraints.get("le") is not None:
            schema["maximum"] = field.constraints.get("le")
    
    elif isinstance(field, JSONField):
        schema["type"] = "object"
    
    elif isinstance(field, DatetimeField):
        schema["type"] = "string"
        schema["format"] = "date-time"
    
    else:
        # 默认当作字符串处理
        schema["type"] = "string"
    
    return schema


def register_error_schemas() -> None:
    """注册通用错误响应模式"""
    # 通用错误响应模式
    error_schema = {
        "type": "object",
        "description": "通用错误响应",
        "properties": {
            "success": {
                "type": "boolean",
                "description": "操作是否成功",
                "example": False
            },
            "code": {
                "type": "string",
                "description": "错误代码",
                "example": "INVALID_REQUEST"
            },
            "message": {
                "type": "string",
                "description": "错误消息",
                "example": "请求参数无效"
            },
            "errors": {
                "type": "object",
                "description": "详细错误信息",
                "example": {
                    "field_name": ["此字段不能为空"]
                }
            }
        },
        "required": ["success", "code", "message"]
    }
    
    # 验证错误模式
    validation_error_schema = {
        "type": "object",
        "description": "验证错误响应",
        "properties": {
            "success": {
                "type": "boolean",
                "description": "操作是否成功",
                "example": False
            },
            "code": {
                "type": "string",
                "description": "错误代码",
                "example": "VALIDATION_ERROR"
            },
            "message": {
                "type": "string",
                "description": "错误消息",
                "example": "请求参数验证失败"
            },
            "errors": {
                "type": "object",
                "description": "字段验证错误信息",
                "example": {
                    "username": ["用户名不能为空"],
                    "email": ["请输入有效的电子邮件地址"]
                }
            }
        },
        "required": ["success", "code", "message", "errors"]
    }
    
    # 注册模式
    _schemas.update({
        "Error": error_schema,
        "ValidationError": validation_error_schema
    })


def register_pagination_schemas() -> None:
    """注册分页响应模式"""
    # 分页响应模式
    pagination_schema = {
        "type": "object",
        "description": "分页响应",
        "properties": {
            "items": {
                "type": "array",
                "description": "数据项列表",
                "items": {
                    "type": "object"
                }
            },
            "total_count": {
                "type": "integer",
                "description": "总数据项数量",
                "example": 100
            },
            "page": {
                "type": "integer",
                "description": "当前页码",
                "example": 1
            },
            "page_size": {
                "type": "integer",
                "description": "每页数据项数量",
                "example": 10
            },
            "total_pages": {
                "type": "integer",
                "description": "总页数",
                "example": 10
            }
        },
        "required": ["items", "page", "page_size"]
    }
    
    # 注册模式
    _schemas["Pagination"] = pagination_schema 