#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
API装饰器模块

提供用于标记和描述API端点的装饰器，用于生成API文档
"""

import functools
import inspect
from typing import Callable, Dict, Any, List, Type, Optional, Union
from pydantic import BaseModel


def api_tags(*tags: str) -> Callable:
    """
    指定API标签的装饰器
    
    Args:
        *tags: API标签列表
    
    Returns:
        装饰后的函数
    """
    def decorator(func: Callable) -> Callable:
        if not hasattr(func, "__api_spec__"):
            func.__api_spec__ = {}
        func.__api_spec__["tags"] = list(tags)
        return func
    return decorator


def api_exclude() -> Callable:
    """
    从API文档中排除该路由的装饰器
    
    Returns:
        装饰后的函数
    """
    def decorator(func: Callable) -> Callable:
        if not hasattr(func, "__api_spec__"):
            func.__api_spec__ = {}
        func.__api_spec__["exclude"] = True
        return func
    return decorator


def api_summary(summary: str) -> Callable:
    """
    设置API摘要的装饰器
    
    Args:
        summary: API摘要文本
    
    Returns:
        装饰后的函数
    """
    def decorator(func: Callable) -> Callable:
        if not hasattr(func, "__api_spec__"):
            func.__api_spec__ = {}
        func.__api_spec__["summary"] = summary
        return func
    return decorator


def api_description(description: str) -> Callable:
    """
    设置API详细描述的装饰器
    
    Args:
        description: API详细描述文本
    
    Returns:
        装饰后的函数
    """
    def decorator(func: Callable) -> Callable:
        if not hasattr(func, "__api_spec__"):
            func.__api_spec__ = {}
        func.__api_spec__["description"] = description
        return func
    return decorator


def api_body(
    model: Type[BaseModel],
    content_type: str = "application/json",
    required: bool = True,
    description: str = None
) -> Callable:
    """
    指定API请求体模型的装饰器
    
    Args:
        model: Pydantic请求体模型类
        content_type: 内容类型，默认为"application/json"
        required: 请求体是否必需
        description: 请求体描述
        
    Returns:
        装饰后的函数
    """
    def decorator(func: Callable) -> Callable:
        if not hasattr(func, "__api_spec__"):
            func.__api_spec__ = {}
        
        if "requestBody" not in func.__api_spec__:
            func.__api_spec__["requestBody"] = {
                "content": {},
                "required": required
            }
            
        if description:
            func.__api_spec__["requestBody"]["description"] = description
            
        # 添加内容类型
        func.__api_spec__["requestBody"]["content"][content_type] = {
            "schema": {
                "$ref": f"#/components/schemas/{model.__name__}"
            }
        }
        
        # 记录模型以便注册
        if "models" not in func.__api_spec__:
            func.__api_spec__["models"] = []
        func.__api_spec__["models"].append(model)
        
        return func
    return decorator


def api_response(
    status_code: int = 200,
    model: Type[BaseModel] = None,
    description: str = None,
    content_type: str = "application/json",
    array: bool = False
) -> Callable:
    """
    指定API响应的装饰器
    
    Args:
        status_code: HTTP状态码，默认为200
        model: Pydantic响应模型类
        description: 响应描述
        content_type: 内容类型，默认为"application/json"
        array: 是否为数组响应
        
    Returns:
        装饰后的函数
    """
    def decorator(func: Callable) -> Callable:
        if not hasattr(func, "__api_spec__"):
            func.__api_spec__ = {}
        
        if "responses" not in func.__api_spec__:
            func.__api_spec__["responses"] = {}
        
        # 创建响应定义
        response_def = {}
        
        if description:
            response_def["description"] = description
        else:
            # 默认描述
            response_def["description"] = f"Status code {status_code} response"
        
        # 添加模型模式
        if model:
            response_def["content"] = {
                content_type: {
                    "schema": {}
                }
            }
            
            if array:
                response_def["content"][content_type]["schema"] = {
                    "type": "array",
                    "items": {
                        "$ref": f"#/components/schemas/{model.__name__}"
                    }
                }
            else:
                response_def["content"][content_type]["schema"] = {
                    "$ref": f"#/components/schemas/{model.__name__}"
                }
            
            # 记录模型以便注册
            if "models" not in func.__api_spec__:
                func.__api_spec__["models"] = []
            func.__api_spec__["models"].append(model)
        
        # 添加到响应定义
        func.__api_spec__["responses"][str(status_code)] = response_def
        
        return func
    return decorator


def api_response_list(
    status_code: int = 200,
    model: Type[BaseModel] = None,
    description: str = None,
    content_type: str = "application/json"
) -> Callable:
    """
    指定API列表响应的装饰器（简化版的数组响应）
    
    Args:
        status_code: HTTP状态码，默认为200
        model: Pydantic响应模型类
        description: 响应描述
        content_type: 内容类型，默认为"application/json"
        
    Returns:
        装饰后的函数
    """
    return api_response(
        status_code=status_code,
        model=model,
        description=description,
        content_type=content_type,
        array=True
    )


def api_response_pagination(
    model: Type[BaseModel],
    status_code: int = 200,
    description: str = None,
    content_type: str = "application/json"
) -> Callable:
    """
    指定分页API响应的装饰器
    
    Args:
        model: 分页项的Pydantic模型类
        status_code: HTTP状态码，默认为200
        description: 响应描述
        content_type: 内容类型，默认为"application/json"
        
    Returns:
        装饰后的函数
    """
    def decorator(func: Callable) -> Callable:
        if not hasattr(func, "__api_spec__"):
            func.__api_spec__ = {}
        
        if "responses" not in func.__api_spec__:
            func.__api_spec__["responses"] = {}
        
        # 创建响应定义
        response_def = {}
        
        if description:
            response_def["description"] = description
        else:
            # 默认描述
            response_def["description"] = "分页响应"
        
        # 添加模型模式
        response_def["content"] = {
            content_type: {
                "schema": {
                    "allOf": [
                        {"$ref": "#/components/schemas/Pagination"},
                        {
                            "type": "object",
                            "properties": {
                                "items": {
                                    "type": "array",
                                    "items": {
                                        "$ref": f"#/components/schemas/{model.__name__}"
                                    }
                                }
                            }
                        }
                    ]
                }
            }
        }
        
        # 记录模型以便注册
        if "models" not in func.__api_spec__:
            func.__api_spec__["models"] = []
        func.__api_spec__["models"].append(model)
        
        # 添加到响应定义
        func.__api_spec__["responses"][str(status_code)] = response_def
        
        return func
    return decorator


def api_param(
    name: str,
    param_type: str = "query",
    data_type: str = "string",
    required: bool = False,
    description: str = None,
    deprecated: bool = False,
    schema: Dict[str, Any] = None
) -> Callable:
    """
    指定API参数的装饰器
    
    Args:
        name: 参数名称
        param_type: 参数类型（query, path, header, cookie）
        data_type: 数据类型（string, number, integer, boolean, array, object）
        required: 是否必需
        description: 参数描述
        deprecated: 是否已弃用
        schema: 参数模式的额外属性
        
    Returns:
        装饰后的函数
    """
    def decorator(func: Callable) -> Callable:
        if not hasattr(func, "__api_spec__"):
            func.__api_spec__ = {}
        
        if "parameters" not in func.__api_spec__:
            func.__api_spec__["parameters"] = []
        
        # 创建参数定义
        param_def = {
            "name": name,
            "in": param_type,
            "required": required,
            "schema": schema or {"type": data_type}
        }
        
        if description:
            param_def["description"] = description
            
        if deprecated:
            param_def["deprecated"] = deprecated
        
        # 添加到参数列表
        func.__api_spec__["parameters"].append(param_def)
        
        return func
    return decorator


def api_paginated_params() -> Callable:
    """
    添加标准分页参数的装饰器
    
    Returns:
        装饰后的函数
    """
    def decorator(func: Callable) -> Callable:
        # 添加分页参数
        func = api_param(
            name="page",
            param_type="query",
            data_type="integer",
            description="页码，从1开始",
            schema={"type": "integer", "minimum": 1, "default": 1}
        )(func)
        
        func = api_param(
            name="page_size",
            param_type="query",
            data_type="integer",
            description="每页项目数量",
            schema={"type": "integer", "minimum": 1, "maximum": 100, "default": 10}
        )(func)
        
        return func
    return decorator


def api_security(scheme_name: str) -> Callable:
    """
    指定API安全需求的装饰器
    
    Args:
        scheme_name: 安全方案名称
        
    Returns:
        装饰后的函数
    """
    def decorator(func: Callable) -> Callable:
        if not hasattr(func, "__api_spec__"):
            func.__api_spec__ = {}
        
        if "security" not in func.__api_spec__:
            func.__api_spec__["security"] = []
        
        # 添加安全需求
        func.__api_spec__["security"].append({scheme_name: []})
        
        return func
    return decorator 