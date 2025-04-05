#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
OpenAPI规范生成模块

收集API路由信息，生成符合OpenAPI规范的API描述文档
"""

import inspect
import json
import re
from typing import Dict, List, Any, Optional, Union, Callable
from sanic import Sanic
from sanic.blueprints import Blueprint
from sanic.router import Route
from sanic.response import json as json_response
from app.config import get_config

# OpenAPI规范版本
OPENAPI_VERSION = "3.0.3"

# 全局API文档对象
_api_spec: Dict[str, Any] = {}


def setup_openapi(app: Sanic, title: str = None, version: str = None, 
                  description: str = None, base_path: str = "") -> None:
    """
    设置OpenAPI规范并收集API路由信息
    
    Args:
        app: Sanic应用实例
        title: API标题，默认使用应用名称
        version: API版本，默认使用配置中的版本
        description: API描述
        base_path: API基础路径前缀
    """
    config = get_config()
    
    # 初始化OpenAPI规范
    global _api_spec
    _api_spec = {
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": title or app.name or "Sanic-Admin API",
            "version": version or config.API_VERSION or "1.0.0",
            "description": description or "Sanic-Admin API文档",
        },
        "servers": [
            {
                "url": base_path or config.API_BASE_URL or "/",
                "description": "API服务器"
            }
        ],
        "paths": {},
        "components": {
            "schemas": {},
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                }
            }
        },
        "tags": []
    }
    
    # 收集所有路由
    for uri, route_obj in app.router.routes_all.items():
        if isinstance(route_obj, list):
            for route in route_obj:
                _process_route(route, uri)
        else:
            _process_route(route_obj, uri)
    
    # 为blueprint组织标签
    _organize_tags_by_blueprint(app)


def _process_route(route: Route, uri: str) -> None:
    """处理单个路由，提取API信息并添加到OpenAPI规范中"""
    # 忽略内部路由和静态文件路由
    if uri.startswith("/swagger") or uri.startswith("/static"):
        return
    
    handler = route.handler
    
    # 尝试获取处理函数的文档字符串
    docstring = inspect.getdoc(handler) or ""
    
    # 检查是否有OpenAPI装饰器提供的元数据
    api_meta = getattr(handler, "_api_meta", {})
    
    # 路径参数处理
    path = uri
    path_params = []
    
    # 将Sanic路径参数格式转换为OpenAPI格式
    # 例如: /users/<user_id:int> -> /users/{user_id}
    pattern = r"<([^>:]+)(:[^>]+)?>"
    for match in re.finditer(pattern, path):
        param_name = match.group(1)
        param_type = (match.group(2) or ":str")[1:]
        
        # 将Sanic路径参数转换为OpenAPI路径参数
        path = path.replace(match.group(0), f"{{{param_name}}}")
        
        # 添加参数信息
        param_schema = {
            "type": _convert_type_to_openapi(param_type)
        }
        
        path_params.append({
            "name": param_name,
            "in": "path",
            "required": True,
            "schema": param_schema,
            "description": f"路径参数 {param_name}"
        })
    
    # 准备路径对象
    if path not in _api_spec["paths"]:
        _api_spec["paths"][path] = {}
    
    # 处理每个HTTP方法
    for method in route.methods:
        method = method.lower()
        
        # 忽略HEAD和OPTIONS请求
        if method in ["head", "options"]:
            continue
        
        # 提取API操作信息
        operation = {
            "summary": api_meta.get("summary", _extract_summary(docstring)),
            "description": api_meta.get("description", docstring),
            "responses": api_meta.get("responses", _default_responses()),
            "tags": api_meta.get("tags", _extract_tags(handler, path)),
            "parameters": path_params + api_meta.get("parameters", [])
        }
        
        # 添加请求体
        request_body = api_meta.get("request_body")
        if request_body and method in ["post", "put", "patch"]:
            operation["requestBody"] = request_body
        
        # 添加安全要求
        if api_meta.get("secured", True) and not path.startswith("/auth"):
            operation["security"] = [{"BearerAuth": []}]
        
        # 将操作添加到路径中
        _api_spec["paths"][path][method] = operation


def _convert_type_to_openapi(sanic_type: str) -> str:
    """将Sanic路径参数类型转换为OpenAPI类型"""
    type_map = {
        "str": "string",
        "int": "integer",
        "float": "number",
        "uuid": "string",
        "alpha": "string",
        "slug": "string",
        "path": "string"
    }
    
    return type_map.get(sanic_type, "string")


def _extract_summary(docstring: str) -> str:
    """从文档字符串中提取摘要（第一行）"""
    if not docstring:
        return ""
    
    lines = docstring.strip().split("\n")
    return lines[0].strip()


def _extract_tags(handler: Callable, path: str) -> List[str]:
    """
    提取处理函数的标签
    
    尝试从blueprint名称或路径前缀推断标签
    """
    # 检查是否是blueprint中的处理函数
    bp = getattr(handler, "__blueprintname__", "")
    if bp:
        # 将blueprintname转换为可读标签
        return [bp.replace("_", " ").title()]
    
    # 尝试从路径推断标签
    parts = path.strip("/").split("/")
    if parts and parts[0]:
        # 使用路径的第一部分作为标签，例如 /api/v1/users -> Users
        tag = parts[0].replace("-", " ").title()
        if len(parts) > 1 and parts[0] == "api":
            tag = parts[2].replace("-", " ").title() if len(parts) > 2 else parts[1].replace("-", " ").title()
        return [tag]
    
    return ["General"]


def _default_responses() -> Dict[str, Any]:
    """生成默认的响应对象"""
    return {
        "200": {
            "description": "成功响应",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "success": {
                                "type": "boolean",
                                "description": "操作是否成功"
                            },
                            "code": {
                                "type": "string",
                                "description": "业务代码"
                            },
                            "message": {
                                "type": "string",
                                "description": "响应消息"
                            },
                            "data": {
                                "type": "object",
                                "description": "响应数据"
                            }
                        }
                    }
                }
            }
        },
        "400": {
            "description": "请求错误",
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/Error"
                    }
                }
            }
        },
        "401": {
            "description": "认证失败",
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/Error"
                    }
                }
            }
        },
        "403": {
            "description": "权限不足",
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/Error"
                    }
                }
            }
        },
        "404": {
            "description": "资源不存在",
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/Error"
                    }
                }
            }
        },
        "500": {
            "description": "服务器错误",
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/Error"
                    }
                }
            }
        }
    }


def _organize_tags_by_blueprint(app: Sanic) -> None:
    """根据蓝图组织API标签"""
    # 收集所有唯一的标签
    unique_tags = set()
    for path_obj in _api_spec["paths"].values():
        for method_obj in path_obj.values():
            if "tags" in method_obj:
                unique_tags.update(method_obj["tags"])
    
    # 将收集到的标签转换为标签对象
    _api_spec["tags"] = [{"name": tag, "description": f"{tag} 相关API"} for tag in sorted(unique_tags)]


def get_openapi_spec() -> Dict[str, Any]:
    """获取当前的OpenAPI规范"""
    return _api_spec


def openapi_json(request):
    """返回OpenAPI规范的JSON响应"""
    return json_response(_api_spec)


# 以下是API文档装饰器

def api_description(summary: str = None, description: str = None, tags: List[str] = None, 
                   secured: bool = True):
    """
    API描述装饰器
    
    用于添加API元数据，包括摘要、描述、标签和安全要求
    
    Args:
        summary: API操作的简短摘要
        description: API操作的详细描述
        tags: API标签列表，用于分组
        secured: 是否需要身份验证，默认为True
    """
    def decorator(func):
        # 确保函数有_api_meta属性
        if not hasattr(func, "_api_meta"):
            func._api_meta = {}
        
        if summary:
            func._api_meta["summary"] = summary
        
        if description:
            func._api_meta["description"] = description
        
        if tags:
            func._api_meta["tags"] = tags
        
        func._api_meta["secured"] = secured
        
        return func
    
    return decorator


def api_request_body(content_type: str = "application/json", schema: Dict[str, Any] = None, 
                    required: bool = True, description: str = None):
    """
    API请求体装饰器
    
    用于定义API请求体的格式
    
    Args:
        content_type: 内容类型，默认为application/json
        schema: 请求体的模式
        required: 请求体是否必需
        description: 请求体的描述
    """
    def decorator(func):
        # 确保函数有_api_meta属性
        if not hasattr(func, "_api_meta"):
            func._api_meta = {}
        
        # 创建请求体对象
        request_body = {
            "required": required,
            "content": {
                content_type: {}
            }
        }
        
        if description:
            request_body["description"] = description
        
        if schema:
            request_body["content"][content_type]["schema"] = schema
        
        func._api_meta["request_body"] = request_body
        
        return func
    
    return decorator


def api_response(status_code: Union[int, str], description: str = None, 
                content_type: str = "application/json", schema: Dict[str, Any] = None):
    """
    API响应装饰器
    
    用于定义API响应的格式
    
    Args:
        status_code: HTTP状态码
        description: 响应描述
        content_type: 内容类型，默认为application/json
        schema: 响应体的模式
    """
    def decorator(func):
        # 确保函数有_api_meta属性
        if not hasattr(func, "_api_meta"):
            func._api_meta = {}
        
        # 确保responses字典存在
        if "responses" not in func._api_meta:
            func._api_meta["responses"] = _default_responses()
        
        # 创建响应对象
        response = {
            "description": description or f"状态码 {status_code} 的响应"
        }
        
        if schema:
            response["content"] = {
                content_type: {
                    "schema": schema
                }
            }
        
        # 转换状态码为字符串
        status_str = str(status_code)
        
        # 添加响应
        func._api_meta["responses"][status_str] = response
        
        return func
    
    return decorator 