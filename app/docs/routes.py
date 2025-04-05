#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
API文档路由模块

配置API文档相关的路由
"""

from sanic import Sanic, Blueprint
from sanic.response import json, html, redirect
from app.docs.openapi import openapi_json, get_openapi_spec
from app.docs.swagger import get_redoc_html

# 文档蓝图
docs_bp = Blueprint("docs", url_prefix="/docs")


def setup_doc_routes(app: Sanic, swagger_json_url: str = "/swagger.json") -> None:
    """
    设置API文档相关的路由
    
    Args:
        app: Sanic应用实例
        swagger_json_url: OpenAPI规范JSON文件URL
    """
    # 确保URL以斜杠开头
    if not swagger_json_url.startswith("/"):
        swagger_json_url = f"/{swagger_json_url}"
    
    # 注册OpenAPI JSON端点
    @app.route(swagger_json_url)
    async def swagger_json_handler(request):
        return openapi_json(request)
    
    # 设置ReDoc文档页面
    @docs_bp.route("/redoc")
    async def redoc_handler(request):
        return html(get_redoc_html(swagger_json_url))
    
    # 设置API文档首页
    @docs_bp.route("/")
    async def docs_index(request):
        return redirect("/swagger")
    
    # 注册API模型信息端点
    @docs_bp.route("/models")
    async def api_models(request):
        """返回API中使用的所有模型/模式信息"""
        api_spec = get_openapi_spec()
        schemas = api_spec.get("components", {}).get("schemas", {})
        return json({
            "success": True,
            "data": {
                "schemas": schemas
            }
        })
    
    # 注册API标签信息端点
    @docs_bp.route("/tags")
    async def api_tags(request):
        """返回API中使用的所有标签信息"""
        api_spec = get_openapi_spec()
        tags = api_spec.get("tags", [])
        return json({
            "success": True,
            "data": {
                "tags": tags
            }
        })
    
    # 注册API路径信息端点
    @docs_bp.route("/paths")
    async def api_paths(request):
        """返回API中的所有路径信息"""
        api_spec = get_openapi_spec()
        paths = api_spec.get("paths", {})
        return json({
            "success": True,
            "data": {
                "paths": paths
            }
        })
    
    # 将文档蓝图注册到应用
    app.blueprint(docs_bp) 