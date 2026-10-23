#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
API文档模块

提供自动化API文档生成功能，支持OpenAPI规范
"""

from app.docs.openapi import setup_openapi, get_openapi_spec
from app.docs.swagger import setup_swagger_ui, get_redoc_html
from app.docs.routes import setup_doc_routes
from app.docs.models import (
    register_model, 
    register_tortoise_model, 
    register_error_schemas, 
    register_pagination_schemas
)
from app.docs.decorators import (
    api_tags,
    api_exclude,
    api_summary,
    api_description,
    api_body,
    api_response,
    api_response_list,
    api_response_pagination,
    api_param,
    api_paginated_params,
    api_security
)

def setup_docs(app, swagger_url: str = "/swagger", swagger_json_url: str = "/swagger.json") -> None:
    """
    一次性接入 API 文档：Swagger UI(/swagger)、ReDoc(/redoc)、OpenAPI JSON(/swagger.json)。

    应在所有蓝图注册之后调用；OpenAPI 规范在服务启动前（before_server_start）生成，
    因此能收集到全部已注册的路由。若 api 蓝图因降级未注册，规范中只含已注册的路由。

    sanic-ext 默认会在 /docs 下自动挂载另一套 OpenAPI，与本模块的 /docs/* 路由冲突，
    此处关闭它（``OAS=False``），以本模块为唯一文档来源。
    """
    app.config.OAS = False
    setup_swagger_ui(app, swagger_url=swagger_url, swagger_json_url=swagger_json_url)
    setup_doc_routes(app, swagger_json_url=swagger_json_url)

    @app.listener("before_server_start")
    async def _build_openapi_spec(app):
        setup_openapi(app)


__all__ = [
    # 设置函数
    'setup_docs',
    'setup_openapi',
    'setup_swagger_ui',
    'setup_doc_routes',
    'get_openapi_spec',
    'get_redoc_html',
    
    # 模型注册函数
    'register_model',
    'register_tortoise_model',
    'register_error_schemas',
    'register_pagination_schemas',
    
    # API装饰器
    'api_tags',
    'api_exclude',
    'api_summary',
    'api_description',
    'api_body',
    'api_response',
    'api_response_list',
    'api_response_pagination',
    'api_param',
    'api_paginated_params',
    'api_security'
] 