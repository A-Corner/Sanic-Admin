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

__all__ = [
    # 设置函数
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