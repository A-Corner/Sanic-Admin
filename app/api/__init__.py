#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
API包，包含所有API相关模块和蓝图
"""

from sanic import Blueprint
from app.api.base import BaseResource, CRUDResource
from app.api.responses import APIResponse, APIError

# API 版本蓝图：所有资源路由（/api/v1/...）都注册到它上面
v1_bp = Blueprint('v1', url_prefix='/v1')

# 自动导入资源模块，确保它们的路由注册到 v1_bp
# （资源模块通过 ``from app.api import v1_bp`` 取得蓝图，因此必须在 v1_bp 定义之后导入）
from app.api import resources  # noqa: E402,F401
from app.api.resources import cache as _cache_resource  # noqa: E402,F401
from app.api.resources.compression import bp as compression_bp  # noqa: E402
from app.api.resources.database import bp as database_bp  # noqa: E402

# 主 API 蓝图组：/api/v1/...、/api/database/...、/api/compression/...
api_bp = Blueprint.group(v1_bp, database_bp, compression_bp, url_prefix='/api')

# 导出常用类和函数
__all__ = [
    'BaseResource',
    'CRUDResource',
    'APIResponse',
    'APIError',
    'api_bp',
    'v1_bp'
]
