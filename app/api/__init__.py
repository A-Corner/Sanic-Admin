#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
API包，包含所有API相关模块和蓝图
"""

from sanic import Blueprint
from app.api.base import BaseResource, CRUDResource
from app.api.responses import APIResponse, APIError
import datetime
import os
from importlib import import_module

# 创建主API蓝图
api_bp = Blueprint.group('api', url_prefix='/api')

# 创建API版本蓝图
v1_bp = Blueprint('v1', url_prefix='/v1')

# 将版本蓝图添加到主API蓝图
api_bp.add_blueprint(v1_bp)

# 自动导入资源模块
resource_dir = os.path.join(os.path.dirname(__file__), "resources")
for filename in os.listdir(resource_dir):
    if filename.endswith(".py") and not filename.startswith("__"):
        module_name = filename[:-3]
        module = import_module(f"app.api.resources.{module_name}")
        
        # 如果模块有Blueprint对象，则注册到主Blueprint组
        if hasattr(module, "bp"):
            api_bp.add_blueprint(getattr(module, "bp"))

# 确保数据库API注册
try:
    from app.api.resources.database import bp as database_bp
    api_bp.add_blueprint(database_bp)
except ImportError:
    pass

# 导出常用类和函数
__all__ = [
    'BaseResource',
    'CRUDResource',
    'APIResponse',
    'APIError',
    'api_bp',
    'v1_bp'
]


def register_api_resources():
    """
    注册所有API资源
    
    此函数将在应用启动时调用，用于注册所有API资源路由
    """
    # 导入所有资源模块，确保它们注册到蓝图
    from app.api.resources import account, role, permission
    
    # 可以在此添加API文档或统计信息
    
    # 注册API健康检查端点
    @v1_bp.route('/health')
    async def health_check(request):
        """API健康检查端点"""
        return APIResponse.success(
            data={
                "status": "ok",
                "version": "1.0",
                "timestamp": APIResponse.serialize(datetime.datetime.now())
            },
            message="API服务正常运行"
        ) 