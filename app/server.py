#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Sanic应用服务器

初始化和配置Sanic应用实例
"""

import os
import importlib
from sanic import Sanic
from sanic.blueprints import Blueprint

from app.cache import setup_cache
from app.config import settings
from app.database import init_db
from app.docs import setup_openapi, setup_swagger_ui, setup_doc_routes, register_error_schemas, register_pagination_schemas
from app.middlewares import setup_middlewares

async def create_app(config_object=None):
    """
    创建并配置Sanic应用实例
    """
    app = Sanic(settings.APP_NAME)
    
    # 配置应用
    _configure_app(app, config_object)
    
    # 注册中间件
    setup_middlewares(app)
    
    # 加载蓝图
    _load_blueprints(app)
    
    # 设置数据库
    init_db(app)
    
    # 设置缓存
    setup_cache(app)
    
    # 设置API文档
    _setup_api_docs(app)
    
    return app

def _configure_app(app: Sanic, config_object=None):
    """
    配置Sanic应用
    
    Args:
        app: Sanic应用实例
        config_object: 配置对象或字典
    """
    # 加载默认配置
    app.config.update_config(settings.dict())
    
    # 加载自定义配置（如果有）
    if config_object:
        if isinstance(config_object, dict):
            app.config.update(config_object)
        else:
            app.config.update_config(config_object)
    
    # 设置日志
    if not hasattr(app.ctx, "logger"):
        import logging
        logger = logging.getLogger(settings.APP_NAME)
        app.ctx.logger = logger

def _load_blueprints(app: Sanic):
    """
    加载所有蓝图
    
    Args:
        app: Sanic应用实例
    """
    # 蓝图模块目录
    blueprint_dir = os.path.join(os.path.dirname(__file__), "api")
    
    # 如果蓝图目录不存在，则创建
    if not os.path.exists(blueprint_dir):
        app.ctx.logger.warning(f"蓝图目录不存在: {blueprint_dir}")
        return
    
    # 遍历蓝图目录
    for module_name in os.listdir(blueprint_dir):
        # 跳过非Python模块和特殊文件
        if not module_name.endswith(".py") and not os.path.isdir(os.path.join(blueprint_dir, module_name)):
            continue
            
        if module_name.startswith("__") or module_name.startswith("."):
            continue
            
        # 获取模块名（不含.py扩展名）
        if module_name.endswith(".py"):
            module_name = module_name[:-3]
        
        try:
            # 导入模块
            module = importlib.import_module(f"app.api.{module_name}")
            
            # 寻找并注册蓝图
            for item_name in dir(module):
                item = getattr(module, item_name)
                if isinstance(item, Blueprint):
                    app.blueprint(item)
                    app.ctx.logger.info(f"已注册蓝图: {item.name}")
        except Exception as e:
            app.ctx.logger.error(f"加载蓝图 {module_name} 时出错: {str(e)}")

def _setup_api_docs(app: Sanic):
    """
    设置API文档功能
    """
    # 注册通用模式
    register_error_schemas()
    register_pagination_schemas()
    
    # 设置OpenAPI规范
    setup_openapi(app, 
                 title=f"{settings.APP_NAME} API",
                 version=settings.APP_VERSION,
                 description="Sanic Admin系统API文档")
    
    # 设置Swagger UI
    setup_swagger_ui(app, swagger_url="/swagger", swagger_json_url="/swagger.json")
    
    # 设置文档路由
    setup_doc_routes(app, swagger_json_url="/swagger.json")
    
    # 记录日志
    app.ctx.logger.info("API文档已设置 - 访问 /swagger 查看API文档") 