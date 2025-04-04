#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
应用程序入口点，创建和配置Sanic应用实例
"""

import os
from sanic import Sanic
from sanic.log import logger
from app.config import settings
from app.middleware import register_all_middlewares
from app.auth.routes import auth_bp, capt_bp, two_step_bp, role_bp, account_bp
from app.api import v1_bp
from app.models import init_db, create_initial_admin
from tortoise import Tortoise
from app.cache import _default_cache, get_cache


def create_app(config=None):
    """
    创建并配置Sanic应用实例
    
    Args:
        config: 配置对象或字典，可选，用于覆盖默认配置
        
    Returns:
        Sanic: 配置好的Sanic应用实例
    """
    # 创建Sanic应用
    app = Sanic(__name__)
    
    # 加载配置
    app.config.update_config(settings)
    
    # 如果提供了自定义配置，则应用它
    if config:
        app.config.update_config(config)
    
    # 确保上传目录存在
    os.makedirs(app.config.UPLOAD_DIR, exist_ok=True)
    
    # 配置静态文件服务
    app.static('/static', app.config.STATIC_DIR)
    
    # 配置上传文件服务
    app.static('/uploads', app.config.UPLOAD_DIR)
    
    # 注册中间件
    register_all_middlewares(app)
    
    # 注册蓝图
    register_blueprints(app)
    
    # 注册启动和关闭时的事件处理器
    @app.listener('before_server_start')
    async def setup_db(app, loop):
        """服务器启动前初始化数据库连接"""
        await init_db(app)
        logger.info("数据库连接初始化完成")
        
        # 初始化缓存
        init_cache(app)
        logger.info("缓存系统初始化完成")
        
        # 创建初始管理员账户
        await create_initial_admin()
    
    @app.listener('after_server_stop')
    async def close_db(app, loop):
        """服务器停止后关闭数据库连接"""
        await Tortoise.close_connections()
        logger.info("数据库连接已关闭")
        
        # 清理缓存
        try:
            get_cache().clear()
            logger.info("缓存已清理")
        except Exception as e:
            logger.error(f"清理缓存时出错: {str(e)}")
    
    # 设置CORS配置
    app.config.CORS_ORIGIN = app.config.get('CORS_ORIGIN', '*')
    
    return app


def init_cache(app):
    """
    初始化缓存系统
    
    Args:
        app: Sanic应用实例
    """
    cache_type = app.config.get('CACHE_TYPE', 'memory')
    
    # 获取缓存实例并绑定到应用
    cache = get_cache(cache_type)
    app.ctx.cache = cache
    
    # 记录缓存类型
    logger.info(f"使用 {cache_type} 缓存后端")
    
    return cache


def register_blueprints(app):
    """
    注册所有蓝图
    
    Args:
        app: Sanic应用实例
    """
    # 认证相关蓝图
    app.blueprint(auth_bp)
    app.blueprint(capt_bp)
    app.blueprint(two_step_bp)
    app.blueprint(role_bp)
    app.blueprint(account_bp)
    
    # API 蓝图
    app.blueprint(v1_bp)
    
    # 导入资源以确保路由注册
    import app.api.resources


# 添加创建初始管理员的函数
async def create_initial_admin():
    """
    创建初始管理员账户
    如果系统中没有管理员账户，则创建一个默认的管理员账户
    """
    from app.auth.authentication import create_initial_admin_account
    
    try:
        await create_initial_admin_account()
        logger.info("初始管理员账户检查完成")
    except Exception as e:
        logger.error(f"创建初始管理员账户时出错: {str(e)}") 