#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
应用程序入口点，创建和配置Sanic应用实例

``create_app(config)`` 契约：``config`` 可以是环境名（'development'/'testing'/'production'）、
配置类/对象或字典；缺省时使用 ``SANIC_ENV``（默认 development）。
依赖尚未修复的下游模块（models/auth/api/cache，见各 [降级] 日志）时，应用仍能启动，
对应功能被禁用并输出 warning。
"""

import importlib
import os
from typing import Any, Optional

from sanic import Sanic
from sanic.log import logger
from sanic.response import json as json_response

from app.config import ConfigError, config_to_dict, get_config, settings
from app.middleware import register_all_middlewares
from app.middleware.compression import configure_compression

__all__ = ["create_app", "ConfigError"]


def _optional_import(module: str, feature: str, owner: str, env: Optional[str] = None):
    """
    导入可选模块；development/testing 失败时记录 warning 并返回 None（不静默吞错），
    production 失败时拒绝启动（抛 ConfigError）。
    """
    try:
        return importlib.import_module(module)
    except Exception as e:
        if env == "production":
            raise ConfigError(f"生产环境拒绝降级启动：{feature} 不可用（导入 {module} 失败，待 {owner} 修复）: {e!r}") from e
        logger.warning(f"[降级] {feature} 未启用（导入 {module} 失败，待 {owner} 修复）: {e!r}")
        return None


def _resolve_config(config: Any) -> dict:
    if config is None:
        return config_to_dict(settings)
    if isinstance(config, str):
        return config_to_dict(get_config(config))
    return config_to_dict(config)


def create_app(config: Optional[Any] = None) -> Sanic:
    """
    创建并配置Sanic应用实例

    Args:
        config: 环境名字符串、配置类/对象或字典，可选

    Returns:
        Sanic: 配置好的Sanic应用实例

    Raises:
        ConfigError: 生产环境缺少必需密钥等配置错误
    """
    cfg = _resolve_config(config)

    # 允许同进程内多次创建（测试、模块级 app 与工厂并存）
    Sanic.test_mode = bool(cfg.get("TESTING")) or Sanic.test_mode
    app = Sanic("SanicAdmin")
    app.config.update(cfg)

    # 确保上传目录存在；静态目录存在时才挂载
    os.makedirs(app.config.UPLOAD_DIR, exist_ok=True)
    if os.path.isdir(app.config.STATIC_DIR):
        app.static('/static', app.config.STATIC_DIR)
    app.static('/uploads', app.config.UPLOAD_DIR)

    register_all_middlewares(app)
    configure_compression(
        app,
        min_length=app.config.get('COMPRESSION_MIN_LENGTH', 1024),
        compression_level=app.config.get('COMPRESSION_LEVEL', 6),
    )

    @app.get('/health')
    async def health(request):
        return json_response({"status": "ok", "env": app.config.get("ENV")})

    register_blueprints(app)
    _register_listeners(app)
    return app


def _register_listeners(app: Sanic) -> None:
    env = app.config.get("ENV")
    models = _optional_import("app.models", "数据库初始化", "B1b (models)", env)
    cache_pkg = _optional_import("app.cache", "缓存系统", "B1c (cache)", env)

    @app.listener('before_server_start')
    async def setup_db(app, loop):
        if models is not None and hasattr(models, "init_db"):
            await models.init_db(app)
            app.ctx.db_ready = True
            logger.info("数据库连接初始化完成")
        else:
            logger.warning("[降级] 跳过数据库初始化（app.models.init_db 不可用）")

        if cache_pkg is not None:
            try:
                init_cache(app, cache_pkg)
                logger.info("缓存系统初始化完成")
            except Exception as e:
                if app.config.get("ENV") == "production":
                    raise
                logger.warning(f"[降级] 缓存初始化失败，待 B1c 修复: {e!r}")

        if models is not None:
            await create_initial_admin()

    @app.listener('after_server_stop')
    async def close_db(app, loop):
        if getattr(app.ctx, "db_ready", False):
            try:
                from tortoise import Tortoise
                await Tortoise.close_connections()
                logger.info("数据库连接已关闭")
            except Exception as e:
                logger.error(f"关闭数据库连接时出错: {str(e)}")
        cache = getattr(app.ctx, "cache", None)
        if cache is not None:
            try:
                cache.clear()
                logger.info("缓存已清理")
            except Exception as e:
                logger.error(f"清理缓存时出错: {str(e)}")


def init_cache(app: Sanic, cache_pkg=None):
    """初始化缓存系统并绑定到 app.ctx.cache"""
    cache_pkg = cache_pkg or importlib.import_module("app.cache")
    cache_type = app.config.get('CACHE_TYPE', 'memory')
    cache = cache_pkg.get_cache(cache_type)
    app.ctx.cache = cache
    logger.info(f"使用 {cache_type} 缓存后端")
    return cache


def register_blueprints(app: Sanic) -> None:
    """注册所有蓝图；不可用的蓝图降级跳过并记录 warning。"""
    env = app.config.get("ENV")
    auth_routes = _optional_import("app.auth.routes", "认证/角色/账户路由", "B1b (auth)", env)
    if auth_routes is not None:
        for name in ("auth_bp", "capt_bp", "two_step_bp", "role_bp", "account_bp"):
            bp = getattr(auth_routes, name, None)
            if bp is None:
                if env == "production":
                    raise ConfigError(f"生产环境拒绝降级启动：app.auth.routes 缺少 {name}")
                logger.warning(f"[降级] app.auth.routes 缺少 {name}，待 B1b 修复")
            else:
                app.blueprint(bp)

    api_pkg = _optional_import("app.api", "API v1 路由", "B1d (api)", env)
    if api_pkg is not None and getattr(api_pkg, "v1_bp", None) is not None:
        app.blueprint(api_pkg.v1_bp)
        # 导入资源以确保路由注册
        _optional_import("app.api.resources", "API 资源路由", "B1d (api)", env)


async def create_initial_admin() -> None:
    """如果系统中没有管理员账户，则创建初始管理员（依赖 app.auth，失败时仅记录错误）"""
    try:
        from app.auth.authentication import create_initial_admin_account
        await create_initial_admin_account()
        logger.info("初始管理员账户检查完成")
    except Exception as e:
        logger.error(f"创建初始管理员账户时出错（待 B1b 修复）: {str(e)}")
