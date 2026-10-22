#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
应用程序入口点，创建和配置Sanic应用实例

``create_app(config)`` 契约：``config`` 可以是环境名（'development'/'testing'/'production'）、
配置类/对象或字典；缺省时使用 ``SANIC_ENV``（默认 development）。
``ENABLE_API_DOCS`` 控制 /swagger、/swagger.json、/redoc、/docs/* 文档路由：
development/testing 默认开启，production 默认关闭。
"""

import importlib
import os
from typing import Any, Optional
from urllib.parse import unquote

from sanic import Sanic
from sanic.log import logger
from sanic.response import json as json_response

from app.config import ConfigError, config_to_dict, get_config, settings
from app.middleware import register_all_middlewares
from app.middleware.compression import configure_compression

__all__ = ["create_app", "ConfigError"]

#: AMIS 静态目录下**不应对外提供**的文件（开发期配置与源码）。
#: 这些文件既无运行期用途，又会泄漏开发环境信息（依赖清单、监听端口等），
#: 因此整目录静态托管时必须显式排除。
AMIS_PRIVATE_FILES = frozenset({
    "server.js",
    "package.json",
    "package-lock.json",
    "nodemon.json",
    "README.md",
})


def _is_amis_private(path: str) -> bool:
    """判断 AMIS 下的请求路径是否指向不应对外公开的文件。"""
    return path.rsplit("/", 1)[-1] in AMIS_PRIVATE_FILES


def _register_amis_static(app: Sanic, amis_dir: str) -> None:
    """
    托管 AMIS 管理界面，同时挡住开发文件。

    做法：不整目录静态托管（那会把 ``server.js``、``package.json`` 等开发文件
    一并公开），而是**逐个挂载**运行期真正需要的资源：

    * 根目录下的两个入口页面 ``login.html`` / ``index.html`` 单独挂载；
    * ``pages/``、``sdk/``、``css/``、``js/``、``images/``、``fonts/``、
      ``vendor/`` 这些子目录按需挂载。

    任何不在此清单中的文件（例如 ``server.js``）自然没有对应路由，返回 404。
    """
    # 运行期需要的子目录
    for sub in ("pages", "sdk", "css", "js", "images", "fonts", "vendor"):
        sub_path = os.path.join(amis_dir, sub)
        if os.path.isdir(sub_path):
            app.static(f"/amis/{sub}", sub_path, name=f"amis_{sub}")

    # 根目录下的入口页面单独挂载
    for page in ("login.html", "index.html"):
        page_path = os.path.join(amis_dir, page)
        if os.path.isfile(page_path):
            app.static(f"/amis/{page}", page_path, name=f"amis_page_{page[:-5]}")

    # /amis/ 显示登录页；裸 /amis 返回 404（与 v0.2.0 行为一致）
    app.static("/amis/", os.path.join(amis_dir, "login.html"), name="amis_index")



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
    # 上传目录不对外静态托管：否则任何人都能直接下载他人上传的文件。
    # 文件下载统一走需要鉴权的 GET /api/v1/files/<id>/download。
    # 托管 AMIS 管理界面（与 API 同源，便于复用 HttpOnly 会话 Cookie）。
    # AMIS_DIR 置空或目录不存在时不挂载（生产环境可据此关闭管理界面）。
    # 显式指定 name，避免与 /static 的默认路由名重复（Sanic 23.6 拒绝重名路由）。
    amis_dir = app.config.get('AMIS_DIR')
    if amis_dir and os.path.isdir(amis_dir):
        _register_amis_static(app, amis_dir)

    register_all_middlewares(app)
    configure_compression(
        app,
        min_length=app.config.get('COMPRESSION_MIN_LENGTH', 1024),
        compression_level=app.config.get('COMPRESSION_LEVEL', 6),
    )

    @app.on_request
    async def reject_null_byte_path(request):
        """
        拒绝路径中含空字节（``\\x00``）的请求。

        静态文件处理器会把请求路径拼到磁盘路径上再求 realpath，空字节会让
        ``posixpath`` 抛 ``ValueError: lstat: embedded null character in path``，
        最终变成 500。带空字节的路径一律没有合法用途，直接 400。

        注意：``request.path`` 是**未解码**的路径（``%00`` 仍是三个字符），
        所以必须先 ``unquote`` 才能看到真正的空字节。
        """
        try:
            decoded = unquote(request.path)
        except Exception:  # noqa: BLE001 - 非法编码不应导致 500
            return json_response(
                {"success": False, "message": "非法路径", "error": "INVALID_PATH"},
                status=400,
            )
        if "\x00" in decoded:
            return json_response(
                {"success": False, "message": "非法路径", "error": "INVALID_PATH"},
                status=400,
            )
        return None

    @app.get('/health')
    async def health(request):
        return json_response({"status": "ok", "env": app.config.get("ENV")})

    register_blueprints(app)
    if app.config.get("ENABLE_API_DOCS"):
        from app.docs import setup_docs
        setup_docs(app)
    _register_listeners(app)
    return app


def _register_listeners(app: Sanic) -> None:
    from app import models
    cache_pkg = importlib.import_module("app.cache")

    @app.listener('before_server_start')
    async def setup_db(app, loop):
        await models.init_db(app)
        app.ctx.db_ready = True
        logger.info("数据库连接初始化完成")

        init_cache(app, cache_pkg)
        logger.info("缓存系统初始化完成")

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
    """注册认证路由与 API 蓝图组（/api/...）。"""
    from app.auth import routes as auth_routes
    from app.api import api_bp

    for name in ("auth_bp", "capt_bp", "two_step_bp", "role_bp", "account_bp"):
        app.blueprint(getattr(auth_routes, name))
    app.blueprint(api_bp)


async def create_initial_admin() -> None:
    """如果系统中没有管理员账户，则创建初始管理员；失败只记录错误，不阻止启动。"""
    try:
        from app.auth.authentication import create_initial_admin_account
        await create_initial_admin_account()
        logger.info("初始管理员账户检查完成")
    except Exception as e:
        logger.error(f"创建初始管理员账户时出错: {str(e)}")
