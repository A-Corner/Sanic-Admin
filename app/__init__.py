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
from pathlib import Path
from typing import Any, Optional
from urllib.parse import unquote

from sanic import Sanic
from sanic.exceptions import NotFound
from sanic.handlers.directory import DirectoryHandler
from sanic.log import logger
from sanic.response import file, json as json_response

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

#: 黑名单的**小写**视图：``/amis/SERVER.JS`` 这类大小写变体必须同样挡下——
#: 黑名单判定发生在文件系统之前，而开发机常见的大小写不敏感文件系统
#: （macOS 默认、Windows）会把 ``SERVER.JS`` 解析到同一个文件。
AMIS_PRIVATE_FILES_LOWER = frozenset(name.lower() for name in AMIS_PRIVATE_FILES)

#: AMIS 根目录下的入口页面（运行期需要的顶层 HTML）。
AMIS_ENTRY_PAGES = ("login.html", "index.html")


class _NoDirectoryListingHandler(DirectoryHandler):
    """``/static`` 的裸目录路径返回 404，而不是触发 Sanic 默认的 500。

    Sanic 的 ``DirectoryHandler`` 在既无 ``index`` 又未开启 ``directory_view`` 时
    会 ``raise IsADirectoryError`` —— 那是**未捕获异常**，直接变成 500。
    等于开了一个可外部触发的 500 面。

    这里覆写 ``handle``：只保留"index 文件命中"与"文件直出"两条正常路径，
    其余一律 404 —— 静态资源目录不应该被列目录。

    （AMIS 不走这个类：``/amis`` 下只注册了普通路由，目录路径由 ``is_file``
    判定直接 404，见 ``_register_amis_static``。当前仓库没有 ``static/`` 目录，
    挂在这里属于防御——将来建了目录也不会出现 500 面。）
    """

    async def handle(self, request, path):
        try:
            return await super().handle(request, path)
        except IsADirectoryError:
            raise NotFound("File not found")


def _register_amis_static(app: Sanic, amis_dir: str) -> None:
    """
    托管 AMIS 管理界面，同时挡住开发文件。

    用普通路由、**不再配合任何 ``app.static`` 挂载**，一条路径只由一套机制
    提供。v0.2.1 曾同时保留「逐子目录 ``app.static`` + 顶层页面 ``app.static``」
    与普通路由两套机制，同一批文件被注册两次（OpenAPI 里 AMIS 相关 path
    12 条，其中 10 条是与普通路由重复覆盖的静态路由——8 个子目录挂载加
    2 个顶层页面挂载）；本版本收敛为只有下面两条路由。

    为什么不用 ``app.static``：

    * ``app.static(uri, <文件>)`` 会把 uri 的尾部斜杠去掉再注册，加上全局
      ``strict_slashes=False``，裸 ``/amis`` 会命中静态路由返回 200；而
      v0.2.0 的裸 ``/amis`` 是 404，docker-acceptance 断言的就是这个行为。
    * ``app.static`` 的目录型挂载由 Sanic 的 ``DirectoryHandler`` 接管目录
      路径，语义不受这里控制（v0.2.1 曾因此出现裸目录 500 面）。

    行为：

    * ``/amis/``       → 登录页（``login.html``）；
    * ``/amis/<path>`` → ``amis/`` 下的文件；``server.js`` 等开发文件、
      目录路径与路径逃逸一律 404；
    * 裸 ``/amis``     → 不匹配任何路由，404（``strict_slashes=True``）。

    新增子目录或资源文件不需要改这里：``<path>`` 通配 ``amis/`` 下所有文件，
    不存在"清单漏挂"的问题；代价是将来若在 ``amis/`` 下新增**开发**子目录，
    它同样会被自动公开——开发文件黑名单只匹配顶层文件名。
    """
    amis_root = Path(amis_dir).resolve()

    @app.route("/amis/", methods=["GET", "HEAD"], strict_slashes=True)
    async def amis_index(request):
        index_file = amis_root / AMIS_ENTRY_PAGES[0]
        if not index_file.is_file():
            return json_response({"success": False, "message": "Not found"}, status=404)
        return await file(index_file)

    @app.route("/amis/<__rest__:path>", methods=["GET", "HEAD"], strict_slashes=True)
    async def amis_files(request, __rest__):
        # 黑名单判两次：
        # ① 原始请求首段（快速路径，防明显命中）；
        # ② **规范化后的相对路径首段**——这是真正提供文件的依据。
        #    只判①会被原始 dot-segment 绕过："/amis/./server.js" 的原始首段
        #    是 "."，而 resolve() 后实际提供的文件就是 server.js（Linux 同样
        #    中招，与文件系统大小写无关）。必须以"实际提供的文件"为准。
        #    大小写不敏感：判定发生在文件系统解析之前，大小写不敏感的文件
        #    系统（macOS/Windows）会把变体名解析到同一个文件。
        if __rest__.split("/")[0].lower() in AMIS_PRIVATE_FILES_LOWER:
            return json_response({"success": False, "message": "Not found"}, status=404)
        target = (amis_root / __rest__).resolve()
        try:
            relative = target.relative_to(amis_root)
        except ValueError:
            return json_response({"success": False, "message": "Not found"}, status=404)
        if relative.parts and relative.parts[0].lower() in AMIS_PRIVATE_FILES_LOWER:
            return json_response({"success": False, "message": "Not found"}, status=404)
        if not target.is_file():
            return json_response({"success": False, "message": "Not found"}, status=404)
        return await file(target)



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
        # 同样禁用目录列表：裸目录路径（/static/）否则会被 Sanic 的
        # DirectoryHandler 抛成 500（见 _NoDirectoryListingHandler 注释）。
        app.static(
            '/static',
            app.config.STATIC_DIR,
            directory_handler=_NoDirectoryListingHandler(
                '/static', Path(app.config.STATIC_DIR)
            ),
        )
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
    async def check_delivery_backend(app):
        """
        投递后端必须在启动期可见（AUTH-13）。

        `LoggingBackend.send()` 正常返回，因此**未配置后端**与**投递成功**在运行期
        完全同形：`deliver()` 返回 True、审计记 success、用户看到「已发送」。这个
        监听器是唯一能把两者区分开的地方——非生产打 warning，生产拒绝启动
        （除非显式声明 `ALLOW_NOOP_DELIVERY=1`）。

        **为什么是 `before_server_start` 而不是 `main_process_start`**：
        `main_process_start` 只在主进程跑一次，而「哪个 worker 忘了配」恰恰需要
        每个进程自己检查；Sanic 25.12 也没有公开 API 回答「我是第几个 worker」。
        代价是多 worker 部署下每个 worker 各打一条相同的告警——重复告警比告警
        位置错（主进程通过、worker 带病运行）好。

        **为什么在 `setup_db` 之前注册**：Sanic 按注册顺序执行监听器，配置问题
        应该在建库/建表之前就暴露，避免「连了库、建了表、然后才拒绝启动」。

        AUTH-02② 追加：同一个监听器顺带检查「开了自助注册但没有投递渠道」。
        注册账户固定 `verified=False`，验证码只能经投递渠道送出；没有渠道时
        自助注册**开了也无人能登录**。这类「能开但没用」的开关半年后会让人
        误以为开了就能用，所以在启动期明确说一次。只 warning 不 fail——开了
        也不危险，只是没效果。

        Args:
            app: 当前应用实例（Sanic 会把 app 传进来，覆盖外层同名变量）
        """
        from app.services.delivery import check_backend_configured

        delivery_ready = check_backend_configured(
            env=app.config.get("ENV"),
            allow_noop=bool(app.config.get("ALLOW_NOOP_DELIVERY", False)),
        )

        if app.config.get("ALLOW_SELF_REGISTRATION", False) and not delivery_ready:
            logger.warning(
                "ALLOW_SELF_REGISTRATION 已开启，但投递后端未配置真实实现："
                "自助注册创建的账户固定 verified=False，验证码无法送达，"
                "注册者永远无法登录。该开关当前没有实际效果——"
                "请配置投递后端（app/services/delivery.py 的 Backend），"
                "或关闭自助注册、改由管理员建号（POST /api/v1/accounts 带 verified=true）。"
            )

    @app.listener('before_server_start')
    async def setup_db(app):
        await models.init_db(app)
        app.ctx.db_ready = True
        logger.info("数据库连接初始化完成")

        init_cache(app, cache_pkg)
        logger.info("缓存系统初始化完成")

        await create_initial_admin()

    @app.listener('after_server_stop')
    async def close_db(app):
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
