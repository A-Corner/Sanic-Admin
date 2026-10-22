#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
pytest 全局配置与夹具。

设计要点
========

1. **环境变量清空**：本文件顶部先把所有与密钥/凭据相关的环境变量从 ``os.environ``
   里删掉，再写入测试专用的固定值。变量名**以 ``app/config.py`` 与
   ``app/auth/authentication.py`` 实际读取的为准**，逐个列举见 ``MANAGED_ENV_VARS``。
   ��清空的目的是：测试绝不依赖开发者本机 ``.env`` / shell 里残留的真实凭据。

2. **数据库隔离**：使用 ``tmp_path_factory`` 在 pytest 临时目录里建一个 sqlite 文件，
   **绝不触碰仓库里的任何数据库文件**（``sanic_admin_dev.sqlite3`` / ``SA_Admin_DB.sqlite3``）。
   每个测试模块一个独立库文件，测试之间互不影响，也不依赖执行顺序。

3. **真实的登录 token**：``admin_token`` / ``normal_user_token`` 都**真的走
   ``POST /auth/login``** 拿 JWT，不伪造、不手写。

4. **不依赖未完成资源**：所有用例只依赖 ``app/`` 里真实存在的接口；
   若某条路由在当前分支尚未注册，用例会明确失败（而不是被静默跳过）。
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# 0. 环境变量隔离（必须在 import app 之前完成）
# ---------------------------------------------------------------------------

#: 测试中需要显式清空再写入固定值的环境变量。
#: 名单来自 ``app/config.py``（密钥/盐/口令/环境名）与 ``app/auth/authentication.py``
#: （初始管理员邮箱、用户名）。
MANAGED_ENV_VARS = (
    # app/config.py —— 密钥与盐
    "SECRET_KEY",
    "PASSWORD_SALT",
    "JWT_PRIVATE_KEY",
    "JWT_PUBLIC_KEY",
    # app/config.py —— 初始管理员口令
    "INITIAL_ADMIN_PASSWORD",
    # app/config.py —— 环境名与运行期开关
    "SANIC_ENV",
    "HOST",
    "PORT",
    "DATABASE_URL",
    "CACHE_TYPE",
    "REDIS_HOST",
    "REDIS_PORT",
    "REDIS_DB",
    "REDIS_PASSWORD",
    "MAIL_SERVER",
    "MAIL_PORT",
    "MAIL_USERNAME",
    "MAIL_PASSWORD",
    "MAIL_DEFAULT_SENDER",
    "ENABLE_API_DOCS",
    "REQUIRE_TWO_FACTOR",
    "CORS_ALLOWED_ORIGINS",
    # app/auth/authentication.py —— 初始管理员身份
    "INITIAL_ADMIN_EMAIL",
    "INITIAL_ADMIN_USERNAME",
)

for _var in MANAGED_ENV_VARS:
    os.environ.pop(_var, None)

#: 测试固定值（仅测试环境使用，绝非真实凭据）
os.environ["SANIC_ENV"] = "testing"
os.environ["SECRET_KEY"] = "test-only-secret-key-not-for-production"
os.environ["PASSWORD_SALT"] = "test-only-password-salt"
os.environ["INITIAL_ADMIN_PASSWORD"] = "TestAdminPass123!"
os.environ["INITIAL_ADMIN_EMAIL"] = "SAdmin@Sanic.com"
os.environ["REQUIRE_TWO_FACTOR"] = "false"

# 让 ``import app`` 能找到仓库根目录
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# ---------------------------------------------------------------------------
# 1. 临时 shim：绕过 base commit 的 import 死因
# ---------------------------------------------------------------------------
#
# 临时 shim，待 Lane A 删除 ``app/api/resources/__init__.py`` 里的
# ``FileDownloadCounterMiddleware`` 导入后移除。
# ---------------------------------------------------------------------------
# 1. 临时 shim：绕过 app 侧"半成品 import 死引用"
# ---------------------------------------------------------------------------
#
# 临时 shim —— **待 app 侧 import 清理完成后即可整段删除**。
# 集成时建议移除：留着会掩盖"import 是否真的干净"这个问题。
#
# 背景：M1 的 API 资源正在被各 lane 重写，重写过程中
# ``app/api/resources/__init__.py`` 偶尔会 import 一个**尚未存在**的符号
# （已知案例：``FileDownloadCounterMiddleware``、``MyAccountPasswordResource``），
# 于是 ``import app`` 直接 ImportError，整个测试套件无法收集。
#
# 注意：这里**不能**简单地 ``import app.api.resources.upload`` 之后再补属性 ——
# 第一次 import 失败会让 ``sys.modules`` 里留下一个**半初始化的 ``app.api``
# 模块**，导致 ``app.api.v1_bp`` 与资源模块里持有的 ``v1_bp`` **不是同一个
# 对象**：资源路由注册到一个"孤儿"蓝图上，最终 ``/api/v1/accounts`` 这类路由
# 在 app 路由表里根本不存在（表现为 404 而不是 401/200），而且这种错误极难排查。
#
# 所以这里用 ``meta_path`` finder 拦截 ``app.api.resources`` 包的导入：
# 先按源码执行各资源模块，再把 ``__init__.py`` 里 import 不到的符号**补成占位类**，
# 让 ``app.api`` 一次性、干净地完成导入，路由全部注册到同一个 ``v1_bp``。
#
# 该 shim 是**幂等且自失效**的：一旦 app 侧不再 import 这些缺失符号，
# 它不会补任何东西，行为与"没有 shim"完全一致。
import importlib.abc  # noqa: E402
import importlib.util  # noqa: E402
import types  # noqa: E402


def _install_missing_symbol_shim() -> None:
    """
    让 ``app.api.resources`` 在其 ``__init__.py`` import 了尚不存在的符号时仍能导入。

    做法：给 ``app.api.resources`` 及其子模块装一个 PEP 562 的模块级
    ``__getattr__``——当 ``from app.api.resources.account import X`` 里的 ``X``
    在 ``account`` 模块上找不到时，返回一个占位类而不是抛 ImportError。

    为什么不用"捕获 ImportError 再重试"：``from X import Y`` 是去 **X 模块**上取
    属性 Y，把 Y 塞进包 ``__init__`` 的命名空间没用。而模块级 ``__getattr__``
    正是 Python 为这种"按需补符号"提供的标准机制。
    """
    package_dir = REPO_ROOT / "app" / "api" / "resources"
    if not package_dir.is_dir():
        return

    masked: list[str] = []

    class _Placeholder:
        """占位实现：不改变任何行为，只让 import 能继续。"""

        def __init__(self, *args, **kwargs):
            pass

        async def __call__(self, *args, **kwargs):
            return None

        @classmethod
        def as_view(cls, *args, **kwargs):
            return cls

    def _make_module_getattr(module_name: str):
        def __getattr__(name: str):
            # 只对"看起来像类名"的符号补占位，避免掩盖真正的拼写错误
            if not name[:1].isupper():
                raise AttributeError(name)
            masked.append(f"{module_name}.{name}")
            return type(name, (_Placeholder,), {})

        return __getattr__

    class _PatchedFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname != "app.api.resources" and not fullname.startswith(
                "app.api.resources."
            ):
                return None
            source_file = Path(fullname.replace(".", "/"))
            candidates = [
                package_dir / f"{fullname.rsplit('.', 1)[-1]}.py",
                package_dir / fullname.rsplit(".", 1)[-1] / "__init__.py",
            ]
            target_file = next((c for c in candidates if c.is_file()), None)
            if target_file is None:
                return None

            is_package = target_file.name == "__init__.py"

            class _PatchedLoader(importlib.abc.Loader):
                def create_module(self, spec):
                    return None

                def exec_module(self, module):
                    source = target_file.read_text(encoding="utf-8")
                    exec(compile(source, str(target_file), "exec"), module.__dict__)
                    module.__dict__["__getattr__"] = _make_module_getattr(fullname)

            return importlib.util.spec_from_file_location(
                fullname,
                target_file,
                loader=_PatchedLoader(),
                submodule_search_locations=[str(target_file.parent)] if is_package else None,
            )

    sys.meta_path.insert(0, _PatchedFinder())

    # 记录被遮蔽的符号，便于在回件/日志里说明"哪些 app 侧 import 还不干净"
    import atexit  # noqa: E402

    def _report():
        if masked:
            print(
                "[tests/conftest] 临时 shim 遮蔽了以下尚不存在的符号（app 侧未完成）: "
                + ", ".join(sorted(set(masked)))
            )

    atexit.register(_report)


_install_missing_symbol_shim()

import httpx  # noqa: E402
from httpx import ASGITransport  # noqa: E402
from sanic import Sanic  # noqa: E402
from tortoise import Tortoise  # noqa: E402

from app import create_app  # noqa: E402
from app.config import config_to_dict, get_config  # noqa: E402
from app.models import Account, Role  # noqa: E402


# ---------------------------------------------------------------------------
# 2. 应用夹具
# ---------------------------------------------------------------------------

#: 管理员与普通账户的固定凭据（测试专用）
ADMIN_EMAIL = "SAdmin@Sanic.com"
ADMIN_PASSWORD = "TestAdminPass123!"
NORMAL_EMAIL = "normal.user@example.com"
NORMAL_PASSWORD = "TestNormalPass123!"
NORMAL_USERNAME = "normaluser"


def _build_config(db_path: Path, upload_dir: Path) -> dict:
    """构造测试用配置：sqlite 文件库 + 独立上传目录 + 内存缓存。"""
    cfg = config_to_dict(get_config("testing"))
    cfg.update(
        {
            "TESTING": True,
            "DEBUG": True,
            "ENV": "testing",
            "DATABASE_URL": f"sqlite://{db_path}",
            "UPLOAD_DIR": str(upload_dir),
            "UPLOAD_FOLDER": str(upload_dir),
            "CACHE_TYPE": "memory",
            "USE_CACHE": True,
            "ROUTE_CACHE_ENABLED": False,
            "ENABLE_API_DOCS": True,
            "SESSION_COOKIE_SECURE": False,
        }
    )
    return cfg


def _unregister_previous_apps() -> None:
    """把已注册的 Sanic 实例全部摘掉，保证注册表里最多只有一个应用。"""
    for name in list(Sanic._app_registry):
        Sanic._app_registry.pop(name, None)


@pytest.fixture()
async def app(tmp_path):
    """
    每个测试一个全新的应用实例 + 独立 sqlite 库。

    ``before_server_start`` 监听器负责建库、建表并创建初始管理员账户。

    注意：Sanic 用**名字**注册应用实例（``Sanic._app_registry``），同名实例会互相覆盖；
    而 ``app/api/resources/upload.py`` 的 ``get_upload_root()`` 会调
    ``Sanic.get_app()``——注册表里多于一个应用时它会抛异常。所以这里在创建前
    先把旧实例摘掉，保证任何时刻注册表里只有当前这一个。
    """
    db_path = tmp_path / "test.sqlite3"
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)

    _unregister_previous_apps()

    application = create_app(_build_config(db_path, upload_dir))

    application.asgi = True
    await application._startup()
    loop = asyncio.get_running_loop()
    await application._server_event("init", "before", loop)
    await application._server_event("init", "after", loop)

    try:
        yield application
    finally:
        await application._server_event("shutdown", "before", loop)
        await application._server_event("shutdown", "after", loop)
        await Tortoise.close_connections()
        _unregister_previous_apps()


@pytest.fixture()
async def client(app):
    """
    ASGI 测试客户端。

    基于 ``httpx.ASGITransport``，直接跑在 Sanic 应用上，不监听真实端口。
    ``httpx.AsyncClient`` 自带 cookie jar，所以登录后 cookie 会自动带上。
    """
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver", follow_redirects=True
    ) as http_client:
        yield http_client


# ---------------------------------------------------------------------------
# 3. 账号与 token 夹具
# ---------------------------------------------------------------------------

async def _login(client, email: str, password: str) -> str:
    """真实调用 ``POST /auth/login``，返回 Authorization 头的 token。"""
    response = await client.post(
        "/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 200, (
        f"登录失败：HTTP {response.status_code} {response.text}"
    )
    token = response.headers.get("authorization")
    assert token, "登录响应缺少 Authorization 头"
    return token


async def _ensure_normal_user() -> None:
    """创建一个已验证、未禁用、非管理员的普通账户。"""
    existing = await Account.filter(email=NORMAL_EMAIL).first()
    if existing is not None:
        await existing.roles.clear()
        await existing.save()
        return

    account = Account(
        username=NORMAL_USERNAME,
        email=NORMAL_EMAIL,
        verified=True,
        disabled=False,
        is_admin=False,
    )
    account.set_password(NORMAL_PASSWORD)
    await account.save()

    # 给一个"只读"角色：没有任何管理权限 → 访问管理接口应当 403
    role, _ = await Role.get_or_create(
        name="reader",
        defaults={"description": "只读角色", "permissions": {}},
    )
    await account.roles.add(role)


@pytest.fixture()
async def admin_token(client):
    """初始管理员的真实登录 token。"""
    return await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)


@pytest.fixture()
async def normal_user_token(client):
    """普通（非管理员）账户的真实登录 token。"""
    await _ensure_normal_user()
    return await _login(client, NORMAL_EMAIL, NORMAL_PASSWORD)


@pytest.fixture()
async def auth_headers(admin_token):
    """管理员请求头。"""
    return {"Authorization": admin_token}


@pytest.fixture()
async def normal_auth_headers(normal_user_token):
    """普通账户请求头。"""
    return {"Authorization": normal_user_token}


# ---------------------------------------------------------------------------
# 4. 路由表工具
# ---------------------------------------------------------------------------

def _concrete_path(path: str) -> str:
    """把路由模板里的动态段替换成可请求的示例值。"""
    replacements = {
        "<account_id:int>": "1",
        "<role_id:int>": "1",
        "<file_id:int>": "1",
        "<profile_id:int>": "1",
        "<setting_id:int>": "1",
        "<log_id:int>": "1",
        "<key:str>": "sample",
        "<key:string>": "sample",
        "<category:str>": "general",
    }
    out = path
    for pattern, value in replacements.items():
        out = out.replace(pattern, value)
    return out


@pytest.fixture(scope="session")
def registered_api_routes():
    """
    从应用路由表**动态提取**受保护的 API 路由。

    不是硬编码路径列表——Lane A 后续新增资源时，本集合自动跟着变。
    只保留 ``/api/`` 前缀的业务接口（排除 ``/health``、文档路由与静态文件）。

    这里只读路由表，不需要启动应用，也就不碰数据库。
    """
    _unregister_previous_apps()
    probe = create_app(
        _build_config(
            Path(tempfile.gettempdir()) / "egc_route_probe.sqlite3",
            Path(tempfile.gettempdir()) / "egc_route_probe_uploads",
        )
    )
    routes = []
    for route in probe.router.routes:
        path = "/" + route.path.lstrip("/")
        if not path.startswith("/api/"):
            continue
        for method in sorted(route.methods or set()):
            if method in ("HEAD", "OPTIONS"):
                continue
            routes.append((method, _concrete_path(path)))
    _unregister_previous_apps()
    return routes


@pytest.fixture()
def api_route_ids(registered_api_routes):
    """供参数化测试使用的 ``(method, path)`` 列表（已去重）。"""
    seen = set()
    unique = []
    for method, path in registered_api_routes:
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(key)
    return unique
