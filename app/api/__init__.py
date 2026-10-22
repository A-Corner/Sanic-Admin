#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
API包，包含所有API相关模块和蓝图
"""

from sanic import Blueprint
from sanic.request import Request
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


def _ensure_unique_route_names(blueprint) -> None:
    """
    为同一视图注册到多个 URL 的路由补上唯一名称。

    ``HTTPMethodView.as_view()`` 把 ``view.__name__`` 设为类名，因此同一个视图类
    注册到两个 URL 时会得到相同的路由名；Sanic 23.6 启动时检测到重名会直接抛
    ``ServerError`` 导致进程起不来。这里按 URL 为重名路由追加后缀，使其唯一。

    路由名不参与业务逻辑（项目内没有 ``url_for`` 调用），只用于 Sanic 内部索引。
    """
    grouped = {}
    for route in blueprint._future_routes:
        grouped.setdefault(route.name, []).append(route)

    for name, routes in grouped.items():
        if len(routes) < 2:
            continue
        for route in routes:
            slug = route.uri.strip("/").replace("/", "_").replace("<", "").replace(">", "")
            new_name = f"{name}_{slug}"
            if new_name == route.name:
                continue
            # FutureRoute 是 NamedTuple（不可变），用 _replace 生成新条目替换
            blueprint._future_routes.discard(route)
            blueprint._future_routes.add(route._replace(name=new_name))


for _bp in (v1_bp, database_bp, compression_bp):
    _ensure_unique_route_names(_bp)


async def _require_api_authentication(request: Request):
    """
    API 蓝图组级请求中间件：**默认拒绝**未认证请求。

    认证逻辑复用 ``app.auth.authentication.authenticate_request``：
    它校验会话令牌并把会话写入 ``request.ctx.authentication_session``，
    下游资源（``requires_permission`` 等装饰器）会直接复用该会话，不重复解码令牌。

    * 认证失败抛 ``AuthenticationError``（401），由全局异常处理器统一转成错误响应；
    * OPTIONS 预检请求直接放行（CORS 预检不应被 401 拦截）；
    * 授权（权限）仍由各资源自己的 ``requires_permission`` 装饰器负责。
    """
    if request.method == "OPTIONS":
        return None

    from app.auth.authentication import authenticate_request

    await authenticate_request(request)
    return None


# 蓝图组中间件：注册到组内每个子蓝图（v1_bp / database_bp / compression_bp）
api_bp.middleware('request')(_require_api_authentication)

# 导出常用类和函数
__all__ = [
    'BaseResource',
    'CRUDResource',
    'APIResponse',
    'APIError',
    'api_bp',
    'v1_bp'
]
