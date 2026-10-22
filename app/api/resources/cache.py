#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
缓存管理 API 资源模块

提供缓存统计、缓存键查询/修改/删除与路由缓存清理。

安全要点：

* 所有接口都要求 ``system:admin`` 权限（``@check_permissions("system", "admin")``），
  未认证 401、权限不足 403。
* 只使用缓存后端的公开接口（``app/cache/``），不改动后端实现。
* 错误响应统一走 ``APIResponse.error``；不把内部异常 ``str(e)`` 透给用户，
  也不用 ``APIError`` 抛异常（``APIError`` 是错误码常量类，不是异常）。
* 路由名显式指定，避免同一个 view 类注册两次时 Sanic 报
  ``Duplicate route names detected`` 导致应用起不来。
"""

import json
from typing import Any, Dict, List

from sanic.request import Request
from sanic.views import HTTPMethodView

from app.api import APIResponse, v1_bp
from app.api.responses import APIError
from app.auth.authorization import check_permissions
from app.cache import get_cache
from app.cache.decorators import clear_route_cache

#: 缓存键列表分页上限
MAX_LIMIT = 1000

#: 缓存键预览的最大长度
PREVIEW_LENGTH = 50


def _bad_request(message: str):
    """统一的 400 响应。"""
    return APIResponse.error(
        message=message,
        error_code=APIError.VALIDATION_ERROR,
        status_code=400,
    )


def _not_found(message: str):
    """统一的 404 响应。"""
    return APIResponse.error(
        message=message,
        error_code=APIError.RESOURCE_NOT_FOUND,
        status_code=404,
    )


def _server_error(message: str = "服务器内部错误"):
    """统一的 500 响应（不暴露内部异常细节）。"""
    return APIResponse.error(
        message=message,
        error_code=APIError.SERVER_ERROR,
        status_code=500,
    )


def _positive_int(value: Any, default: int, maximum: int = None) -> int:
    """把请求参数解析为正整数，非法时回落到默认值。"""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    if number < 1:
        return default
    return min(number, maximum) if maximum else number


def _preview(value: Any) -> str:
    """生成缓存值的简短预览。"""
    if value is None:
        return "None"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value[:PREVIEW_LENGTH] + "..." if len(value) > PREVIEW_LENGTH else value
    if isinstance(value, (list, tuple)):
        return f"{type(value).__name__}[{len(value)}]"
    if isinstance(value, dict):
        return f"dict{{{len(value)}}}"
    return f"{type(value).__name__} object"


def _safe_dump(value: Any) -> str:
    """把缓存值转成可读字符串；序列化失败时回落到 repr。"""
    try:
        return json.dumps(value, ensure_ascii=False, indent=2)
    except (TypeError, ValueError):
        return repr(value)


class CacheResource(HTTPMethodView):
    """缓存统计与清理：``/api/v1/cache``"""

    @check_permissions("system", "admin")
    async def get(self, request: Request):
        """获取缓存统计信息。"""
        try:
            cache = get_cache()
            stats = cache.get_stats()
            keys_count = len(cache.keys())
        except Exception:
            return _server_error("获取缓存统计信息失败")

        return APIResponse.success(
            data={
                "cache_type": request.app.config.get("CACHE_TYPE", "memory"),
                "stats": stats,
                "keys_count": keys_count,
                "enabled": request.app.config.get("USE_CACHE", True),
                "route_cache_enabled": request.app.config.get("ROUTE_CACHE_ENABLED", True),
            },
            message="获取缓存统计信息成功",
        )

    @check_permissions("system", "admin")
    async def delete(self, request: Request):
        """清理缓存（``type=route`` 只清路由缓存，``type=all`` 清全部）。"""
        pattern = request.args.get("pattern", "*")
        cache_type = request.args.get("type", "all")

        try:
            if cache_type == "route":
                count = clear_route_cache(pattern)
                message = f"已清除 {count} 个路由缓存键"
            else:
                cache = get_cache()
                if cache_type == "all":
                    cache.clear()
                    message = "已清除所有缓存"
                else:
                    keys = cache.keys(pattern)
                    count = cache.delete_many(keys)
                    message = f"已清除 {count} 个缓存键"
        except Exception:
            return _server_error("清理缓存失败")

        return APIResponse.success(message=message)


class CacheKeysResource(HTTPMethodView):
    """缓存键列表：``/api/v1/cache/keys``"""

    @check_permissions("system", "admin")
    async def get(self, request: Request):
        """按模式分页列出缓存键。"""
        pattern = request.args.get("pattern", "*")
        page = _positive_int(request.args.get("page"), 1)
        limit = _positive_int(request.args.get("limit"), 100, MAX_LIMIT)

        try:
            cache = get_cache()
            all_keys = cache.keys(pattern)
        except Exception:
            return _server_error("获取缓存键列表失败")

        total = len(all_keys)
        start = (page - 1) * limit
        page_keys = all_keys[start:start + limit]

        keys_info: List[Dict[str, Any]] = []
        for key in page_keys:
            ttl = cache.ttl(key)
            keys_info.append({
                "key": key,
                "ttl": ttl,
                "expires_in": "永不过期" if ttl == -1 else (f"{ttl}秒" if ttl >= 0 else "已过期"),
                "value_type": type(cache.get(key)).__name__,
                "preview": _preview(cache.get(key)),
            })

        return APIResponse.success(
            data={
                "keys": keys_info,
                "total": total,
                "page": page,
                "limit": limit,
                "pages": (total + limit - 1) // limit if limit else 0,
            },
            message="获取缓存键列表成功",
        )


class CacheKeyResource(HTTPMethodView):
    """单个缓存键：``/api/v1/cache/keys/<key>``"""

    @check_permissions("system", "admin")
    async def get(self, request: Request, key: str):
        """获取单个缓存键的详细信息。"""
        try:
            cache = get_cache()
            if not cache.exists(key):
                return _not_found(f"缓存键 '{key}' 不存在")
            value = cache.get(key)
            ttl = cache.ttl(key)
        except Exception:
            return _server_error("获取缓存键信息失败")

        return APIResponse.success(
            data={
                "key": key,
                "ttl": ttl,
                "expires_in": "永不过期" if ttl == -1 else (f"{ttl}秒" if ttl >= 0 else "已过期"),
                "value_type": type(value).__name__,
                "value": value,
                "value_str": _safe_dump(value),
            },
            message="获取缓存键详细信息成功",
        )

    @check_permissions("system", "admin")
    async def put(self, request: Request, key: str):
        """更新缓存键的过期时间（``timeout<=0`` 表示设为永不过期）。"""
        body = request.json
        if not isinstance(body, dict) or not body:
            return _bad_request("请求体必须是非空的 JSON 对象")

        timeout = body.get("timeout")
        if timeout is None:
            return _bad_request("缺少必要参数：timeout")
        if isinstance(timeout, bool) or not isinstance(timeout, int):
            return _bad_request("参数类型错误：timeout 必须是整数")

        try:
            cache = get_cache()
            if not cache.exists(key):
                return _not_found(f"缓存键 '{key}' 不存在")

            if timeout <= 0:
                success = cache.set(key, cache.get(key))
            else:
                success = cache.expire(key, timeout)
        except Exception:
            return _server_error("更新缓存键失败")

        if not success:
            return _server_error(f"更新缓存键 '{key}' 过期时间失败")
        return APIResponse.success(message=f"缓存键 '{key}' 过期时间已更新")

    @check_permissions("system", "admin")
    async def delete(self, request: Request, key: str):
        """删除单个缓存键。"""
        try:
            cache = get_cache()
            if not cache.exists(key):
                return _not_found(f"缓存键 '{key}' 不存在")
            success = cache.delete(key)
        except Exception:
            return _server_error("删除缓存键失败")

        if not success:
            return _server_error(f"删除缓存键 '{key}' 失败")
        return APIResponse.success(message=f"缓存键 '{key}' 已删除")


# 注册路由（显式指定路由名，避免 Sanic 的路由名重复检查）
cache_resource = CacheResource()
cache_keys_resource = CacheKeysResource()
cache_key_resource = CacheKeyResource()

v1_bp.add_route(cache_resource.as_view(), "/cache", name="cache_overview")
v1_bp.add_route(cache_keys_resource.as_view(), "/cache/keys", name="cache_keys")
v1_bp.add_route(cache_key_resource.as_view(), "/cache/keys/<key:str>", name="cache_key")
