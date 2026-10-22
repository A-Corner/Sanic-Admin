#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
缓存装饰器模块

提供路由缓存装饰器，用于缓存API响应。

安全约定
--------
* 缓存键只由**字符串**构成（方法、路径、查询串、用户 id 等），绝不把 request
  对象本身塞进键里——request 不可哈希、不可序列化，且会把会话状态带进缓存键。
* 缓存的是**已经鉴权之后**的结果。若把 ``@cached`` 放在 ``@requires_permission``
  之内（后者先执行），缓存命中时鉴权仍会先跑；反之则会把未鉴权的数据缓存起来，
  造成越权读取。本项目的用法一律是 ``@requires_permission`` 在外、``@cached`` 在内。
* 不同用户的数据必须用不同的缓存键隔离：键中包含当前账户 id。
"""

import hashlib
import inspect
import json
from functools import wraps
from typing import Any, Optional, Callable, Dict, Union

from sanic.request import Request
from sanic.response import HTTPResponse, json as json_response

from app.cache import get_cache
from app.config import config

#: 参与缓存键的请求头（只取与响应表示相关的稳定字段，不含 Cookie/Authorization）
_CACHEABLE_HEADERS = ("content-type", "accept", "accept-language", "x-requested-with")


def _account_id(request: Request) -> str:
    """
    取当前已认证账户 id（取不到时返回 "anonymous"）。

    鉴权中间件与 ``requires_permission`` 会把会话放进 ``request.ctx``；
    未认证请求统一落到 "anonymous" 桶，不会与任何已登录用户共享缓存。
    """
    session = getattr(request.ctx, "authentication_session", None)
    bearer = getattr(session, "bearer", None) if session is not None else None
    account_id = getattr(bearer, "id", None)
    if account_id is None:
        return "anonymous"
    return str(account_id)


def generate_cache_key(request: Request, include_query: bool = True, include_body: bool = False,
                       include_headers: bool = False, prefix: str = "",
                       scope: Optional[str] = None) -> str:
    """
    生成缓存键

    根据请求URL和可选的查询参数、请求体和请求头生成缓存键。

    键中始终包含**当前账户 id**（``scope`` 参数），使不同用户的响应互不串用。

    Args:
        request: Sanic请求对象
        include_query: 是否包含查询参数
        include_body: 是否包含请求体
        include_headers: 是否包含请求头
        prefix: 缓存键前缀
        scope: 隔离维度（通常是账户 id）；为空时自动取当前认证账户 id

    Returns:
        str: 缓存键
    """
    # 基础键为请求方法、路径与隔离维度
    key_parts = [request.method, request.path, scope if scope is not None else _account_id(request)]

    # 添加查询参数
    if include_query and request.args:
        # 将查询参数按键排序，然后合并
        query_parts = []
        for k in sorted(request.args.keys()):
            values = request.args.getlist(k)
            if len(values) == 1:
                query_parts.append(f"{k}={values[0]}")
            else:
                # 多值参数，先排序
                values.sort()
                for v in values:
                    query_parts.append(f"{k}={v}")
        key_parts.append("&".join(query_parts))

    # 添加请求体
    if include_body and request.body:
        try:
            # 尝试解析为JSON并按键排序，保证相同的JSON对象生成相同的键
            body_dict = json.loads(request.body)
            # 将字典转换为规范化的JSON字符串，确保键的顺序一致
            body_str = json.dumps(body_dict, sort_keys=True)
            key_parts.append(body_str)
        except (json.JSONDecodeError, TypeError):
            # 如果不是有效的JSON，则使用原始请求体
            key_parts.append(request.body.decode('utf-8', errors='ignore'))

    # 添加请求头
    if include_headers and request.headers:
        headers_parts = []
        for k in _CACHEABLE_HEADERS:
            if k in request.headers:
                headers_parts.append(f"{k}:{request.headers[k]}")
        key_parts.append(",".join(headers_parts))

    # 合并所有部分并添加前缀
    key = ":".join(key_parts)

    # 对较长的键使用哈希值
    if len(key) > 250:
        key = hashlib.md5(key.encode('utf-8')).hexdigest()

    # 添加前缀
    if prefix:
        key = f"{prefix}:{key}"

    return key


def cached(timeout: Optional[int] = None, key_prefix: str = "route",
           include_query: bool = True, include_body: bool = False,
           include_headers: bool = False, unless: Optional[Callable] = None) -> Callable:
    """
    路由缓存装饰器

    缓存路由处理程序的响应结果。

    兼容两种签名：

    * 函数处理器 ``async def handler(request, ...)``；
    * 视图方法 ``async def get(self, request, ...)``（``HTTPMethodView``）——
      此时 ``self`` 会被跳过，``request`` 仍从位置参数中识别。

    缓存键只由字符串构成，并包含当前账户 id，因此不同用户的响应不会互相污染。

    Args:
        timeout: 缓存过期时间（秒），如果为None则使用默认过期时间
        key_prefix: 缓存键前缀
        include_query: 是否在缓存键中包含查询参数
        include_body: 是否在缓存键中包含请求体
        include_headers: 是否在缓存键中包含请求头
        unless: 判断是否应该跳过缓存的函数，参数为request，返回True时跳过缓存

    Returns:
        Callable: 装饰后的函数
    """
    def decorator(f):
        @wraps(f)
        async def decorated_function(*args, **kwargs):
            # 兼容函数处理器 (request, ...) 与视图方法 (self, request, ...)
            request = next((a for a in args if isinstance(a, Request)), None)
            if request is None:
                raise TypeError("cached 装饰的处理函数必须接收 Request 参数")
            # 如果缓存未启用或者请求方法不是GET，则不缓存
            if not config.ROUTE_CACHE_ENABLED or request.method != "GET":
                return await f(*args, **kwargs)

            # 如果提供了unless函数并且函数返回True，则不缓存
            if unless and unless(request):
                return await f(*args, **kwargs)

            # 获取缓存实例
            cache = get_cache()

            # 生成缓存键（含账户 id 隔离）
            cache_key = generate_cache_key(
                request,
                include_query=include_query,
                include_body=include_body,
                include_headers=include_headers,
                prefix=key_prefix
            )

            # 尝试从缓存获取响应
            cached_response = cache.get(cache_key)
            if cached_response is not None:
                # 从缓存中恢复响应
                return json_response(
                    cached_response.get('body', {}),
                    status=cached_response.get('status', 200),
                    headers=cached_response.get('headers', {})
                )

            # 执行原始处理程序
            response = await f(*args, **kwargs)

            # 缓存响应
            if isinstance(response, HTTPResponse):
                # 计算过期时间
                cache_timeout = timeout if timeout is not None else config.ROUTE_CACHE_TIMEOUT

                # 缓存响应内容
                try:
                    response_body = json.loads(response.body)
                except (json.JSONDecodeError, TypeError):
                    # 如果不是有效的JSON，则不缓存
                    return response

                # 只缓存状态码与内容类型等安全头，不缓存 Content-Length /
                # Content-Disposition 等与本次响应体绑定的头，避免回放时长度错乱。
                cache_data = {
                    'body': response_body,
                    'status': response.status,
                    'headers': {
                        k: v for k, v in response.headers.items()
                        if k.lower() in ('content-type',)
                    }
                }

                cache.set(cache_key, cache_data, timeout=cache_timeout)

            return response

        return decorated_function

    return decorator


def clear_route_cache(pattern: str = "*") -> int:
    """
    清除路由缓存

    Args:
        pattern: 缓存键模式，默认清除所有路由缓存

    Returns:
        int: 清除的缓存键数量
    """
    cache = get_cache()

    # 添加路由缓存前缀
    if not pattern.startswith("route:"):
        pattern = f"route:{pattern}"

    # 获取匹配的缓存键
    keys = cache.keys(pattern)

    # 删除缓存
    if keys:
        return cache.delete_many(keys)

    return 0
