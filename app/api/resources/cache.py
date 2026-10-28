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
from app.api.resources.route_methods import register_view
from app.api.responses import APIError
from app.auth.authorization import check_permissions
from app.cache import get_cache
from app.cache.decorators import clear_route_cache
from app.services.audit import record_resource_event

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
        """
        清理缓存。**必须显式指定 ``type``**，没有默认行为。

        ``type`` 的三个合法值（**三个都写审计**）：

        =========== ==================================== ==================
        type        行为                                 审计 ``object_id``
        =========== ==================================== ==================
        ``route``   只清路由缓存（``pattern`` 生效）      ``route:<pattern>``
        ``pattern`` 按 ``pattern`` 删除匹配的键            ``pattern:<pattern>``
        ``all``     全量清空（**破坏性**）                ``all``
        =========== ==================================== ==================

        为什么取消默认值（EVT-20261028-041）
        ===================================
        此前 ``type`` 默认 ``"all"`` —— 一个**不带参数的 DELETE 就会清空整个缓存**。
        实测：``DELETE /api/v1/cache`` 不带任何 query 直接全清。

        这与 HTTP 语义相悖（DELETE 通常针对**指定资源**），且**审计后置**：
        全量清空是三个分支里唯一不可逆的，却是唯一有默认值的。

        改为必填后，误操作需要显式写 ``?type=all`` —— 从「默认危险」变成
        「显式危险」。

        为什么三个分支都写审计（不是只有 ``all``）
        ==========================================
        最初只让 ``all`` 写。复审发现这留下了一条**不留痕的全清路径**：
        ``?type=pattern&pattern=*`` 与 ``type=all`` 效果完全相同（``*`` 匹配全部键）
        却因为是 ``pattern`` 分支而不写审计。

        尝试过「先判断这次 pattern 是否等效全清，等于才拒绝/才审计」，
        但这条路要求穷举「所有等效于 ``*`` 的 glob 写法」（``*`` / ``**`` / ``*?`` /
        ``[a-w]*`` …），集合无法穷举；而且两个缓存后端（``fnmatch`` 与 redis
        ``KEYS``）的 glob 语义还不一致。

        改成「凡删除必审计」后问题消失：**审计记录的内容是「删了什么范围」，
        而「这个范围是否等于全部」是派生问题，不需要在审计时回答。**

        为什么 pattern 不能含空格或 ``fields=``
        ======================================
        ``pattern`` 会被拼进审计 ``detail``（``id=pattern:<pattern>``），而 detail
        是空格分隔的 ``key=value`` 格式。两类字符会破坏它，且都能让操作者伪造
        审计内容 —— 详见 ``delete`` 方法体内的注释与 ``EVT-20261028-043``。
        """
        cache_type = request.args.get("type")
        if cache_type not in ("route", "pattern", "all"):
            return _bad_request(
                "必须显式指定 type 参数，可选值：route（只清路由缓存）/ "
                "pattern（按 pattern 删除匹配键）/ all（全量清空，会写审计）"
            )

        pattern = request.args.get("pattern", "*")

        # pattern 会被拼进审计的 detail（``id=pattern:<pattern>``），而 detail 是
        # **空格分隔的 key=value 格式**（audit.py:152-159）：
        #
        #     parts = [f"id={object_id}"]; detail = " ".join(parts)
        #
        # 而官方解析器（docs/audit-log-format.md）按 ``detail[3:].split(" ", 1)[0]``
        # 取 id、按 ``detail.find("fields=")`` 取字段名。两条都受 pattern 内容影响：
        #
        # 1. **空格** → ``split(" ", 1)[0]`` 截断 id：
        #      pattern="a b" → detail="id=pattern:a b" → 解析出 id="pattern:a"
        # 2. **子串 "fields="** → ``find("fields=")`` 命中的是 pattern 里那个：
        #      pattern="fields=y" → detail="id=pattern:fields=y"
        #      → 解析出 fields=["y"]（id 段看起来正常，但 fields 被伪造）
        #
        # 第 2 条比第 1 条更隐蔽：**id 没被截断，整条记录看起来格式合法**，
        # 而伪造的 fields 语义是「被操作的字段名」——攻击者可以让审计看起来
        # 像「只动了 title」。
        #
        # 这里只拦这两类。``\\t`` / ``\\n`` / ``=`` / ``:`` / ``,`` / ``*`` 都实测
        # 不破坏结构（``split(" ", 1)`` 只认 ASCII 空格）。
        #
        # 根本修法是让 ``record_resource_event`` 约束 ``object_id`` 的字符集或
        # 改用结构化 detail —— 那要动解析契约与所有消费方，不在本 PR 范围
        # （已记 EVT-20261028-043）。
        if " " in pattern:
            return _bad_request("pattern 不能包含空格（空格会截断审计记录中的对象标识）")
        if "fields=" in pattern:
            return _bad_request("pattern 不能包含 'fields=' 子串（会伪造审计记录中的字段名）")

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

        # 三个分支都写审计 —— 不是只有 all。
        #
        # 为什么改（EVT-20261028-041 复审发现）：此前只有 ``type=all`` 写审计，
        # 于是 ``?type=pattern&pattern=*`` 能达成与 ``type=all`` 完全相同的效果
        # （pattern="*" 匹配全部键）却不留任何记录 —— 一条**不留痕的全清路径**。
        #
        # 尝试过「检测 pattern 是否等于全清再决定是否审计」，但那条路要求穷举
        # 「所有等效于 * 的 glob 写法」（``*`` / ``**`` / ``*?`` / ``[a-w]*`` …），
        # 集合无法穷举，且两个缓存后端（fnmatch / redis KEYS）语义还不同。
        #
        # 改成「凡删除必审计」后，这个问题不存在了：审计的内容是「删了什么范围」，
        # 而「这个范围是否等于全部」是一个派生问题，不需要在审计时回答。
        #
        # object_id 的取值按分支填，让 detail 能读出删除范围：
        #   type=all     -> id=all
        #   type=route   -> id=route:<pattern>
        #   type=pattern -> id=pattern:<pattern>
        if cache_type == "all":
            object_id = "all"
        elif cache_type == "route":
            object_id = f"route:{pattern}"
        else:
            object_id = f"pattern:{pattern}"

        # 审计是旁路：record_resource_event 永不抛出（audit.py:144），
        # 所以这里不需要 try/except，也不该因为它影响主请求的结果。
        #
        # account 直接取 ctx.authentication_session.bearer，不加 getattr 兜底：
        # 本方法有 @check_permissions，而 check_permissions 内部必走
        # authenticate_request，后者**无条件**写
        # ``request.ctx.authentication_session``（authentication.py:389）。
        # 仓库里 8 处同类调用（order/ticket/customer 各 2-3 处）也都是直接取。
        #
        # 注意：``object_id="all"`` 与 ``object_id="route:*"`` 挤在同一个契约里
        # 是拉伸 —— 该参数的语义是「被操作记录的 id」，而批量操作没有单一对象。
        # 已记 EVT-20261028-043。
        await record_resource_event(
            request,
            resource="cache",
            action="delete",
            object_id=object_id,
            account=request.ctx.authentication_session.bearer,
        )

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

register_view(v1_bp, "/cache", cache_resource, ["GET", "DELETE"], "cache_overview")
register_view(v1_bp, "/cache/keys", cache_keys_resource, ["GET"], "cache_keys")
register_view(
    v1_bp, "/cache/keys/<key:str>", cache_key_resource, ["GET", "PUT", "DELETE"], "cache_key"
)
