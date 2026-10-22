#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
数据库性能分析API资源模块

提供数据库查询日志、慢查询分析和连接池状态管理接口。
权限资源名为 ``system:database``（操作 query / connectionpool / manage），管理员账户拥有全部权限。
"""

import re

from sanic import Blueprint
from sanic.views import HTTPMethodView

from app.api.responses import APIResponse, APIError
from app.auth.authorization import requires_permission
from app.database.connection_pool import (
    get_connection_pool,
    set_pool_options,
)
from app.database.query_analyzer import (
    analyze_query_plan,
    get_query_logs,
    get_slow_queries,
)

bp = Blueprint("database", url_prefix="/database")

QUERY_TYPES = ("SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "OTHER")
_CONN_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,31}$")


def _bad_request(message: str, details=None):
    return APIResponse.error(message=message, error_code=APIError.VALIDATION_ERROR,
                             status_code=400, details=details)


def _int_arg(request, name: str, default: int, minimum: int, maximum: int):
    """读取整数查询参数；非法返回 (None, 错误响应)。"""
    raw = request.args.get(name)
    if raw is None:
        return default, None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None, _bad_request(f"参数 {name} 必须是整数")
    if not minimum <= value <= maximum:
        return None, _bad_request(f"参数 {name} 必须在 {minimum} 到 {maximum} 之间")
    return value, None


def _float_arg(request, name: str):
    raw = request.args.get(name)
    if raw is None:
        return None, None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None, _bad_request(f"参数 {name} 必须是数字")
    if value < 0:
        return None, _bad_request(f"参数 {name} 不能为负数")
    return value, None


def _json_body(request):
    body = request.json
    return body if isinstance(body, dict) else None


class QueryLogsResource(HTTPMethodView):
    """查询日志资源"""

    @requires_permission("system:database:query")
    async def get(self, request):
        """获取查询日志列表，支持按类型、持续时间和来源过滤。"""
        limit, err = _int_arg(request, "limit", 50, 1, 100)
        if err:
            return err
        min_duration, err = _float_arg(request, "min_duration")
        if err:
            return err
        max_duration, err = _float_arg(request, "max_duration")
        if err:
            return err
        query_type = request.args.get("query_type")
        if query_type is not None and query_type not in QUERY_TYPES:
            return _bad_request(f"query_type 必须是 {', '.join(QUERY_TYPES)} 之一")

        logs = await get_query_logs(
            limit=limit,
            query_type=query_type,
            min_duration=min_duration,
            max_duration=max_duration,
            source=request.args.get("source"),
        )
        return APIResponse.success(data=logs)


class SlowQueriesResource(HTTPMethodView):
    """慢查询日志资源"""

    @requires_permission("system:database:query")
    async def get(self, request):
        """获取慢查询日志。"""
        limit, err = _int_arg(request, "limit", 20, 1, 100)
        if err:
            return err
        return APIResponse.success(data=await get_slow_queries(limit=limit))


class QueryPlanResource(HTTPMethodView):
    """查询执行计划分析资源（只读：仅接受单条 SELECT，只发出 EXPLAIN）"""

    @requires_permission("system:database:query")
    async def post(self, request):
        """分析 SQL 查询执行计划。写入类 SQL 一律拒绝（400）。"""
        body = _json_body(request)
        if body is None:
            return _bad_request("请求体必须是 JSON 对象")
        sql = body.get("sql")
        params = body.get("params")
        conn_name = body.get("conn_name", "default")
        if not isinstance(sql, str) or not sql.strip():
            return _bad_request("sql 是必填的字符串")
        if params is not None and not isinstance(params, list):
            return _bad_request("params 必须是列表")
        if not isinstance(conn_name, str) or not _CONN_NAME_RE.match(conn_name):
            return _bad_request("conn_name 不合法")

        result = await analyze_query_plan(sql, params, conn_name)
        error = result.get("error")
        if error:
            if error.startswith("拒绝分析"):
                return _bad_request(error)
            return APIResponse.error(message=error, error_code=APIError.SERVER_ERROR,
                                     status_code=500)
        return APIResponse.success(data=result)


class ConnectionPoolResource(HTTPMethodView):
    """数据库连接池资源"""

    # 与 set_pool_options 的选项名一致：(类型, 最小值, 最大值)
    _OPTION_RULES = {
        "min_size": (int, 1, 100),
        "max_size": (int, 1, 500),
        "max_idle_time": (int, 1, 86400),
        "connect_timeout": (float, 0.1, 300.0),
        "echo": (bool, None, None),
        "retry_limit": (int, 0, 10),
        "retry_interval": (float, 0.1, 10.0),  # 秒
    }

    @requires_permission("system:database:connectionpool")
    async def get(self, request):
        """获取数据库连接池状态。"""
        return APIResponse.success(data=await get_connection_pool())

    @requires_permission("system:database:connectionpool:manage")
    async def put(self, request):
        """更新数据库连接池配置（仅修改内存中的选项）。"""
        body = _json_body(request)
        if body is None:
            return _bad_request("请求体必须是 JSON 对象")
        unknown = sorted(set(body) - set(self._OPTION_RULES))
        if unknown:
            return _bad_request(f"不支持的选项: {', '.join(unknown)}")

        options = {}
        for key, value in body.items():
            if value is None:
                continue
            kind, low, high = self._OPTION_RULES[key]
            if kind is bool:
                if not isinstance(value, bool):
                    return _bad_request(f"{key} 必须是布尔值")
            else:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    return _bad_request(f"{key} 必须是数字")
                if kind is int and int(value) != value:
                    return _bad_request(f"{key} 必须是整数")
                value = kind(value)
                if not low <= value <= high:
                    return _bad_request(f"{key} 必须在 {low} 到 {high} 之间")
            options[key] = value

        current = (await get_connection_pool())["options"]
        if options.get("min_size", current["min_size"]) > options.get("max_size", current["max_size"]):
            return _bad_request("min_size 不能大于 max_size")

        set_pool_options(**options)
        return APIResponse.success(data=await get_connection_pool(), message="连接池配置已更新")


class DatabaseAnalysisResource(HTTPMethodView):
    """数据库性能分析资源"""

    @requires_permission("system:database:query")
    async def get(self, request):
        """返回数据库查询性能、慢查询和连接池状态的综合分析。"""
        slow_queries = await get_slow_queries(limit=5)
        logs_data = await get_query_logs(limit=1)
        return APIResponse.success(data={
            "query_stats": logs_data["stats"],
            "type_stats": logs_data["type_stats"],
            "recent_slow_queries": slow_queries,
            "connection_pool": await get_connection_pool(),
        })


# 注册路由
bp.add_route(QueryLogsResource.as_view(), "/query-logs")
bp.add_route(SlowQueriesResource.as_view(), "/slow-queries")
bp.add_route(QueryPlanResource.as_view(), "/query-plan")
bp.add_route(ConnectionPoolResource.as_view(), "/connection-pool")
bp.add_route(DatabaseAnalysisResource.as_view(), "/analysis")
