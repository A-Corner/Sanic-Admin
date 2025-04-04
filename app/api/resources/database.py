#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
数据库性能分析API资源模块

提供数据库查询日志、慢查询分析和连接池状态管理接口
"""

from sanic import Blueprint
from sanic.response import json
from sanic.exceptions import NotFound, Forbidden

from app.api.base import BaseResource, response
from app.auth.authorization import requires_permission
from app.utils.validator import validate_request
from app.database.query_analyzer import (
    get_query_logs, 
    get_slow_queries, 
    analyze_query_plan
)
from app.database.connection_pool import (
    get_connection_pool,
    apply_pool_options,
    configure_pool,
    set_pool_options
)

bp = Blueprint("database", url_prefix="/api/database")


class QueryLogsResource(BaseResource):
    """查询日志资源"""
    
    @requires_permission("system:database:query")
    @validate_request(query={
        "limit": {"type": "integer", "min": 1, "max": 100, "default": 50},
        "query_type": {"type": "string", "allowed": ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "OTHER"], "nullable": True},
        "min_duration": {"type": "float", "min": 0, "nullable": True},
        "max_duration": {"type": "float", "min": 0, "nullable": True},
        "source": {"type": "string", "nullable": True}
    })
    async def get(self, request):
        """
        获取查询日志列表
        
        获取系统数据库查询日志，支持按类型、持续时间和来源过滤
        """
        logs = await get_query_logs(
            limit=request.args.get("limit", 50, type=int),
            query_type=request.args.get("query_type"),
            min_duration=request.args.get("min_duration", type=float),
            max_duration=request.args.get("max_duration", type=float),
            source=request.args.get("source")
        )
        
        return response(data=logs)


class SlowQueriesResource(BaseResource):
    """慢查询日志资源"""
    
    @requires_permission("system:database:query")
    @validate_request(query={
        "limit": {"type": "integer", "min": 1, "max": 100, "default": 20}
    })
    async def get(self, request):
        """
        获取慢查询日志
        
        获取系统记录的慢查询日志，用于优化性能瓶颈
        """
        logs = await get_slow_queries(
            limit=request.args.get("limit", 20, type=int)
        )
        
        return response(data=logs)


class QueryPlanResource(BaseResource):
    """查询执行计划分析资源"""
    
    @requires_permission("system:database:query")
    @validate_request(json={
        "sql": {"type": "string", "required": True},
        "params": {"type": "list", "nullable": True},
        "conn_name": {"type": "string", "default": "default"}
    })
    async def post(self, request):
        """
        分析SQL查询执行计划
        
        提交SQL查询并返回执行计划分析和优化建议
        """
        sql = request.json.get("sql")
        params = request.json.get("params")
        conn_name = request.json.get("conn_name", "default")
        
        result = await analyze_query_plan(sql, params, conn_name)
        
        return response(data=result)


class ConnectionPoolResource(BaseResource):
    """数据库连接池资源"""
    
    @requires_permission("system:database:connectionpool")
    async def get(self, request):
        """
        获取数据库连接池状态
        
        返回当前数据库连接池的状态和统计信息
        """
        pool_info = await get_connection_pool()
        return response(data=pool_info)
    
    @requires_permission("system:database:connectionpool:manage")
    @validate_request(json={
        "min_size": {"type": "integer", "min": 1, "max": 100, "nullable": True},
        "max_size": {"type": "integer", "min": 1, "max": 500, "nullable": True},
        "max_idle_time": {"type": "integer", "min": 1, "nullable": True},
        "connection_timeout": {"type": "integer", "min": 1, "nullable": True},
        "log_queries": {"type": "boolean", "nullable": True},
        "retry_limit": {"type": "integer", "min": 0, "max": 10, "nullable": True},
        "retry_interval": {"type": "integer", "min": 100, "max": 10000, "nullable": True}
    })
    async def put(self, request):
        """
        更新数据库连接池配置
        
        更新数据库连接池的配置参数，如连接数、超时和重试策略
        """
        pool_options = {}
        
        # 提取所有非None的选项
        for key in ["min_size", "max_size", "max_idle_time", "connection_timeout", 
                   "log_queries", "retry_limit", "retry_interval"]:
            if key in request.json and request.json[key] is not None:
                pool_options[key] = request.json[key]
        
        # 更新连接池配置
        set_pool_options(**pool_options)
        await apply_pool_options()
        
        pool_info = await get_connection_pool()
        return response(data=pool_info, message="连接池配置已更新")


class DatabaseAnalysisResource(BaseResource):
    """数据库性能分析资源"""
    
    @requires_permission("system:database:query")
    async def get(self, request):
        """
        获取数据库性能分析概览
        
        返回数据库查询性能、慢查询和连接池状态的综合分析
        """
        # 获取最近的慢查询
        slow_queries = await get_slow_queries(limit=5)
        
        # 获取查询统计
        logs_data = await get_query_logs(limit=1)
        query_stats = logs_data["stats"]
        type_stats = logs_data["type_stats"]
        
        # 获取连接池信息
        pool_info = await get_connection_pool()
        
        # 组合数据
        summary = {
            "query_stats": query_stats,
            "type_stats": type_stats,
            "recent_slow_queries": slow_queries,
            "connection_pool": pool_info
        }
        
        return response(data=summary)


# 注册路由
bp.add_route(QueryLogsResource.as_view(), "/query-logs")
bp.add_route(SlowQueriesResource.as_view(), "/slow-queries")
bp.add_route(QueryPlanResource.as_view(), "/query-plan")
bp.add_route(ConnectionPoolResource.as_view(), "/connection-pool")
bp.add_route(DatabaseAnalysisResource.as_view(), "/analysis") 