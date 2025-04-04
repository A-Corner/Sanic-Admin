#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
日志API资源模块，提供系统操作日志查询功能
"""

from sanic.request import Request
from app.api import CRUDResource, APIResponse, v1_bp
from app.models import OperationLog
from app.api.validators import (
    validate_request,
    validate_path_param,
    Required,
    Length,
    Type,
    OneOf,
    Optional
)
from app.auth.authorization import check_permissions, check_roles
from typing import Dict, Any, List
from datetime import datetime
from tortoise.functions import Count


class LogResource(CRUDResource):
    """
    日志资源
    
    提供系统操作日志的查询功能
    """
    model_class = OperationLog
    resource_name = "系统日志"
    
    # 默认排序和分页
    default_sort_field = "created_at"
    default_sort_direction = "desc"
    default_page_size = 20
    
    # 搜索和过滤字段
    searchable_fields = ["operation", "detail", "ip_address", "user_agent"]
    filterable_fields = ["operation_type", "status", "account_id"]
    
    @classmethod
    def format_model(cls, model: OperationLog) -> Dict[str, Any]:
        """
        格式化日志模型为字典
        
        Args:
            model: 日志模型实例
            
        Returns:
            Dict[str, Any]: 格式化的字典
        """
        return {
            "id": model.id,
            "account_id": model.account_id,
            "account_name": model.account_name,
            "operation": model.operation,
            "operation_type": model.operation_type,
            "detail": model.detail,
            "status": model.status,
            "ip_address": model.ip_address,
            "user_agent": model.user_agent,
            "created_at": model.created_at
        }
    
    async def get(self, request: Request, log_id: str = None):
        """
        获取日志或日志列表
        
        Args:
            request: Sanic请求对象
            log_id: 日志ID，如果不提供则获取列表
            
        Returns:
            Response: Sanic响应
        """
        # 使用权限检查装饰器
        @check_permissions("log", "read")
        async def get_log(request, log_id=None):
            return await super(LogResource, self).get(request, log_id)
            
        return await get_log(request, log_id)


class LogStatisticsResource:
    """
    日志统计资源
    
    提供日志数据统计功能
    """
    
    async def get(self, request: Request):
        """
        获取日志统计数据
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应
        """
        @check_permissions("log", "read")
        async def get_statistics(request):
            # 解析查询参数
            start_date = request.args.get('start_date')
            end_date = request.args.get('end_date')
            group_by = request.args.get('group_by', 'day')  # day, week, month
            
            # 验证日期格式
            try:
                if start_date:
                    start_date = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                if end_date:
                    end_date = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            except ValueError:
                return APIResponse.error(
                    message="日期格式无效，请使用ISO格式 (YYYY-MM-DDTHH:MM:SS)",
                    error_code="INVALID_DATE_FORMAT",
                    status_code=400
                )
            
            # 构建查询条件
            query = OperationLog.all()
            if start_date:
                query = query.filter(created_at__gte=start_date)
            if end_date:
                query = query.filter(created_at__lte=end_date)
            
            # 获取基本统计数据
            total_count = await query.count()
            
            # 按操作类型统计
            operation_type_stats = await query.group_by("operation_type").annotate(
                count=Count("id")
            ).values("operation_type", "count")
            
            # 按状态统计
            status_stats = await query.group_by("status").annotate(
                count=Count("id")
            ).values("status", "count")
            
            # 按账户统计（前10个）
            account_stats = await query.group_by("account_id", "account_name").annotate(
                count=Count("id")
            ).values("account_id", "account_name", "count").limit(10)
            
            # 构建统计结果
            statistics = {
                "total_count": total_count,
                "by_operation_type": {stat["operation_type"]: stat["count"] for stat in operation_type_stats},
                "by_status": {stat["status"]: stat["count"] for stat in status_stats},
                "by_account": [
                    {"account_id": stat["account_id"], "account_name": stat["account_name"], "count": stat["count"]}
                    for stat in account_stats
                ]
            }
            
            return APIResponse.success(
                data=statistics,
                message="获取日志统计数据成功"
            )
            
        return await get_statistics(request)


# 注册路由
log_resource = LogResource()
log_statistics_resource = LogStatisticsResource()

v1_bp.add_route(log_resource.as_view(), "/logs/<log_id:int>", methods=["GET"])
v1_bp.add_route(log_resource.as_view(), "/logs", methods=["GET"])
v1_bp.add_route(log_statistics_resource.get, "/logs/statistics", methods=["GET"]) 