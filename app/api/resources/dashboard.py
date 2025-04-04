#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
仪表盘API资源模块，提供系统概览和数据统计功能
"""

from sanic.request import Request
from sanic.views import HTTPMethodView
from app.api import APIResponse, v1_bp, APIError
from app.models import Account, Role, OperationLog, File, SystemSetting, Profile
from app.auth.authentication import get_authenticated_account
from app.auth.authorization import check_permissions, check_roles
from app.cache.decorators import cached, clear_route_cache
from typing import Dict, Any, List, Optional
from tortoise.functions import Count, Sum
from datetime import datetime, timedelta
import platform
import psutil
import os


class DashboardSummaryResource(HTTPMethodView):
    """
    仪表盘概览资源
    
    提供系统关键指标和概览数据
    """
    
    @cached(timeout=60, key_prefix="dashboard_summary")
    async def get(self, request: Request):
        """
        获取系统概览数据
        
        使用缓存装饰器，缓存60秒
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应，包含系统概览数据
        """
        @check_permissions("dashboard", "read")
        async def get_summary(request):
            # 获取用户统计
            total_accounts = await Account.all().count()
            active_accounts = await Account.filter(is_active=True).count()
            admin_accounts = await Account.filter(is_admin=True).count()
            
            # 获取角色统计
            total_roles = await Role.all().count()
            
            # 获取最近注册趋势
            now = datetime.now()
            last_week = now - timedelta(days=7)
            
            # 按天统计最近一周的注册用户
            registration_trend = []
            for i in range(7):
                day_start = last_week + timedelta(days=i)
                day_end = day_start + timedelta(days=1)
                count = await Account.filter(
                    created_at__gte=day_start,
                    created_at__lt=day_end
                ).count()
                registration_trend.append({
                    "date": day_start.strftime("%Y-%m-%d"),
                    "count": count
                })
            
            # 获取文件统计
            total_files = await File.all().count()
            total_storage = await File.all().annotate(
                size_sum=Sum('size')
            ).values('size_sum')
            total_storage_bytes = total_storage[0]['size_sum'] if total_storage and total_storage[0]['size_sum'] else 0
            
            # 获取系统资源使用情况
            system_stats = {
                "os": platform.platform(),
                "cpu_usage": psutil.cpu_percent(),
                "memory": {
                    "total": psutil.virtual_memory().total,
                    "available": psutil.virtual_memory().available,
                    "percent": psutil.virtual_memory().percent
                },
                "disk": {
                    "total": psutil.disk_usage('/').total,
                    "used": psutil.disk_usage('/').used,
                    "free": psutil.disk_usage('/').free,
                    "percent": psutil.disk_usage('/').percent
                }
            }
            
            # 返回汇总数据
            return APIResponse.success(data={
                "accounts": {
                    "total": total_accounts,
                    "active": active_accounts,
                    "admin": admin_accounts,
                    "registration_trend": registration_trend
                },
                "roles": {
                    "total": total_roles
                },
                "files": {
                    "total": total_files,
                    "storage_bytes": total_storage_bytes,
                    "storage_formatted": self._format_size(total_storage_bytes)
                },
                "system": system_stats
            }, message="获取系统概览数据成功")
        
        return await get_summary(request)
    
    def _format_size(self, size_bytes: int) -> str:
        """
        格式化文件大小
        
        Args:
            size_bytes: 字节大小
            
        Returns:
            str: 格式化的大小字符串
        """
        if size_bytes == 0:
            return "0 B"
        
        size_names = ("B", "KB", "MB", "GB", "TB", "PB")
        i = 0
        while size_bytes >= 1024 and i < len(size_names)-1:
            size_bytes /= 1024
            i += 1
        
        return f"{size_bytes:.2f} {size_names[i]}"


class DashboardActivitiesResource(HTTPMethodView):
    """
    活动日志概览资源
    
    提供系统操作日志统计和分析
    """
    
    @cached(timeout=30, key_prefix="dashboard_activities", include_query=True)
    async def get(self, request: Request):
        """
        获取活动日志概览数据
        
        使用缓存装饰器，缓存30秒，并包含查询参数
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应，包含活动日志概览数据
        """
        @check_permissions("dashboard", "read")
        async def get_activities(request):
            # 获取时间范围参数
            days = int(request.args.get('days', '7'))
            if days <= 0:
                days = 7
            
            # 计算时间范围
            now = datetime.now()
            start_date = now - timedelta(days=days)
            
            # 获取总操作日志数
            total_logs = await OperationLog.filter(
                created_at__gte=start_date
            ).count()
            
            # 按操作类型分类统计
            logs_by_type = await OperationLog.filter(
                created_at__gte=start_date
            ).group_by("operation_type").annotate(
                count=Count("id")
            ).values("operation_type", "count")
            
            # 按状态分类统计
            logs_by_status = await OperationLog.filter(
                created_at__gte=start_date
            ).group_by("status").annotate(
                count=Count("id")
            ).values("status", "count")
            
            # 计算失败率
            failed_count = sum(item["count"] for item in logs_by_status if item["status"] != "success")
            failure_rate = failed_count / total_logs if total_logs > 0 else 0
            
            # 获取最近的操作记录
            recent_logs = await OperationLog.all().order_by('-created_at').limit(10)
            
            # 每日活动趋势
            daily_trend = []
            for i in range(days):
                day_start = start_date + timedelta(days=i)
                day_end = day_start + timedelta(days=1)
                count = await OperationLog.filter(
                    created_at__gte=day_start,
                    created_at__lt=day_end
                ).count()
                daily_trend.append({
                    "date": day_start.strftime("%Y-%m-%d"),
                    "count": count
                })
            
            # 返回活动数据
            return APIResponse.success(data={
                "total_logs": total_logs,
                "by_type": {item["operation_type"]: item["count"] for item in logs_by_type},
                "by_status": {item["status"]: item["count"] for item in logs_by_status},
                "failure_rate": failure_rate,
                "daily_trend": daily_trend,
                "recent_logs": [self._format_log(log) for log in recent_logs]
            }, message="获取活动日志概览数据成功")
        
        return await get_activities(request)
    
    def _format_log(self, log: OperationLog) -> Dict[str, Any]:
        """
        格式化日志数据
        
        Args:
            log: 日志模型实例
            
        Returns:
            Dict[str, Any]: 格式化的日志字典
        """
        return {
            "id": log.id,
            "account_name": log.account_name,
            "operation": log.operation,
            "operation_type": log.operation_type,
            "status": log.status,
            "created_at": log.created_at
        }


class DashboardStorageResource(HTTPMethodView):
    """
    存储统计资源
    
    提供文件存储统计数据
    """
    
    @cached(timeout=120, key_prefix="dashboard_storage")
    async def get(self, request: Request):
        """
        获取存储统计数据
        
        使用缓存装饰器，缓存120秒
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应，包含存储统计数据
        """
        @check_permissions("dashboard", "read")
        async def get_storage_stats(request):
            # 获取文件总数和总大小
            total_files = await File.all().count()
            total_storage = await File.all().annotate(
                size_sum=Sum('size')
            ).values('size_sum')
            total_size = total_storage[0]['size_sum'] if total_storage and total_storage[0]['size_sum'] else 0
            
            # 按文件类型分类统计
            file_types = await File.all().group_by("file_type").annotate(
                count=Count("id"),
                total_size=Sum("size")
            ).values("file_type", "count", "total_size")
            
            # 获取最近上传的文件
            recent_files = await File.all().order_by('-created_at').limit(10)
            
            # 计算存储增长趋势
            now = datetime.now()
            last_month = now - timedelta(days=30)
            
            # 按周统计最近一个月的文件增长
            storage_trend = []
            for i in range(5):  # 分为5个时间段
                period_start = last_month + timedelta(days=i*6)
                period_end = period_start + timedelta(days=6)
                files_count = await File.filter(
                    created_at__gte=period_start,
                    created_at__lt=period_end
                ).count()
                
                files_size = await File.filter(
                    created_at__gte=period_start,
                    created_at__lt=period_end
                ).annotate(size_sum=Sum('size')).values('size_sum')
                
                period_size = files_size[0]['size_sum'] if files_size and files_size[0]['size_sum'] else 0
                
                storage_trend.append({
                    "period": f"{period_start.strftime('%Y-%m-%d')} to {period_end.strftime('%Y-%m-%d')}",
                    "files_count": files_count,
                    "size_bytes": period_size,
                    "size_formatted": self._format_size(period_size)
                })
            
            # 返回存储统计数据
            return APIResponse.success(data={
                "total_files": total_files,
                "total_size_bytes": total_size,
                "total_size_formatted": self._format_size(total_size),
                "by_type": [
                    {
                        "type": item["file_type"] or "unknown",
                        "count": item["count"],
                        "size_bytes": item["total_size"] or 0,
                        "size_formatted": self._format_size(item["total_size"] or 0)
                    }
                    for item in file_types
                ],
                "recent_files": [self._format_file(file) for file in recent_files],
                "storage_trend": storage_trend
            }, message="获取存储统计数据成功")
        
        return await get_storage_stats(request)
    
    def _format_size(self, size_bytes: int) -> str:
        """
        格式化文件大小
        
        Args:
            size_bytes: 字节大小
            
        Returns:
            str: 格式化的大小字符串
        """
        if size_bytes == 0:
            return "0 B"
        
        size_names = ("B", "KB", "MB", "GB", "TB", "PB")
        i = 0
        while size_bytes >= 1024 and i < len(size_names)-1:
            size_bytes /= 1024
            i += 1
        
        return f"{size_bytes:.2f} {size_names[i]}"
    
    def _format_file(self, file: File) -> Dict[str, Any]:
        """
        格式化文件数据
        
        Args:
            file: 文件模型实例
            
        Returns:
            Dict[str, Any]: 格式化的文件字典
        """
        return {
            "id": file.id,
            "filename": file.filename,
            "file_type": file.file_type,
            "size_bytes": file.size,
            "size_formatted": self._format_size(file.size),
            "uploader": file.uploader_name,
            "downloads": file.download_count,
            "created_at": file.created_at
        }


# 注册路由
dashboard_summary = DashboardSummaryResource()
dashboard_activities = DashboardActivitiesResource()
dashboard_storage = DashboardStorageResource()

v1_bp.add_route(dashboard_summary.get, "/dashboard/summary", methods=["GET"])
v1_bp.add_route(dashboard_activities.get, "/dashboard/activities", methods=["GET"])
v1_bp.add_route(dashboard_storage.get, "/dashboard/storage", methods=["GET"]) 