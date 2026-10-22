#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
仪表盘API资源模块，提供系统概览和数据统计功能
"""

from sanic.request import Request
from sanic.views import HTTPMethodView
from app.api import APIResponse, v1_bp
from app.api.resources.route_methods import register_view
from app.models import Account, Role, OperationLog, UploadedFile
from app.auth.authorization import requires_permission
from app.cache.decorators import cached
from typing import Dict, Any
from tortoise.functions import Count, Sum
from datetime import timedelta
from app.services.utils import utcnow
import platform
import psutil


async def _sum_bytes(query) -> int:
    """UploadedFile.file_size 以 KB 存储，这里汇总并换算为字节。"""
    rows = await query.annotate(size_sum=Sum("file_size")).values("size_sum")
    total_kb = rows[0]["size_sum"] if rows and rows[0]["size_sum"] else 0
    return int(total_kb * 1024)


class DashboardSummaryResource(HTTPMethodView):
    """
    仪表盘概览资源
    
    提供系统关键指标和概览数据
    """
    
    @requires_permission("dashboard:read")  # 鉴权必须在缓存之外，缓存命中也要先检查权限
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
        # 获取用户统计
        total_accounts = await Account.filter(deleted=False).count()
        active_accounts = await Account.filter(verified=True, disabled=False, deleted=False).count()
        admin_accounts = await Account.filter(is_admin=True).count()
        
        # 获取角色统计
        total_roles = await Role.all().count()
        
        # 获取最近注册趋势
        now = utcnow()
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
        total_files = await UploadedFile.filter(deleted=False).count()
        total_storage_bytes = await _sum_bytes(UploadedFile.filter(deleted=False))
        
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
    
    @requires_permission("dashboard:read")
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
        # 获取时间范围参数
        days = int(request.args.get('days', '7'))
        if days <= 0:
            days = 7
        
        # 计算时间范围
        now = utcnow()
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
    
    @requires_permission("dashboard:read")
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
        # 获取文件总数和总大小
        total_files = await UploadedFile.filter(deleted=False).count()
        total_size = await _sum_bytes(UploadedFile.filter(deleted=False))
        
        # 按文件类型分类统计
        file_types = await UploadedFile.filter(deleted=False).group_by("file_type").annotate(
            count=Count("id"),
            total_size=Sum("file_size")
        ).values("file_type", "count", "total_size")
        
        # 获取最近上传的文件
        recent_files = await UploadedFile.filter(deleted=False).order_by('-created_at').limit(10)
        
        # 计算存储增长趋势
        now = utcnow()
        last_month = now - timedelta(days=30)
        
        # 按周统计最近一个月的文件增长
        storage_trend = []
        for i in range(5):  # 分为5个时间段
            period_start = last_month + timedelta(days=i*6)
            period_end = period_start + timedelta(days=6)
            period_query = UploadedFile.filter(
                deleted=False,
                created_at__gte=period_start,
                created_at__lt=period_end
            )
            files_count = await period_query.count()
            period_size = await _sum_bytes(period_query)
            
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
    
    def _format_file(self, file: UploadedFile) -> Dict[str, Any]:
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
            "size_bytes": int(file.file_size * 1024),
            "size_formatted": self._format_size(int(file.file_size * 1024)),
            "uploader_id": file.account_id,
            "downloads": file.download_count,
            "created_at": file.created_at
        }


# 注册路由
dashboard_summary = DashboardSummaryResource()
dashboard_activities = DashboardActivitiesResource()
dashboard_storage = DashboardStorageResource()

register_view(v1_bp, "/dashboard/summary", dashboard_summary, ["GET"], "dashboard_summary")
register_view(v1_bp, "/dashboard/activities", dashboard_activities, ["GET"], "dashboard_activities")
register_view(v1_bp, "/dashboard/storage", dashboard_storage, ["GET"], "dashboard_storage")