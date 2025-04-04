#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
仪表盘系统性能监控API资源模块，提供性能指标收集和异常统计
"""

from sanic.request import Request
from sanic.views import HTTPMethodView
from app.api import APIResponse, v1_bp, APIError
from app.models import OperationLog
from app.auth.authorization import check_permissions
from typing import Dict, Any, List, Optional, Tuple
from tortoise.functions import Count, Avg, Min, Max
from datetime import datetime, timedelta
import time
import psutil
import os
import platform
import json


class PerformanceResource(HTTPMethodView):
    """
    性能指标资源
    
    提供系统和API性能数据
    """
    
    async def get(self, request: Request):
        """
        获取性能指标数据
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应，包含性能指标数据
        """
        @check_permissions("dashboard", "read")
        async def get_performance(request):
            # 获取当前系统性能数据
            system_performance = self._get_system_performance()
            
            # 获取API响应时间统计
            api_performance = await self._get_api_performance()
            
            # 获取数据库查询性能
            db_performance = await self._get_db_performance()
            
            # 返回性能指标数据
            return APIResponse.success(data={
                "system": system_performance,
                "api": api_performance,
                "database": db_performance
            }, message="获取性能指标数据成功")
        
        return await get_performance(request)
    
    def _get_system_performance(self) -> Dict[str, Any]:
        """
        获取系统性能数据
        
        Returns:
            Dict[str, Any]: 系统性能数据
        """
        # CPU 使用率
        cpu_percent = psutil.cpu_percent(interval=0.5)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        
        # 内存使用情况
        memory = psutil.virtual_memory()
        
        # 磁盘使用情况
        disk = psutil.disk_usage('/')
        
        # 网络使用情况
        net_io_counters = psutil.net_io_counters()
        
        # 系统负载
        try:
            load_avg = os.getloadavg()  # 仅在类Unix系统可用
        except:
            load_avg = (0, 0, 0)
        
        # 进程信息
        current_process = psutil.Process()
        process_info = {
            "cpu_percent": current_process.cpu_percent(interval=0.1),
            "memory_percent": current_process.memory_percent(),
            "threads": current_process.num_threads(),
            "connections": len(current_process.connections()),
            "uptime": time.time() - current_process.create_time()
        }
        
        return {
            "timestamp": datetime.now().isoformat(),
            "platform": platform.platform(),
            "cpu": {
                "percent": cpu_percent,
                "count": cpu_count,
                "frequency_mhz": cpu_freq.current if cpu_freq else None,
                "per_cpu": psutil.cpu_percent(interval=0.1, percpu=True)
            },
            "memory": {
                "total": memory.total,
                "available": memory.available,
                "used": memory.used,
                "percent": memory.percent
            },
            "disk": {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": disk.percent
            },
            "network": {
                "bytes_sent": net_io_counters.bytes_sent,
                "bytes_recv": net_io_counters.bytes_recv,
                "packets_sent": net_io_counters.packets_sent,
                "packets_recv": net_io_counters.packets_recv,
                "errin": net_io_counters.errin,
                "errout": net_io_counters.errout
            },
            "load": {
                "1min": load_avg[0],
                "5min": load_avg[1],
                "15min": load_avg[2]
            },
            "process": process_info
        }
    
    async def _get_api_performance(self) -> Dict[str, Any]:
        """
        获取API响应时间统计
        
        Returns:
            Dict[str, Any]: API性能数据
        """
        # 获取操作日志中记录的响应时间数据
        now = datetime.now()
        start_date = now - timedelta(days=7)
        
        # 按资源类型统计平均响应时间
        response_times = []
        
        # 获取所有资源类型
        resource_types = await OperationLog.filter(
            created_at__gte=start_date
        ).distinct().values_list('operation_type', flat=True)
        
        for resource_type in resource_types:
            # 尝试从日志的detail字段中提取响应时间
            logs = await OperationLog.filter(
                operation_type=resource_type,
                created_at__gte=start_date
            ).all()
            
            times = []
            for log in logs:
                try:
                    # 假设detail字段中可能包含JSON格式的响应时间信息
                    if log.detail:
                        detail = json.loads(log.detail) if isinstance(log.detail, str) else log.detail
                        if isinstance(detail, dict) and 'response_time' in detail:
                            times.append(float(detail['response_time']))
                except:
                    # 忽略解析错误
                    pass
            
            if times:
                avg_time = sum(times) / len(times)
                min_time = min(times)
                max_time = max(times)
                
                response_times.append({
                    "resource_type": resource_type,
                    "avg_time": avg_time,
                    "min_time": min_time,
                    "max_time": max_time,
                    "sample_count": len(times)
                })
        
        # 计算整体API响应时间趋势
        daily_avg_times = []
        for i in range(7):  # 最近7天
            day_start = now - timedelta(days=i+1)
            day_end = now - timedelta(days=i)
            
            logs = await OperationLog.filter(
                created_at__gte=day_start,
                created_at__lt=day_end
            ).all()
            
            times = []
            for log in logs:
                try:
                    if log.detail:
                        detail = json.loads(log.detail) if isinstance(log.detail, str) else log.detail
                        if isinstance(detail, dict) and 'response_time' in detail:
                            times.append(float(detail['response_time']))
                except:
                    pass
            
            if times:
                avg_time = sum(times) / len(times)
            else:
                avg_time = 0
            
            daily_avg_times.append({
                "date": day_start.strftime("%Y-%m-%d"),
                "avg_time": avg_time,
                "request_count": len(times)
            })
        
        # 翻转列表使日期按正序排列
        daily_avg_times.reverse()
        
        # 计算速度最慢的端点
        slowest_endpoints = []
        
        # 获取所有操作
        operations = await OperationLog.filter(
            created_at__gte=start_date
        ).distinct().values_list('operation_type', 'operation')
        
        endpoint_times = {}
        for resource_type, operation in operations:
            logs = await OperationLog.filter(
                operation_type=resource_type,
                operation=operation,
                created_at__gte=start_date
            ).all()
            
            times = []
            for log in logs:
                try:
                    if log.detail:
                        detail = json.loads(log.detail) if isinstance(log.detail, str) else log.detail
                        if isinstance(detail, dict) and 'response_time' in detail:
                            times.append(float(detail['response_time']))
                except:
                    pass
            
            if times:
                avg_time = sum(times) / len(times)
                endpoint_key = f"{resource_type}.{operation}"
                endpoint_times[endpoint_key] = {
                    "resource_type": resource_type,
                    "operation": operation,
                    "avg_time": avg_time,
                    "request_count": len(times)
                }
        
        # 按平均响应时间排序，获取最慢的10个端点
        slowest_endpoints = sorted(
            endpoint_times.values(),
            key=lambda x: x["avg_time"],
            reverse=True
        )[:10]
        
        return {
            "resource_response_times": response_times,
            "daily_avg_times": daily_avg_times,
            "slowest_endpoints": slowest_endpoints
        }
    
    async def _get_db_performance(self) -> Dict[str, Any]:
        """
        获取数据库查询性能数据
        
        Returns:
            Dict[str, Any]: 数据库性能数据
        """
        # 假设在日志中存储了数据库查询时间
        now = datetime.now()
        start_date = now - timedelta(days=7)
        
        # 尝试从日志的detail字段中提取数据库查询时间
        logs = await OperationLog.filter(
            created_at__gte=start_date
        ).all()
        
        db_times = []
        for log in logs:
            try:
                if log.detail:
                    detail = json.loads(log.detail) if isinstance(log.detail, str) else log.detail
                    if isinstance(detail, dict) and 'db_query_time' in detail:
                        db_times.append({
                            "timestamp": log.created_at,
                            "query_time": float(detail['db_query_time']),
                            "resource_type": log.operation_type,
                            "operation": log.operation
                        })
            except:
                # 忽略解析错误
                pass
        
        # 计算平均查询时间
        avg_query_time = sum(item["query_time"] for item in db_times) / len(db_times) if db_times else 0
        
        # 按资源类型统计平均查询时间
        resource_db_times = {}
        for item in db_times:
            resource_type = item["resource_type"]
            if resource_type not in resource_db_times:
                resource_db_times[resource_type] = {
                    "total_time": 0,
                    "count": 0
                }
            
            resource_db_times[resource_type]["total_time"] += item["query_time"]
            resource_db_times[resource_type]["count"] += 1
        
        # 计算每个资源类型的平均查询时间
        for resource_type in resource_db_times:
            if resource_db_times[resource_type]["count"] > 0:
                resource_db_times[resource_type]["avg_time"] = (
                    resource_db_times[resource_type]["total_time"] / 
                    resource_db_times[resource_type]["count"]
                )
            else:
                resource_db_times[resource_type]["avg_time"] = 0
        
        # 查找最慢的查询
        slowest_queries = sorted(db_times, key=lambda x: x["query_time"], reverse=True)[:10]
        
        return {
            "avg_query_time": avg_query_time,
            "resource_query_times": [
                {
                    "resource_type": resource_type,
                    "avg_time": data["avg_time"],
                    "query_count": data["count"]
                }
                for resource_type, data in resource_db_times.items()
            ],
            "slowest_queries": [
                {
                    "resource_type": item["resource_type"],
                    "operation": item["operation"],
                    "query_time": item["query_time"],
                    "timestamp": item["timestamp"]
                }
                for item in slowest_queries
            ],
            "total_queries": len(db_times)
        }


class ExceptionsResource(HTTPMethodView):
    """
    异常情况统计资源
    
    提供系统错误和异常统计
    """
    
    async def get(self, request: Request):
        """
        获取异常统计数据
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应，包含异常统计数据
        """
        @check_permissions("dashboard", "read")
        async def get_exceptions(request):
            # 获取时间范围参数
            days = int(request.args.get('days', '30'))
            if days <= 0:
                days = 30
            
            # 计算时间范围
            now = datetime.now()
            start_date = now - timedelta(days=days)
            
            # 获取所有失败的操作日志
            error_logs = await OperationLog.filter(
                status__not="success",
                created_at__gte=start_date
            ).all()
            
            # 按错误类型统计
            error_types = {}
            for log in error_logs:
                error_type = log.detail.get('error_type', 'unknown') if isinstance(log.detail, dict) else 'unknown'
                
                if error_type not in error_types:
                    error_types[error_type] = 0
                
                error_types[error_type] += 1
            
            # 按资源类型和操作统计错误
            resource_errors = {}
            for log in error_logs:
                resource_type = log.operation_type
                operation = log.operation
                
                if resource_type not in resource_errors:
                    resource_errors[resource_type] = {
                        "total": 0,
                        "operations": {}
                    }
                
                resource_errors[resource_type]["total"] += 1
                
                op_key = operation
                if op_key not in resource_errors[resource_type]["operations"]:
                    resource_errors[resource_type]["operations"][op_key] = 0
                
                resource_errors[resource_type]["operations"][op_key] += 1
            
            # 统计每天的错误数量
            daily_error_counts = []
            for i in range(min(30, days)):
                day_start = now - timedelta(days=i+1)
                day_end = now - timedelta(days=i)
                
                error_count = await OperationLog.filter(
                    status__not="success",
                    created_at__gte=day_start,
                    created_at__lt=day_end
                ).count()
                
                # 同时统计总请求数以计算错误率
                total_count = await OperationLog.filter(
                    created_at__gte=day_start,
                    created_at__lt=day_end
                ).count()
                
                error_rate = error_count / total_count if total_count > 0 else 0
                
                daily_error_counts.append({
                    "date": day_start.strftime("%Y-%m-%d"),
                    "error_count": error_count,
                    "total_count": total_count,
                    "error_rate": error_rate
                })
            
            # 翻转列表使日期按正序排列
            daily_error_counts.reverse()
            
            # 获取最近的错误日志
            recent_errors = []
            for log in sorted(error_logs, key=lambda x: x.created_at, reverse=True)[:10]:
                error_detail = log.detail if isinstance(log.detail, dict) else {}
                recent_errors.append({
                    "id": log.id,
                    "timestamp": log.created_at,
                    "resource_type": log.operation_type,
                    "operation": log.operation,
                    "account_name": log.account_name,
                    "error_type": error_detail.get('error_type', 'unknown'),
                    "error_message": error_detail.get('error_message', '')
                })
            
            # 返回异常统计数据
            return APIResponse.success(data={
                "total_errors": len(error_logs),
                "error_types": error_types,
                "resource_errors": resource_errors,
                "daily_error_counts": daily_error_counts,
                "recent_errors": recent_errors
            }, message="获取异常统计数据成功")
        
        return await get_exceptions(request)


class AlertsResource(HTTPMethodView):
    """
    资源使用预警资源
    
    提供系统资源使用阈值检测和优化建议
    """
    
    # 设置资源使用预警阈值
    CPU_WARNING_THRESHOLD = 80  # CPU使用率超过80%报警
    MEMORY_WARNING_THRESHOLD = 85  # 内存使用率超过85%报警
    DISK_WARNING_THRESHOLD = 90  # 磁盘使用率超过90%报警
    ERROR_RATE_WARNING_THRESHOLD = 0.05  # 错误率超过5%报警
    RESPONSE_TIME_WARNING_THRESHOLD = 1.0  # 平均响应时间超过1秒报警
    
    async def get(self, request: Request):
        """
        获取资源使用预警数据
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应，包含资源使用预警数据
        """
        @check_permissions("dashboard", "read")
        async def get_alerts(request):
            # 检测系统资源使用情况
            system_alerts = self._check_system_resources()
            
            # 检测API性能问题
            api_alerts = await self._check_api_performance()
            
            # 检测错误率
            error_alerts = await self._check_error_rates()
            
            # 生成优化建议
            optimization_suggestions = self._generate_optimization_suggestions(
                system_alerts, api_alerts, error_alerts
            )
            
            # 合并所有警报
            all_alerts = system_alerts + api_alerts + error_alerts
            
            # 按严重程度排序
            sorted_alerts = sorted(all_alerts, key=lambda x: x["severity"], reverse=True)
            
            # 返回预警数据
            return APIResponse.success(data={
                "alerts": sorted_alerts,
                "alert_count": len(sorted_alerts),
                "critical_count": sum(1 for alert in sorted_alerts if alert["severity"] == "critical"),
                "warning_count": sum(1 for alert in sorted_alerts if alert["severity"] == "warning"),
                "info_count": sum(1 for alert in sorted_alerts if alert["severity"] == "info"),
                "optimization_suggestions": optimization_suggestions
            }, message="获取资源使用预警数据成功")
        
        return await get_alerts(request)
    
    def _check_system_resources(self) -> List[Dict[str, Any]]:
        """
        检测系统资源使用情况
        
        Returns:
            List[Dict[str, Any]]: 系统资源警报列表
        """
        alerts = []
        
        # 检测CPU使用率
        cpu_percent = psutil.cpu_percent(interval=0.5)
        if cpu_percent > self.CPU_WARNING_THRESHOLD:
            alerts.append({
                "type": "system",
                "resource": "cpu",
                "severity": "critical" if cpu_percent > 90 else "warning",
                "message": f"CPU使用率过高: {cpu_percent}%",
                "current_value": cpu_percent,
                "threshold": self.CPU_WARNING_THRESHOLD,
                "timestamp": datetime.now().isoformat()
            })
        
        # 检测内存使用率
        memory = psutil.virtual_memory()
        if memory.percent > self.MEMORY_WARNING_THRESHOLD:
            alerts.append({
                "type": "system",
                "resource": "memory",
                "severity": "critical" if memory.percent > 95 else "warning",
                "message": f"内存使用率过高: {memory.percent}%",
                "current_value": memory.percent,
                "threshold": self.MEMORY_WARNING_THRESHOLD,
                "timestamp": datetime.now().isoformat()
            })
        
        # 检测磁盘使用率
        disk = psutil.disk_usage('/')
        if disk.percent > self.DISK_WARNING_THRESHOLD:
            alerts.append({
                "type": "system",
                "resource": "disk",
                "severity": "critical" if disk.percent > 95 else "warning",
                "message": f"磁盘空间不足: {disk.percent}%",
                "current_value": disk.percent,
                "threshold": self.DISK_WARNING_THRESHOLD,
                "timestamp": datetime.now().isoformat()
            })
        
        # 检测系统负载
        try:
            load_avg = os.getloadavg()[0]  # 1分钟平均负载
            cpu_count = psutil.cpu_count()
            
            # 负载超过CPU核心数的80%警告
            load_threshold = cpu_count * 0.8
            if load_avg > load_threshold:
                alerts.append({
                    "type": "system",
                    "resource": "load",
                    "severity": "critical" if load_avg > cpu_count else "warning",
                    "message": f"系统负载过高: {load_avg} (CPU核心数: {cpu_count})",
                    "current_value": load_avg,
                    "threshold": load_threshold,
                    "timestamp": datetime.now().isoformat()
                })
        except:
            # 在不支持的平台上忽略
            pass
        
        return alerts
    
    async def _check_api_performance(self) -> List[Dict[str, Any]]:
        """
        检测API性能问题
        
        Returns:
            List[Dict[str, Any]]: API性能警报列表
        """
        alerts = []
        
        # 获取最近的API响应时间数据
        now = datetime.now()
        start_date = now - timedelta(days=1)  # 只检查最近一天的数据
        
        # 获取操作日志
        logs = await OperationLog.filter(
            created_at__gte=start_date
        ).all()
        
        # 按资源类型和操作分组
        endpoint_times = {}
        for log in logs:
            try:
                if log.detail:
                    detail = json.loads(log.detail) if isinstance(log.detail, str) else log.detail
                    if isinstance(detail, dict) and 'response_time' in detail:
                        response_time = float(detail['response_time'])
                        
                        endpoint_key = f"{log.operation_type}.{log.operation}"
                        if endpoint_key not in endpoint_times:
                            endpoint_times[endpoint_key] = {
                                "times": [],
                                "resource_type": log.operation_type,
                                "operation": log.operation
                            }
                        
                        endpoint_times[endpoint_key]["times"].append(response_time)
            except:
                # 忽略解析错误
                pass
        
        # 检查每个端点的平均响应时间
        for endpoint_key, data in endpoint_times.items():
            times = data["times"]
            if times:
                avg_time = sum(times) / len(times)
                
                if avg_time > self.RESPONSE_TIME_WARNING_THRESHOLD:
                    alerts.append({
                        "type": "api",
                        "resource": endpoint_key,
                        "severity": "critical" if avg_time > 2.0 else "warning",
                        "message": f"API端点响应时间过长: {endpoint_key}, 平均: {avg_time:.2f}秒",
                        "current_value": avg_time,
                        "threshold": self.RESPONSE_TIME_WARNING_THRESHOLD,
                        "timestamp": datetime.now().isoformat(),
                        "details": {
                            "resource_type": data["resource_type"],
                            "operation": data["operation"],
                            "sample_count": len(times)
                        }
                    })
        
        return alerts
    
    async def _check_error_rates(self) -> List[Dict[str, Any]]:
        """
        检测错误率
        
        Returns:
            List[Dict[str, Any]]: 错误率警报列表
        """
        alerts = []
        
        # 获取最近的错误率数据
        now = datetime.now()
        start_date = now - timedelta(days=1)  # 只检查最近一天的数据
        
        # 获取总请求数
        total_count = await OperationLog.filter(
            created_at__gte=start_date
        ).count()
        
        if total_count == 0:
            return alerts
        
        # 获取错误请求数
        error_count = await OperationLog.filter(
            status__not="success",
            created_at__gte=start_date
        ).count()
        
        # 计算总体错误率
        error_rate = error_count / total_count
        
        if error_rate > self.ERROR_RATE_WARNING_THRESHOLD:
            alerts.append({
                "type": "error",
                "resource": "global",
                "severity": "critical" if error_rate > 0.1 else "warning",
                "message": f"系统总体错误率过高: {error_rate:.2%}",
                "current_value": error_rate,
                "threshold": self.ERROR_RATE_WARNING_THRESHOLD,
                "timestamp": datetime.now().isoformat(),
                "details": {
                    "error_count": error_count,
                    "total_count": total_count
                }
            })
        
        # 按资源类型检查错误率
        resource_types = await OperationLog.filter(
            created_at__gte=start_date
        ).distinct().values_list('operation_type', flat=True)
        
        for resource_type in resource_types:
            # 获取该资源类型的总请求数
            resource_total_count = await OperationLog.filter(
                operation_type=resource_type,
                created_at__gte=start_date
            ).count()
            
            # 获取该资源类型的错误请求数
            resource_error_count = await OperationLog.filter(
                operation_type=resource_type,
                status__not="success",
                created_at__gte=start_date
            ).count()
            
            # 计算该资源类型的错误率
            resource_error_rate = resource_error_count / resource_total_count if resource_total_count > 0 else 0
            
            if resource_error_rate > self.ERROR_RATE_WARNING_THRESHOLD:
                alerts.append({
                    "type": "error",
                    "resource": resource_type,
                    "severity": "critical" if resource_error_rate > 0.1 else "warning",
                    "message": f"资源 {resource_type} 错误率过高: {resource_error_rate:.2%}",
                    "current_value": resource_error_rate,
                    "threshold": self.ERROR_RATE_WARNING_THRESHOLD,
                    "timestamp": datetime.now().isoformat(),
                    "details": {
                        "error_count": resource_error_count,
                        "total_count": resource_total_count
                    }
                })
        
        return alerts
    
    def _generate_optimization_suggestions(self, system_alerts: List[Dict[str, Any]], 
                                         api_alerts: List[Dict[str, Any]], 
                                         error_alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        生成优化建议
        
        Args:
            system_alerts: 系统资源警报
            api_alerts: API性能警报
            error_alerts: 错误率警报
            
        Returns:
            List[Dict[str, Any]]: 优化建议列表
        """
        suggestions = []
        
        # 检查是否有CPU使用率问题
        cpu_alerts = [alert for alert in system_alerts if alert["resource"] == "cpu"]
        if cpu_alerts:
            suggestions.append({
                "type": "system",
                "resource": "cpu",
                "priority": "high" if any(alert["severity"] == "critical" for alert in cpu_alerts) else "medium",
                "suggestion": "优化CPU密集型操作，考虑增加服务器实例或升级CPU",
                "details": [
                    "检查和优化数据库查询",
                    "使用异步处理长时间运行的任务",
                    "实现请求节流和缓存机制",
                    "考虑水平扩展应用服务器"
                ]
            })
        
        # 检查是否有内存使用率问题
        memory_alerts = [alert for alert in system_alerts if alert["resource"] == "memory"]
        if memory_alerts:
            suggestions.append({
                "type": "system",
                "resource": "memory",
                "priority": "high" if any(alert["severity"] == "critical" for alert in memory_alerts) else "medium",
                "suggestion": "优化内存使用，检查内存泄漏，考虑增加服务器内存",
                "details": [
                    "检查应用程序是否存在内存泄漏",
                    "优化大型对象的生命周期管理",
                    "调整数据库连接池大小",
                    "考虑增加服务器内存或使用分布式缓存"
                ]
            })
        
        # 检查是否有磁盘空间问题
        disk_alerts = [alert for alert in system_alerts if alert["resource"] == "disk"]
        if disk_alerts:
            suggestions.append({
                "type": "system",
                "resource": "disk",
                "priority": "high" if any(alert["severity"] == "critical" for alert in disk_alerts) else "medium",
                "suggestion": "清理磁盘空间，实现日志轮换，考虑增加存储容量",
                "details": [
                    "清理临时文件和旧日志",
                    "实现自动日志轮换和归档",
                    "将文件存储迁移到云存储服务",
                    "考虑增加磁盘容量或挂载额外存储卷"
                ]
            })
        
        # 检查是否有API性能问题
        if api_alerts:
            suggestions.append({
                "type": "api",
                "resource": "performance",
                "priority": "high" if any(alert["severity"] == "critical" for alert in api_alerts) else "medium",
                "suggestion": "优化慢速API端点，实现缓存和异步处理",
                "details": [
                    "检查并优化数据库查询",
                    "为频繁访问的数据实现缓存",
                    "使用异步处理长时间运行的操作",
                    "考虑实现API结果分页"
                ]
            })
        
        # 检查是否有错误率问题
        if error_alerts:
            suggestions.append({
                "type": "error",
                "resource": "reliability",
                "priority": "high" if any(alert["severity"] == "critical" for alert in error_alerts) else "medium",
                "suggestion": "解决导致高错误率的问题，完善错误处理和重试机制",
                "details": [
                    "分析错误日志，修复常见故障",
                    "实现请求验证和参数检查",
                    "添加适当的错误处理和重试逻辑",
                    "考虑实现熔断机制防止故障级联"
                ]
            })
        
        # 如果没有任何警报，提供一般性能优化建议
        if not system_alerts and not api_alerts and not error_alerts:
            suggestions.append({
                "type": "general",
                "resource": "performance",
                "priority": "low",
                "suggestion": "实施一般性能优化措施",
                "details": [
                    "实现应用级缓存以提高响应时间",
                    "优化数据库索引和查询",
                    "压缩API响应以减少网络流量",
                    "实现资源池化和连接复用"
                ]
            })
        
        return suggestions


# 注册路由
performance_resource = PerformanceResource()
exceptions_resource = ExceptionsResource()
alerts_resource = AlertsResource()

v1_bp.add_route(performance_resource.get, "/dashboard/performance", methods=["GET"])
v1_bp.add_route(exceptions_resource.get, "/dashboard/exceptions", methods=["GET"])
v1_bp.add_route(alerts_resource.get, "/dashboard/alerts", methods=["GET"]) 