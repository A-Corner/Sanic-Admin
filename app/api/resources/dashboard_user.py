#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
仪表盘用户行为分析API资源模块，提供用户活跃度和功能使用分析
"""

from sanic.request import Request
from sanic.views import HTTPMethodView
from app.api import APIResponse, v1_bp, APIError
from app.models import Account, Role, OperationLog, File, SystemSetting
from app.auth.authentication import get_authenticated_account
from app.auth.authorization import check_permissions, check_roles
from typing import Dict, Any, List, Optional, Tuple
from tortoise.functions import Count, Sum
from tortoise.expressions import Q
from datetime import datetime, timedelta


class UserActivityResource(HTTPMethodView):
    """
    用户活跃度分析资源
    
    提供用户登录频率和活跃时间段分析
    """
    
    async def get(self, request: Request):
        """
        获取用户活跃度分析数据
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应，包含用户活跃度分析数据
        """
        @check_permissions("dashboard", "read")
        async def get_user_activity(request):
            # 获取时间范围参数
            days = int(request.args.get('days', '30'))
            if days <= 0:
                days = 30
            
            # 计算时间范围
            now = datetime.now()
            start_date = now - timedelta(days=days)
            
            # 获取登录操作日志
            login_logs = await OperationLog.filter(
                operation_type="auth",
                operation="login",
                status="success",
                created_at__gte=start_date
            ).all()
            
            # 按用户ID分组统计登录次数
            login_frequency = {}
            for log in login_logs:
                if log.account_id not in login_frequency:
                    login_frequency[log.account_id] = {
                        "account_id": log.account_id,
                        "account_name": log.account_name,
                        "login_count": 0,
                        "last_login": None
                    }
                
                login_frequency[log.account_id]["login_count"] += 1
                
                # 记录最后登录时间
                if (login_frequency[log.account_id]["last_login"] is None or 
                    log.created_at > login_frequency[log.account_id]["last_login"]):
                    login_frequency[log.account_id]["last_login"] = log.created_at
            
            # 按登录次数排序
            sorted_users = sorted(
                login_frequency.values(), 
                key=lambda x: x["login_count"], 
                reverse=True
            )
            
            # 获取活跃时间段分析
            hour_distribution = await self._get_hour_distribution(login_logs)
            
            # 获取用户留存率
            retention_rates = await self._calculate_retention(days)
            
            # 日活跃用户数趋势
            daily_active_users = []
            for i in range(min(30, days)):  # 最多显示30天
                day_start = now - timedelta(days=i+1)
                day_end = now - timedelta(days=i)
                
                # 获取当天有登录记录的不同用户数
                unique_users = await OperationLog.filter(
                    operation_type="auth",
                    operation="login",
                    status="success",
                    created_at__gte=day_start,
                    created_at__lt=day_end
                ).distinct().values_list('account_id', flat=True)
                
                daily_active_users.append({
                    "date": day_start.strftime("%Y-%m-%d"),
                    "active_users": len(unique_users)
                })
            
            # 翻转列表使日期按正序显示
            daily_active_users.reverse()
            
            # 返回用户活跃度分析数据
            return APIResponse.success(data={
                "most_active_users": sorted_users[:10],  # 取前10个活跃用户
                "hour_distribution": hour_distribution,
                "retention_rates": retention_rates,
                "daily_active_users": daily_active_users,
                "total_login_count": sum(user["login_count"] for user in login_frequency.values()),
                "unique_login_users": len(login_frequency)
            }, message="获取用户活跃度分析数据成功")
        
        return await get_user_activity(request)
    
    async def _get_hour_distribution(self, login_logs: List[OperationLog]) -> List[Dict[str, Any]]:
        """
        计算登录时间的小时分布
        
        Args:
            login_logs: 登录日志列表
            
        Returns:
            List[Dict[str, Any]]: 小时分布数据
        """
        # 初始化24小时的计数器
        hour_counts = {hour: 0 for hour in range(24)}
        
        # 统计每个小时的登录次数
        for log in login_logs:
            hour = log.created_at.hour
            hour_counts[hour] += 1
        
        # 构造返回结果
        return [
            {"hour": hour, "count": count}
            for hour, count in hour_counts.items()
        ]
    
    async def _calculate_retention(self, days: int) -> Dict[str, Any]:
        """
        计算用户留存率
        
        Args:
            days: 天数范围
            
        Returns:
            Dict[str, Any]: 留存率数据
        """
        now = datetime.now()
        retention_data = {}
        
        # 计算1天、7天、14天、30天留存率
        retention_periods = [1, 7, 14, 30]
        for period in retention_periods:
            if period > days:
                continue
                
            # 获取指定时间前注册的用户
            period_date = now - timedelta(days=period)
            registered_before = await Account.filter(
                created_at__lt=period_date
            ).count()
            
            if registered_before == 0:
                retention_data[f"{period}_day"] = 0
                continue
            
            # 获取这些用户中在之后有活动的用户数
            active_after = await OperationLog.filter(
                created_at__gte=period_date
            ).distinct().values_list('account_id', flat=True)
            
            # 去重并过滤出注册时间早于period_date的用户
            active_user_ids = set(active_after)
            active_old_users = await Account.filter(
                id__in=active_user_ids,
                created_at__lt=period_date
            ).count()
            
            # 计算留存率
            retention_rate = active_old_users / registered_before if registered_before > 0 else 0
            retention_data[f"{period}_day"] = retention_rate
        
        return retention_data


class FeatureUsageResource(HTTPMethodView):
    """
    功能使用情况分析资源
    
    提供API资源使用频率和趋势分析
    """
    
    async def get(self, request: Request):
        """
        获取功能使用情况分析数据
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应，包含功能使用情况分析数据
        """
        @check_permissions("dashboard", "read")
        async def get_feature_usage(request):
            # 获取时间范围参数
            days = int(request.args.get('days', '30'))
            if days <= 0:
                days = 30
            
            # 计算时间范围
            now = datetime.now()
            start_date = now - timedelta(days=days)
            
            # 按资源类型和操作统计API调用
            api_usage = await OperationLog.filter(
                created_at__gte=start_date
            ).group_by("operation_type", "operation").annotate(
                count=Count("id")
            ).values("operation_type", "operation", "count")
            
            # 整理数据格式
            feature_usage = {}
            for item in api_usage:
                resource_type = item["operation_type"]
                operation = item["operation"]
                count = item["count"]
                
                if resource_type not in feature_usage:
                    feature_usage[resource_type] = {"total": 0, "operations": {}}
                
                feature_usage[resource_type]["total"] += count
                feature_usage[resource_type]["operations"][operation] = count
            
            # 按资源类型统计成功率
            success_rates = await self._calculate_success_rates(start_date)
            
            # 获取功能使用趋势
            usage_trend = await self._get_usage_trend(days)
            
            # 获取最常用和最少用的功能
            all_operations = []
            for resource_type, data in feature_usage.items():
                for operation, count in data["operations"].items():
                    all_operations.append({
                        "resource_type": resource_type,
                        "operation": operation,
                        "count": count
                    })
            
            # 按使用频率排序
            sorted_operations = sorted(all_operations, key=lambda x: x["count"], reverse=True)
            most_used = sorted_operations[:10]  # 最常用的10个功能
            least_used = sorted_operations[-10:] if len(sorted_operations) > 10 else []  # 最少用的10个功能
            
            # 返回功能使用情况分析数据
            return APIResponse.success(data={
                "feature_usage": feature_usage,
                "success_rates": success_rates,
                "usage_trend": usage_trend,
                "most_used": most_used,
                "least_used": least_used
            }, message="获取功能使用情况分析数据成功")
        
        return await get_feature_usage(request)
    
    async def _calculate_success_rates(self, start_date: datetime) -> Dict[str, Any]:
        """
        计算各资源类型的操作成功率
        
        Args:
            start_date: 起始日期
            
        Returns:
            Dict[str, Any]: 成功率数据
        """
        # 按资源类型统计总请求数和成功请求数
        success_rates = {}
        
        # 获取所有资源类型
        resource_types = await OperationLog.filter(
            created_at__gte=start_date
        ).distinct().values_list('operation_type', flat=True)
        
        for resource_type in resource_types:
            # 统计该资源类型的总请求数
            total_count = await OperationLog.filter(
                operation_type=resource_type,
                created_at__gte=start_date
            ).count()
            
            # 统计成功请求数
            success_count = await OperationLog.filter(
                operation_type=resource_type,
                status="success",
                created_at__gte=start_date
            ).count()
            
            # 计算成功率
            success_rate = success_count / total_count if total_count > 0 else 0
            
            success_rates[resource_type] = {
                "total": total_count,
                "success": success_count,
                "rate": success_rate
            }
        
        return success_rates
    
    async def _get_usage_trend(self, days: int) -> List[Dict[str, Any]]:
        """
        获取功能使用趋势数据
        
        Args:
            days: 天数范围
            
        Returns:
            List[Dict[str, Any]]: 趋势数据
        """
        now = datetime.now()
        trend_data = []
        
        # 按天统计API调用次数
        for i in range(min(30, days)):  # 最多显示30天的数据
            day_start = now - timedelta(days=i+1)
            day_end = now - timedelta(days=i)
            
            # 统计当天的API调用总次数
            total_count = await OperationLog.filter(
                created_at__gte=day_start,
                created_at__lt=day_end
            ).count()
            
            # 获取当天最常用的资源类型
            resource_counts = await OperationLog.filter(
                created_at__gte=day_start,
                created_at__lt=day_end
            ).group_by("operation_type").annotate(
                count=Count("id")
            ).values("operation_type", "count")
            
            top_resource = None
            top_count = 0
            
            for item in resource_counts:
                if item["count"] > top_count:
                    top_count = item["count"]
                    top_resource = item["operation_type"]
            
            trend_data.append({
                "date": day_start.strftime("%Y-%m-%d"),
                "total_count": total_count,
                "top_resource": top_resource,
                "top_resource_count": top_count
            })
        
        # 翻转列表使日期按正序排列
        trend_data.reverse()
        
        return trend_data


class PermissionAnalysisResource(HTTPMethodView):
    """
    角色权限分析资源
    
    提供角色分布和权限使用情况分析
    """
    
    async def get(self, request: Request):
        """
        获取角色权限分析数据
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应，包含角色权限分析数据
        """
        @check_permissions("dashboard", "read")
        async def get_permission_analysis(request):
            # 获取所有角色
            roles = await Role.all()
            
            # 统计每个角色的用户数
            role_distribution = []
            for role in roles:
                user_count = await role.accounts.all().count()
                
                # 获取角色权限数据
                permissions = role.permissions
                permission_count = self._count_permissions(permissions)
                
                role_distribution.append({
                    "role_id": role.id,
                    "role_name": role.name,
                    "user_count": user_count,
                    "permission_count": permission_count,
                    "permissions": permissions
                })
            
            # 获取权限使用情况
            permission_usage = await self._analyze_permission_usage()
            
            # 权限冲突和冗余检测
            permission_issues = self._detect_permission_issues(role_distribution)
            
            # 返回角色权限分析数据
            return APIResponse.success(data={
                "role_distribution": role_distribution,
                "permission_usage": permission_usage,
                "permission_issues": permission_issues
            }, message="获取角色权限分析数据成功")
        
        return await get_permission_analysis(request)
    
    def _count_permissions(self, permissions: Dict[str, Any]) -> int:
        """
        统计权限总数
        
        Args:
            permissions: 权限字典
            
        Returns:
            int: 权限总数
        """
        count = 0
        for resource, actions in permissions.items():
            count += len(actions) if isinstance(actions, list) else 1
        
        return count
    
    async def _analyze_permission_usage(self) -> Dict[str, Any]:
        """
        分析权限使用情况
        
        Returns:
            Dict[str, Any]: 权限使用情况数据
        """
        # 获取所有角色
        roles = await Role.all()
        
        # 统计各资源和权限的使用次数
        resource_counts = {}
        permission_counts = {}
        
        for role in roles:
            permissions = role.permissions
            for resource, actions in permissions.items():
                # 更新资源计数
                if resource not in resource_counts:
                    resource_counts[resource] = 0
                resource_counts[resource] += 1
                
                # 更新权限计数
                actions_list = actions if isinstance(actions, list) else [actions]
                for action in actions_list:
                    permission_key = f"{resource}.{action}"
                    if permission_key not in permission_counts:
                        permission_counts[permission_key] = 0
                    permission_counts[permission_key] += 1
        
        # 获取操作日志中的权限验证记录
        permission_logs = await OperationLog.filter(
            operation_type="permission",
            created_at__gte=datetime.now() - timedelta(days=30)
        ).all()
        
        # 统计权限验证成功和失败次数
        permission_checks = {}
        for log in permission_logs:
            # 解析操作中的权限信息
            try:
                parts = log.operation.split(":")
                if len(parts) >= 2:
                    resource = parts[0].strip()
                    action = parts[1].strip()
                    permission_key = f"{resource}.{action}"
                    
                    if permission_key not in permission_checks:
                        permission_checks[permission_key] = {"success": 0, "failure": 0}
                    
                    if log.status == "success":
                        permission_checks[permission_key]["success"] += 1
                    else:
                        permission_checks[permission_key]["failure"] += 1
            except:
                # 忽略无法解析的日志
                pass
        
        return {
            "resource_counts": resource_counts,
            "permission_counts": permission_counts,
            "permission_checks": permission_checks
        }
    
    def _detect_permission_issues(self, role_distribution: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        检测权限冲突和冗余
        
        Args:
            role_distribution: 角色分布数据
            
        Returns:
            List[Dict[str, Any]]: 权限问题列表
        """
        issues = []
        
        # 检测权限冗余
        for i in range(len(role_distribution)):
            for j in range(i+1, len(role_distribution)):
                role1 = role_distribution[i]
                role2 = role_distribution[j]
                
                # 检查两个角色的权限是否存在重复
                overlapping_permissions = self._find_overlapping_permissions(
                    role1["permissions"], role2["permissions"]
                )
                
                if overlapping_permissions:
                    issues.append({
                        "type": "redundancy",
                        "roles": [role1["role_name"], role2["role_name"]],
                        "permissions": overlapping_permissions
                    })
        
        return issues
    
    def _find_overlapping_permissions(self, permissions1: Dict[str, Any], permissions2: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        查找两个权限集合的重叠部分
        
        Args:
            permissions1: 第一个权限集合
            permissions2: 第二个权限集合
            
        Returns:
            Dict[str, List[str]]: 重叠的权限
        """
        overlapping = {}
        
        for resource, actions1 in permissions1.items():
            if resource in permissions2:
                actions2 = permissions2[resource]
                
                # 转换为列表以便比较
                actions1_list = actions1 if isinstance(actions1, list) else [actions1]
                actions2_list = actions2 if isinstance(actions2, list) else [actions2]
                
                # 查找重叠的操作
                common_actions = [action for action in actions1_list if action in actions2_list]
                
                if common_actions:
                    overlapping[resource] = common_actions
        
        return overlapping


# 注册路由
user_activity = UserActivityResource()
feature_usage = FeatureUsageResource()
permission_analysis = PermissionAnalysisResource()

v1_bp.add_route(user_activity.get, "/dashboard/user-activity", methods=["GET"])
v1_bp.add_route(feature_usage.get, "/dashboard/feature-usage", methods=["GET"])
v1_bp.add_route(permission_analysis.get, "/dashboard/permission-analysis", methods=["GET"]) 