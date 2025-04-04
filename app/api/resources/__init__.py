#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
API资源模块初始化文件

导入并注册所有API资源
"""

# 导入所有资源模块
from app.api.resources.account import AccountResource, AccountPasswordResource, AccountMeResource
from app.api.resources.role import RoleResource, RoleMembersResource, AccountRolesResource
from app.api.resources.profile import ProfileResource, MyProfileResource
from app.api.resources.log import LogResource, LogStatisticsResource
from app.api.resources.setting import SettingResource, SettingByKeyResource, SettingBulkResource
from app.api.resources.upload import (
    FileUploadResource, AvatarUploadResource, 
    FileListResource, FileDeleteResource, 
    FileDownloadCounterMiddleware
)
from app.api.resources.dashboard import (
    DashboardSummaryResource, DashboardActivitiesResource, DashboardStorageResource
)
from app.api.resources.dashboard_user import (
    UserActivityResource, FeatureUsageResource, PermissionAnalysisResource
)
from app.api.resources.dashboard_performance import (
    PerformanceResource, ExceptionsResource, AlertsResource
)

# 资源列表 - 用于配置文档
all_resources = [
    AccountResource,
    AccountPasswordResource, 
    AccountMeResource,
    RoleResource,
    RoleMembersResource,
    AccountRolesResource,
    ProfileResource,
    LogResource,
    LogStatisticsResource,
    SettingResource,
    SettingByKeyResource,
    SettingBulkResource,
    FileUploadResource,
    AvatarUploadResource,
    FileListResource,
    FileDeleteResource,
    # 仪表盘资源
    DashboardSummaryResource,
    DashboardActivitiesResource,
    DashboardStorageResource,
    UserActivityResource,
    FeatureUsageResource,
    PermissionAnalysisResource,
    PerformanceResource,
    ExceptionsResource,
    AlertsResource
]

__all__ = [
    'all_resources',
    'AccountResource',
    'AccountPasswordResource',
    'AccountMeResource',
    'RoleResource',
    'RoleMembersResource',
    'AccountRolesResource',
    'ProfileResource',
    'MyProfileResource',
    'LogResource',
    'LogStatisticsResource',
    'SettingResource',
    'SettingByKeyResource',
    'SettingBulkResource',
    'FileUploadResource',
    'AvatarUploadResource',
    'FileListResource',
    'FileDeleteResource',
    'FileDownloadCounterMiddleware',
    # 仪表盘资源
    'DashboardSummaryResource',
    'DashboardActivitiesResource',
    'DashboardStorageResource',
    'UserActivityResource',
    'FeatureUsageResource',
    'PermissionAnalysisResource',
    'PerformanceResource',
    'ExceptionsResource',
    'AlertsResource'
] 