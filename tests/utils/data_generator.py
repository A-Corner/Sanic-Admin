#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
测试数据生成工具模块

提供各种测试场景所需的数据生成函数
"""

import random
import string
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple

from app.models.account import Account
from app.models.role import Role
from app.models.permission import Permission
from app.models.system_log import SystemLog
from app.models.system_setting import SystemSetting


async def create_test_account(
    username: Optional[str] = None,
    email: Optional[str] = None,
    password: str = "password123",
    is_active: bool = True,
    is_admin: bool = False,
    role_codes: Optional[List[str]] = None
) -> Account:
    """
    创建测试账户

    Args:
        username: 用户名，如果为None则自动生成
        email: 邮箱，如果为None则自动生成
        password: 密码
        is_active: 是否激活
        is_admin: 是否为管理员
        role_codes: 角色代码列表，如果为None则不分配角色

    Returns:
        Account: 创建的账户对象
    """
    if username is None:
        username = f"user_{uuid.uuid4().hex[:8]}"
    
    if email is None:
        email = f"{username}@example.com"
    
    # 创建账户
    account = await Account.create(
        username=username,
        email=email,
        password_hash=Account.hash_password(password),
        is_active=is_active,
        is_admin=is_admin,
        display_name=f"测试用户 {username}",
        avatar="default.png"
    )
    
    # 分配角色
    if role_codes:
        roles = await Role.filter(code__in=role_codes)
        if roles:
            await account.roles.add(*roles)
    
    return account


async def create_test_roles(
    count: int = 3,
    with_permissions: bool = True
) -> List[Role]:
    """
    创建测试角色

    Args:
        count: 创建角色的数量
        with_permissions: 是否为角色分配权限

    Returns:
        List[Role]: 创建的角色列表
    """
    roles = []
    
    for i in range(count):
        role_code = f"test_role_{i}"
        role, _ = await Role.get_or_create(
            code=role_code,
            defaults={
                "name": f"测试角色 {i}",
                "description": f"这是测试角色 {i} 的描述",
                "sort_order": i
            }
        )
        roles.append(role)
    
    # 如果需要分配权限
    if with_permissions and roles:
        # 创建一些测试权限
        permissions = []
        perm_types = ["read", "write", "delete", "export", "import"]
        
        for i, role in enumerate(roles):
            for perm_type in perm_types:
                perm_code = f"system:test:{role.code}:{perm_type}"
                perm, _ = await Permission.get_or_create(
                    code=perm_code,
                    defaults={
                        "name": f"测试{perm_type}权限 {i}",
                        "description": f"这是角色 {role.code} 的测试{perm_type}权限"
                    }
                )
                permissions.append(perm)
            
            # 为每个角色分配相应的权限（分配2-5个权限）
            role_perms_count = random.randint(2, min(5, len(permissions)))
            role_perms = random.sample(permissions, role_perms_count)
            await role.permissions.add(*role_perms)
    
    return roles


async def create_test_system_logs(
    count: int = 50,
    account_id: Optional[int] = None
) -> List[SystemLog]:
    """
    创建测试系统日志

    Args:
        count: 创建日志的数量
        account_id: 关联的账户ID，如果为None则使用随机账户或不关联

    Returns:
        List[SystemLog]: 创建的系统日志列表
    """
    logs = []
    
    # 如果没有指定账户，获取一个随机账户或创建新账户
    if account_id is None:
        accounts = await Account.all()
        if not accounts:
            test_account = await create_test_account()
            account_id = test_account.id
        else:
            account_id = random.choice(accounts).id
    
    # 操作类型
    operation_types = ["登录", "登出", "创建", "更新", "删除", "查询", "导出", "导入"]
    
    # 模块名称
    module_names = ["账户管理", "角色管理", "权限管理", "系统设置", "日志管理", "文件管理"]
    
    # IP地址
    ip_addresses = [
        "192.168.1.1", "10.0.0.1", "172.16.0.1", 
        "127.0.0.1", "::1", "fe80::1234:5678:abcd:ef01"
    ]
    
    # 用户代理
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
    ]
    
    # 创建日志
    for i in range(count):
        # 生成随机时间（过去30天内）
        days_ago = random.randint(0, 30)
        hours_ago = random.randint(0, 23)
        minutes_ago = random.randint(0, 59)
        log_time = datetime.now() - timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)
        
        # 随机选择操作类型和模块
        operation_type = random.choice(operation_types)
        module_name = random.choice(module_names)
        
        # 生成操作内容
        if operation_type == "登录":
            operation = "用户登录系统"
            status = random.choice([0, 0, 0, 1])  # 大部分登录成功
        elif operation_type == "登出":
            operation = "用户退出系统"
            status = 0  # 登出总是成功
        else:
            operation = f"{operation_type}{module_name}数据"
            status = random.choice([0, 0, 0, 1])  # 大部分操作成功
        
        # 根据状态设置详细信息
        if status == 0:
            details = f"{operation}成功"
        else:
            error_reasons = [
                "权限不足", "数据不存在", "参数无效", "系统错误", "数据库错误"
            ]
            details = f"{operation}失败：{random.choice(error_reasons)}"
        
        # 创建日志
        log = await SystemLog.create(
            account_id=account_id,
            operation_type=operation_type,
            operation=operation,
            status=status,
            details=details,
            ip_address=random.choice(ip_addresses),
            user_agent=random.choice(user_agents),
            module=module_name,
            created_at=log_time
        )
        
        logs.append(log)
    
    return logs


async def create_test_system_settings(
    count: int = 10
) -> List[SystemSetting]:
    """
    创建测试系统设置

    Args:
        count: 创建设置的数量

    Returns:
        List[SystemSetting]: 创建的系统设置列表
    """
    settings = []
    
    # 设置类型
    setting_categories = ["系统", "安全", "界面", "通知", "功能"]
    
    # 可能的设置项
    possible_settings = [
        {"key": "system_name", "name": "系统名称", "value": "Sanic-Admin测试系统", "category": "系统"},
        {"key": "system_logo", "name": "系统Logo", "value": "logo.png", "category": "系统"},
        {"key": "system_description", "name": "系统描述", "value": "这是一个测试系统", "category": "系统"},
        {"key": "allow_registration", "name": "允许注册", "value": "true", "category": "安全"},
        {"key": "login_attempts", "name": "登录尝试次数", "value": "5", "category": "安全"},
        {"key": "password_expire_days", "name": "密码过期天数", "value": "90", "category": "安全"},
        {"key": "lock_time_minutes", "name": "账户锁定时间(分钟)", "value": "30", "category": "安全"},
        {"key": "theme", "name": "主题", "value": "light", "category": "界面"},
        {"key": "sidebar_collapsed", "name": "侧边栏折叠", "value": "false", "category": "界面"},
        {"key": "show_breadcrumb", "name": "显示面包屑", "value": "true", "category": "界面"},
        {"key": "enable_email_notification", "name": "启用邮件通知", "value": "true", "category": "通知"},
        {"key": "notification_channels", "name": "通知渠道", "value": "email,sms", "category": "通知"},
        {"key": "enable_file_upload", "name": "启用文件上传", "value": "true", "category": "功能"},
        {"key": "max_upload_size", "name": "最大上传大小(MB)", "value": "10", "category": "功能"},
        {"key": "allowed_file_types", "name": "允许的文件类型", "value": "jpg,png,pdf,doc,docx", "category": "功能"},
    ]
    
    # 随机选择设置项
    if count > len(possible_settings):
        count = len(possible_settings)
    
    selected_settings = random.sample(possible_settings, count)
    
    # 创建设置
    for i, setting in enumerate(selected_settings):
        system_setting = await SystemSetting.create(
            key=setting["key"],
            name=setting["name"],
            value=setting["value"],
            category=setting["category"],
            description=f"这是{setting['name']}的描述",
            sort_order=i
        )
        
        settings.append(system_setting)
    
    return settings


def generate_random_string(length: int = 10) -> str:
    """生成随机字符串"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def generate_random_email() -> str:
    """生成随机邮箱"""
    domains = ["example.com", "test.com", "mock.org", "demo.net"]
    username = generate_random_string(8).lower()
    domain = random.choice(domains)
    return f"{username}@{domain}" 