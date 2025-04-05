#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
pytest配置文件

提供测试夹具和测试环境配置
"""

import os
import sys
import asyncio
import pytest
from typing import Dict, Any, List, Optional, Generator, AsyncGenerator

from sanic import Sanic
from sanic_testing import TestManager
from tortoise import Tortoise

from app import create_app
from app.config import settings
from app.models import init_db
from app.auth.authentication import create_initial_admin_account


# 测试配置覆盖
test_config = {
    "TESTING": True,
    "DEBUG": True,
    "DB_URL": "sqlite://:memory:",  # 使用内存数据库
    "SECRET_KEY": "test_secret_key",
    "ACCESS_TOKEN_EXPIRE_MINUTES": 15,
    "REFRESH_TOKEN_EXPIRE_DAYS": 7,
    "CACHE_TYPE": "memory",  # 使用内存缓存
    "MAIL_ENABLED": False,   # 禁用邮件发送
    "UPLOAD_DIR": "/tmp/sanic_admin_test_uploads",
    "STATIC_DIR": "/tmp/sanic_admin_test_static"
}


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """创建一个会话范围的事件循环"""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
async def app() -> AsyncGenerator[Sanic, None]:
    """创建测试应用实例"""
    app_instance = create_app(test_config)
    
    # 添加测试管理器
    TestManager(app_instance)
    
    # 确保测试目录存在
    os.makedirs(test_config["UPLOAD_DIR"], exist_ok=True)
    os.makedirs(test_config["STATIC_DIR"], exist_ok=True)
    
    # 初始化数据库
    await init_db(app_instance)
    
    # 生成测试数据
    await generate_test_data()
    
    yield app_instance
    
    # 清理数据库
    await Tortoise.close_connections()


@pytest.fixture(scope="function")
async def client(app) -> AsyncGenerator[TestManager, None]:
    """创建测试客户端"""
    yield app.test_manager


@pytest.fixture(scope="function")
async def auth_headers() -> Dict[str, str]:
    """获取认证头信息"""
    # 实现获取认证令牌的逻辑
    from app.models.account import Account
    from app.auth.jwt import create_access_token
    
    admin = await Account.filter(username="admin").first()
    if not admin:
        # 如果没有管理员账户，创建一个
        await create_initial_admin_account()
        admin = await Account.filter(username="admin").first()
    
    access_token = await create_access_token({"sub": str(admin.id)})
    
    return {
        "Authorization": f"Bearer {access_token}"
    }


async def generate_test_data() -> None:
    """生成测试数据"""
    from app.models.account import Account
    from app.models.role import Role
    from app.models.permission import Permission
    
    # 创建测试权限
    test_permissions = [
        {"code": "system:test:read", "name": "测试读取权限", "description": "用于测试的读取权限"},
        {"code": "system:test:write", "name": "测试写入权限", "description": "用于测试的写入权限"},
        {"code": "system:test:delete", "name": "测试删除权限", "description": "用于测试的删除权限"},
    ]
    
    for perm_data in test_permissions:
        await Permission.get_or_create(
            code=perm_data["code"],
            defaults={
                "name": perm_data["name"],
                "description": perm_data["description"]
            }
        )
    
    # 创建测试角色
    test_role, _ = await Role.get_or_create(
        code="test_role",
        defaults={
            "name": "测试角色",
            "description": "用于测试的角色"
        }
    )
    
    # 为测试角色分配权限
    perms = await Permission.filter(code__startswith="system:test:")
    await test_role.permissions.add(*perms)
    
    # 创建测试用户
    test_user, _ = await Account.get_or_create(
        username="testuser",
        defaults={
            "email": "test@example.com",
            "password_hash": Account.hash_password("testpassword"),
            "is_active": True,
            "display_name": "测试用户"
        }
    )
    
    # 为测试用户分配角色
    await test_user.roles.add(test_role)


@pytest.fixture(scope="function")
async def test_user_auth_headers() -> Dict[str, str]:
    """获取测试用户的认证头信息"""
    from app.models.account import Account
    from app.auth.jwt import create_access_token
    
    test_user = await Account.filter(username="testuser").first()
    if not test_user:
        # 如果没有测试用户，先生成测试数据
        await generate_test_data()
        test_user = await Account.filter(username="testuser").first()
    
    access_token = await create_access_token({"sub": str(test_user.id)})
    
    return {
        "Authorization": f"Bearer {access_token}"
    } 