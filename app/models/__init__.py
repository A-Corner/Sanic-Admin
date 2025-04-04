#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
数据模型包，包含所有数据模型和数据库初始化函数
"""

from tortoise import Tortoise
from sanic import Sanic
from sanic.log import logger
from app.config import settings
from app.models.account import Account
from app.models.role import Role
from app.models.session import Session
from app.models.base import BaseModel
from app.models.verification import VerificationToken
from enum import Enum


class TwoFactorMethod(Enum):
    """两步验证方法"""
    SMS = "sms"
    EMAIL = "email"
    APP = "app"


# 导出所有模型类，方便其他模块导入
__all__ = [
    'Account',
    'Role',
    'Session',
    'BaseModel',
    'VerificationToken',
    'TwoFactorMethod'
]


async def init_db(app: Sanic = None):
    """
    初始化数据库连接
    
    Args:
        app: Sanic应用实例，可选
    """
    config = app.config if app else settings
    
    # 获取数据库URL
    db_url = config.get('DATABASE_URL', 'sqlite://:memory:')
    
    # 初始化Tortoise ORM
    await Tortoise.init(
        db_url=db_url,
        modules={
            'models': ['app.models']
        }
    )
    
    # 生成数据库架构
    await Tortoise.generate_schemas()
    
    logger.info(f"数据库连接初始化完成，使用: {db_url}")


async def create_initial_admin():
    """
    创建初始管理员角色和账户
    
    如果系统中没有管理员角色，则创建一个默认的管理员角色
    此函数应该在应用启动时调用
    """
    # 检查管理员角色是否存在
    admin_role = await Role.filter(name='admin').first()
    
    # 如果不存在，创建管理员角色
    if not admin_role:
        admin_role = await Role.create(
            name='admin',
            description='系统管理员',
            permissions={
                'system': ['all'],
                'user': ['all'],
                'role': ['all'],
                'account': ['all']
            }
        )
        logger.info("创建了管理员角色")
    
    # 检查是否已存在管理员账户
    admin_account = await Account.filter(username='admin').first()
    
    # 如果不存在，创建一个默认的管理员账户
    if not admin_account:
        admin_account = await Account.create(
            username='admin',
            email='admin@example.com',
            is_active=True,
            is_admin=True
        )
        admin_account.set_password('admin123')
        await admin_account.save()
        
        # 分配管理员角色
        await admin_account.roles.add(admin_role)
        
        logger.info("创建了默认管理员账户，用户名: admin，密码: admin123")
    
    return admin_account 