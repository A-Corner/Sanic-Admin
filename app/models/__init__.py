#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
数据模型包，包含所有数据模型和数据库初始化函数

所有模型类必须在此处导入：``init_db`` 以本包为 Tortoise 的模型模块，
只有包命名空间里的模型才会被注册。
"""

from tortoise import Tortoise
from sanic import Sanic
from sanic.log import logger
from app.config import settings
from app.models.base import BaseModel
from app.models.account import Account
from app.models.role import Role
from app.models.session import (
    Session,
    VerificationSession,
    TwoStepSession,
    CaptchaSession,
    AuthenticationSession,
)
from app.models.verification import VerificationToken
from app.models.profile import Profile
from app.models.system_setting import SystemSetting
from app.models.operation_log import OperationLog
from app.models.uploaded_file import UploadedFile
from app.models.customer import Customer


# 导出所有模型类，方便其他模块导入
__all__ = [
    'BaseModel',
    'Account',
    'Role',
    'Session',
    'VerificationSession',
    'TwoStepSession',
    'CaptchaSession',
    'AuthenticationSession',
    'VerificationToken',
    'Profile',
    'SystemSetting',
    'OperationLog',
    'UploadedFile',
    'Customer',
    'init_db',
]


def _redact_db_url(db_url: str) -> str:
    """日志中隐去数据库 URL 里的口令。"""
    if "@" in db_url and "://" in db_url:
        scheme, rest = db_url.split("://", 1)
        return f"{scheme}://***@{rest.rsplit('@', 1)[1]}"
    return db_url


async def init_db(app: Sanic = None):
    """
    初始化数据库连接并建表

    Args:
        app: Sanic应用实例，可选；缺省使用全局 settings
    """
    config = app.config if app else settings
    db_url = getattr(config, 'DATABASE_URL', None) or 'sqlite://:memory:'

    await Tortoise.init(
        db_url=db_url,
        modules={'models': ['app.models']}
    )
    await Tortoise.generate_schemas(safe=True)

    logger.info(f"数据库连接初始化完成，使用: {_redact_db_url(db_url)}")
