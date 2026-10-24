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
    'init_db',
]


def _redact_db_url(db_url: str) -> str:
    """日志中隐去数据库 URL 里的口令。"""
    if "@" in db_url and "://" in db_url:
        scheme, rest = db_url.split("://", 1)
        return f"{scheme}://***@{rest.rsplit('@', 1)[1]}"
    return db_url


async def _aerich_ledger_present() -> bool:
    """检查 aerich 版本账本表是否存在（不依赖 aerich 包，直接查系统表）。"""
    try:
        conn = Tortoise.get_connection("default")
        if getattr(conn.capabilities, "dialect", "") == "sqlite":
            rows = await conn.execute_query_dict(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='aerich'"
            )
            return bool(rows)
        # 必须按当前 schema 过滤：同名表可能存在于别的 schema 里，
        # 不过滤会把「其它库的账本表」误判为本库已有。
        dialect = getattr(conn.capabilities, "dialect", "")
        if "mysql" in dialect or "maria" in dialect:
            rows = await conn.execute_query_dict(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_name='aerich' AND table_schema = DATABASE()"
            )
        else:
            rows = await conn.execute_query_dict(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_name='aerich' AND table_schema = current_schema()"
            )
        return bool(rows)
    except Exception:
        logger.warning("检查 aerich 账本表失败，按缺失处理")
        return False


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

    env = str(getattr(config, "ENV", "") or "").lower()
    if env == "production":
        # 生产：结构由迁移链负责（见 docs/migrations.md）。generate_schemas 的
        # safe=True 只建缺失的表、不加也不改列，在这里跑会让「缺迁移」被静默掩盖，
        # 长期停在旧 schema。改为检查账本表存在，缺失即拒绝启动。
        if not await _aerich_ledger_present():
            raise RuntimeError(
                "生产环境缺少 aerich 迁移账本表：请先执行 `aerich upgrade` "
                "（存量库见 docs/migrations.md 的基线化流程）后再启动。"
            )
    else:
        await Tortoise.generate_schemas(safe=True)

    logger.info(f"数据库连接初始化完成，使用: {_redact_db_url(db_url)}")
