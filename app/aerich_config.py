#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
aerich 迁移工具使用的 Tortoise 配置。

数据库地址不另起一份：直接取 ``app.config.settings.DATABASE_URL``
（与 ``app.models.init_db`` 同源，受 ``SANIC_ENV`` / ``DATABASE_URL`` 环境变量控制）。

用法见 ``docs/migrations.md``。
"""

from app.config import settings

# 模型模块与 app.models.init_db 保持一致；aerich.models 是 aerich 自己的版本账本表。
MODEL_MODULES = ["app.models", "aerich.models"]


def build_tortoise_config(db_url: str) -> dict:
    """按给定数据库地址构造 aerich 需要的 Tortoise 配置字典（测试用临时库时调用）。"""
    return {
        "connections": {"default": db_url},
        "apps": {
            "models": {
                "models": list(MODEL_MODULES),
                "default_connection": "default",
            },
        },
    }


def _require_db_url() -> str:
    """迁移必须有真实数据库地址；静默回落到内存库会让 ``aerich`` 对空库操作而毫无察觉。"""
    db_url = getattr(settings, "DATABASE_URL", None)
    if not db_url or not str(db_url).strip():
        raise RuntimeError(
            "DATABASE_URL 为空：迁移需要真实数据库地址，"
            "请设置 SANIC_ENV / DATABASE_URL（不接受 sqlite://:memory: 回落）。"
        )
    return str(db_url).strip()


TORTOISE_ORM = build_tortoise_config(_require_db_url())
