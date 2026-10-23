#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
v0.3.2 存量库迁移：account 表补 must_change_password 列（首次登录强制改密）。

背景：项目未引入迁移框架，Tortoise 的 generate_schemas 只建表不加列。
从 v0.3.1 及更早版本升级的**存量**数据库需要执行本脚本补列；全新安装
（generate_schemas 建表）自动包含该列，无需运行。

幂等：列已存在时跳过 ALTER；口令仍等于 INITIAL_ADMIN_PASSWORD 的管理员
会被置 must_change_password=True（交付口令未换，必须走强制改密）。

支持方言：SQLite / MySQL / PostgreSQL（生产默认 MySQL，见 app/config.py）。
用法（在仓库根目录、已配置数据库环境变量的环境下）：
    python scripts/migrate_v0_3_2_must_change_password.py
"""

import asyncio
import os
import sys
from pathlib import Path

# 仓库根加入 sys.path（脚本在 scripts/ 下，`python scripts/x.py` 时根不在 path）
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ALTER_SQL = {
    "sqlite": "ALTER TABLE account ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT 0;",
    "mysql": "ALTER TABLE account ADD COLUMN must_change_password BOOL NOT NULL DEFAULT FALSE;",
    "postgres": 'ALTER TABLE account ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE;',
}


async def column_exists(conn, dialect: str, table: str, column: str) -> bool:
    """按方言探测列是否已存在（限定 schema，避免误探同名表）。"""
    if dialect == "sqlite":
        rows = await conn.execute_query_dict(f"PRAGMA table_info({table})")
        return any(row["name"] == column for row in rows)
    if dialect == "mysql":
        # DATABASE()：当前连接的库；避免探到其它库的同名表
        rows = await conn.execute_query_dict(
            "SELECT COLUMN_NAME AS name FROM information_schema.columns "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s "
            "AND COLUMN_NAME = %s",
            [table, column],
        )
        return bool(rows)
    # postgres：asyncpg 用 $1/$2 占位符
    rows = await conn.execute_query_dict(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND table_name = $1 "
        "AND column_name = $2",
        [table, column],
    )
    return bool(rows)


async def main() -> int:
    from tortoise import Tortoise

    from app.auth.authentication import create_initial_admin_account
    from app.config import config_to_dict, get_config
    from app.models import Account

    env = os.environ.get("SANIC_ENV", "development")
    cfg = config_to_dict(get_config(env))
    db_url = os.environ.get("DB_URL") or cfg.get("DATABASE_URL")
    admin_password = os.environ.get("INITIAL_ADMIN_PASSWORD", "")
    if not db_url:
        print("❌ 未找到 DATABASE_URL 配置（环境变量 DB_URL 或 SANIC_ENV 对应配置）", file=sys.stderr)
        return 1

    await Tortoise.init(db_url=db_url, modules={"models": ["app.models"]})
    try:
        conn = Tortoise.get_connection("default")
        dialect = conn.capabilities.dialect
        if dialect not in ALTER_SQL:
            print(f"❌ 不支持的数据库方言：{dialect}", file=sys.stderr)
            return 1

        if not await column_exists(conn, dialect, "account", "password"):
            # 全新空库（连 account 表都没有）：直接建全量表结构，新列天然包含
            print("ℹ️ 空库：generate_schemas 建全表（must_change_password 天然包含）")
            await Tortoise.generate_schemas()
        else:
            if await column_exists(conn, dialect, "account", "must_change_password"):
                print("✅ account.must_change_password 列已存在，跳过 ALTER")
            else:
                await conn.execute_script(ALTER_SQL[dialect])
                print(f"✅ 已在 {dialect} 上补列：account.must_change_password（NOT NULL DEFAULT FALSE）")
            # 部分存量库可能缺其它表（如只有 account 表的手工库）：
            # safe=True 只建缺失表，不动已有表/数据，保证后续管理员创建/比对可用
            await Tortoise.generate_schemas(safe=True)

        # M3：交付口令尚未更换的管理员（含初始管理员）必须进入强制改密流程。
        # argon2 盐随机，无法用 SQL 比对——逐账户 verify。
        # INITIAL_ADMIN_PASSWORD 未提供时跳过（无法验证，fail-safe 不强置）。
        flagged = 0
        if admin_password:
            admins = await Account.filter(is_admin=True, disabled=False)
            for admin in admins:
                if admin.verify_password(admin_password):
                    if not admin.must_change_password:
                        admin.must_change_password = True
                        await admin.save(update_fields=["must_change_password"])
                        flagged += 1
            print(f"✅ 口令仍等于 INITIAL_ADMIN_PASSWORD 的管理员已置强制改密：{flagged} 个")
        else:
            print("ℹ️ 未设置 INITIAL_ADMIN_PASSWORD，跳过管理员口令比对")

        # create_initial_admin_account：全新库上兜底建管理员（幂等，已存在则返回现有）
        await create_initial_admin_account()
        return 0
    finally:
        await Tortoise.close_connections()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
