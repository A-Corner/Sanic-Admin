#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
v0.3.2 存量库迁移：account 表补 must_change_password 列（首次登录强制改密）。

背景：项目未引入迁移框架，Tortoise 的 generate_schemas 只建表不加列。
从 v0.3.1 及更早版本升级的**存量**数据库需要执行本脚本补列；全新安装
（generate_schemas 建表）自动包含该列，无需运行。

用法（在仓库根目录、已配置数据库环境变量的环境下）：
    python scripts/migrate_v0_3_2_must_change_password.py

幂等：列已存在时跳过，可重复执行。支持 SQLite 与 PostgreSQL。
"""

import asyncio
import os
import sys

ALTER_SQL = {
    "sqlite": "ALTER TABLE account ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT 0;",
    "postgres": "ALTER TABLE account ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE;",
}


def column_exists(conn, table: str, column: str) -> bool:
    """按后端类型探测列是否已存在。"""
    if conn.sqlite:
        rows = conn.execute_query_dict(f"PRAGMA table_info({table})")
        return any(row["name"] == column for row in rows)
    rows = conn.execute_query_dict(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = %s AND column_name = %s",
        [table, column],
    )
    return bool(rows)


async def main() -> int:
    from tortoise import Tortoise

    from app.config import config_to_dict, get_config

    env = os.environ.get("SANIC_ENV", "development")
    cfg = config_to_dict(get_config(env))
    db_url = os.environ.get("DB_URL") or cfg.get("DATABASE_URL")
    if not db_url:
        print("❌ 未找到 DATABASE_URL 配置（环境变量 DB_URL 或 SANIC_ENV 对应配置）", file=sys.stderr)
        return 1

    await Tortoise.init(db_url=db_url, modules={"models": ["app.models"]})
    try:
        conn = Tortoise.get_connection("default")
        if column_exists(conn, "account", "must_change_password"):
            print("✅ account.must_change_password 列已存在，无需迁移")
            return 0
        dialect = "sqlite" if conn.sqlite else "postgres"
        if dialect not in ALTER_SQL:
            print(f"❌ 不支持的数据库方言：{dialect}", file=sys.stderr)
            return 1
        await conn.execute_script(ALTER_SQL[dialect])
        print(f"✅ 已在 {dialect} 上补列：account.must_change_password（NOT NULL DEFAULT FALSE）")
        return 0
    finally:
        await Tortoise.close_connections()


if __name__ == "__main__":
    sys.exit(main())
