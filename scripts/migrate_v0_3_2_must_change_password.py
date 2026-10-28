#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
v0.3.2 存量库迁移：account 表补 must_change_password 列（首次登录强制改密）。

背景：项目未引入迁移框架，Tortoise 的 generate_schemas 只建表不加列。
从 v0.3.1 及更早版本升级的**存量**数据库需要执行本脚本补列；全新安装
（generate_schemas 建表）自动包含该列，无需运行。

幂等：列已存在时跳过 ALTER；口令仍等于 INITIAL_ADMIN_PASSWORD（当前环境变量）
或历史硬编码默认口令（v0.3.1 及更早版本内置）的管理员会被置
must_change_password=True（交付口令未换，必须走强制改密）。脚本不打印、
不记录任何口令。

初始管理员兜底创建：库里已有管理员、但没有 INITIAL_ADMIN_EMAIL 对应账户
（管理员邮箱已改过）时，默认打印警告并跳过创建，避免静默多建一个管理员；
确需创建时加 ``--create-initial-admin``。

边界：仅比对 **未禁用的管理员**（is_admin=True 且 disabled=False）。
被禁用的管理员与非管理员账户即使口令仍是默认值也不比对、不置标志——
禁用账户无法登录，非管理员不经此流程管理。

**这个边界留下一个未覆盖的分支，运维必须知道**：
被跳过的禁用管理员，其 ``must_change_password`` 保持 False（补列 DDL 的默认值），
口令也仍是**从未更换过的历史默认口令**。项目当前**没有「重新启用账号」的代码路径**
（``app/models/account.py:178`` 只有 ``disable()``，全仓无 ``enable()``；
``app/api/resources/account.py`` 的 ``ACCOUNT_UPDATE_FIELDS`` 也不含 ``disabled``），
所以应用层不会自动发生；但运维直接改库
（``UPDATE account SET disabled=0 ...``）恢复一个禁用管理员后，该账号会
**带着默认口令、以 must_change_password=False 直接可登录，并跳过强制改密**，
且 ``is_admin=True`` 意味着全量权限。

``must_change_password`` 唯一的清零点是本人改密（``app/auth/routes.py`` 里
改密成功后 save 该字段），重新启用路径上没有任何重置逻辑。

**恢复被禁用管理员时的正确做法**：恢复后**手动复跑一次本脚本**
（脚本每次运行都会重新比对，发现口令仍是默认值就会重新置标志）；
或恢复时同时把该账号的 ``must_change_password`` 直接置为 1。
**本脚本是升级期一次性步骤，常规流程不会自动复跑——这条不能靠脚本自己兜住。**

支持方言：SQLite / MySQL / PostgreSQL（生产默认 MySQL，见 app/config.py）。
用法（在仓库根目录、已配置数据库环境变量的环境下）：
    python scripts/migrate_v0_3_2_must_change_password.py [--create-initial-admin]
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path

# 仓库根加入 sys.path（脚本在 scripts/ 下，`python scripts/x.py` 时根不在 path）
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

#: v0.3.1 及更早版本硬编码的初始管理员口令（已公开于旧版 README/CLAUDE.md）。
#: 仍使用它的管理员必须强制改密。仅用于 verify 比对，绝不打印/记录。
LEGACY_DEFAULT_ADMIN_PASSWORDS = ("SAdmin@123",)

ALTER_SQL = {
    # SQLite 用 INT：与 aerich 基线（Tortoise 对 BooleanField 生成 INT）一致，
    # 避免「手写补列 BOOLEAN / 基线 INT」造成守门比对时出现虚假类型差异。
    "sqlite": "ALTER TABLE account ADD COLUMN must_change_password INT NOT NULL DEFAULT 0;",
    "mysql": "ALTER TABLE account ADD COLUMN must_change_password BOOL NOT NULL DEFAULT FALSE;",
    "postgres": "ALTER TABLE account ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE;",
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


async def main(create_initial_admin: bool = False) -> int:
    from tortoise import Tortoise

    from app.auth.authentication import create_initial_admin_account
    from app.config import BaseConfig, config_to_dict, get_config
    from app.models import Account

    env = os.environ.get("SANIC_ENV", "development")
    cfg = config_to_dict(get_config(env))
    # 统一读 DATABASE_URL（与 aerich / app.config 同源）；DB_URL 保留兼容但提示弃用
    db_url = os.environ.get("DATABASE_URL") or cfg.get("DATABASE_URL")
    if os.environ.get("DB_URL"):
        print(
            "[deprecation] 环境变量 DB_URL 已弃用，请改用 DATABASE_URL（本次仍按 DB_URL 生效）。",
            file=sys.stderr,
        )
        db_url = os.environ["DB_URL"] or db_url
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
        # 比对口令 = 当前 INITIAL_ADMIN_PASSWORD（若设置）+ 历史硬编码默认口令。
        # argon2 盐随机，无法用 SQL 比对——逐账户 verify。
        candidates = [p for p in (admin_password, *LEGACY_DEFAULT_ADMIN_PASSWORDS) if p]
        if not admin_password:
            print("ℹ️ 未设置 INITIAL_ADMIN_PASSWORD，仅比对历史默认口令")
        flagged = 0
        admins = await Account.filter(is_admin=True, disabled=False)
        for admin in admins:
            if admin.must_change_password:
                continue
            if any(admin.verify_password(p) for p in candidates):
                admin.must_change_password = True
                await admin.save(update_fields=["must_change_password"])
                flagged += 1
        print(f"✅ 口令仍为交付/默认口令的管理员已置强制改密：{flagged} 个")

        # create_initial_admin_account：全新库上兜底建管理员（幂等，已存在则返回现有）。
        # 已有管理员但邮箱不是 INITIAL_ADMIN_EMAIL（邮箱改过）时默认跳过，不静默多建。
        initial_email = BaseConfig.INITIAL_ADMIN_EMAIL
        has_initial = await Account.filter(email=initial_email).exists()
        if not has_initial and admins and not create_initial_admin:
            print(
                f"⚠️ 库里已有 {len(admins)} 个管理员，但没有 {initial_email} 账户"
                "（管理员邮箱可能已改过）：跳过初始管理员创建。"
                "确需创建请加 --create-initial-admin",
                file=sys.stderr,
            )
        else:
            await create_initial_admin_account()
        return 0
    finally:
        await Tortoise.close_connections()


def _parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="v0.3.2 must_change_password 存量库迁移")
    parser.add_argument(
        "--create-initial-admin",
        action="store_true",
        help="即使库里已有其它邮箱的管理员，也创建 INITIAL_ADMIN_EMAIL 初始管理员",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args()
    sys.exit(asyncio.run(main(create_initial_admin=args.create_initial_admin)))
