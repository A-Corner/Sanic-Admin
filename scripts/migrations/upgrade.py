#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
迁移应用入口（带方言校验）。

为什么需要它：直接跑 `aerich upgrade` 时，若 `migrations/models/` 里装的是**别的方言**
的基线，SQLite 版在 MySQL/PG 上会直接报语法错误（`AUTOINCREMENT`），反之则可能静默
按错误类型建表。本入口在 upgrade 之前先做方言一致性校验，不一致立刻退出。

用法：
    python scripts/migrations/upgrade.py            # 用 DATABASE_URL
    python scripts/migrations/upgrade.py --url <dsn>

退出码：
    0  升级成功（可能为 no-op）
    1  升级失败（数据库或迁移文件问题）
    2  用法/配置错误（如 DATABASE_URL 为空、不支持的方言）
    4  **方言不一致**：`migrations/models/` 装的不是目标方言的基线，
       需先执行 `python scripts/migrations/select_dialect_baseline.py <方言>`
"""
import argparse
import asyncio
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

#: aerich 的迁移根目录（location）与其下的 models 子目录是两个概念：
#: location 传给 aerich，models 目录里才是基线文件
MIGRATIONS_ROOT = REPO / "migrations"
MODELS_DIR = MIGRATIONS_ROOT / "models"


def _resolve_url(cli_url: str) -> str:
    if cli_url:
        return cli_url
    env_url = os.environ.get("DATABASE_URL")
    if env_url and env_url.strip():
        return env_url.strip()
    print("!! 未提供数据库地址：请设置 DATABASE_URL 或使用 --url", file=sys.stderr)
    raise SystemExit(2)


def _load_baseline_checker():
    """复用 baseline_existing_db.py 里的方言校验（单一定义，避免两处漂移）。"""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "baseline_existing_db", REPO / "scripts" / "migrations" / "baseline_existing_db.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


async def _upgrade(db_url: str) -> int:
    from aerich import Command

    from app.aerich_config import build_tortoise_config

    command = Command(build_tortoise_config(db_url), app="models",
                      location=str(MIGRATIONS_ROOT))
    await command.init()
    # SQLite 上事务模式会死锁（aerich 官方的 --no-transaction 即为此场景）
    migrated = await command.upgrade(run_in_transaction=False)
    if migrated:
        print(f"已应用迁移: {migrated}")
    else:
        print("无待应用迁移（账本已对齐）")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="应用迁移（含方言校验）")
    parser.add_argument("--url", help="数据库连接串（缺省取 DATABASE_URL）")
    args = parser.parse_args(argv)

    db_url = _resolve_url(args.url)

    checker = _load_baseline_checker()
    dialect_err = checker.verify_installed_baseline_matches_dialect(db_url, MODELS_DIR)
    if dialect_err:
        print(f"!! {dialect_err}", file=sys.stderr)
        return 4

    try:
        return asyncio.run(_upgrade(db_url))
    except Exception as exc:
        print(f"!! 升级失败: {exc!r}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
