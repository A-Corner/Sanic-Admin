#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
存量库基线化脚本（SA-MIG-S1，方案 A / aerich 路线）。

用途：给「 aerich 引入之前就已经存在的库」打上基线标记——这些库的表早已由
``generate_schemas(safe=True)`` 建好，直接 ``aerich upgrade`` 会撞「表已存在」，
直接 ``init-db`` 也会撞。正确姿势：

  1. 手工创建 aerich 版本账本表（本脚本完成，DDL 与 aerich 0.7.2 的
     Tortoise 模型产出一致，已实测被 ``aerich upgrade`` 接受）；
  2. 把基线迁移（migrations/models/0_*_init.py）作为「已应用」写入账本
     （本脚本完成，content 与迁移文件全文一致）；
  3. 之后 ``aerich upgrade`` 即为无操作（no-op），账本对齐；
  4. 以后每次改模型 → ``aerich migrate`` → ``aerich upgrade``，恢复正常迭代。

幂等：重复执行安全（表已存在则跳过建表；基线行已存在则跳过写入）。
用法：python scripts/migrations/baseline_existing_db.py <sqlite路径> [迁移目录]
"""
import sqlite3
import sys
from pathlib import Path

AERICH_TABLE_DDL = (
    'CREATE TABLE "aerich" ('
    '"id" INTEGER PRIMARY KEY AUTOINCREMENT, '
    '"version" VARCHAR(255) NOT NULL, '
    '"app" VARCHAR(60) NOT NULL, '
    '"content" TEXT NOT NULL)'
)


def main(db_path: str, migrations_dir: str, app: str = "models", fresh: bool = False) -> int:
    db = Path(db_path)
    if not db.is_file():
        if not fresh:
            print(f"!! 数据库文件不存在: {db}（全新部署请加 --fresh）")
            return 1
        print("  全新库：将创建空文件与账本表")
    mig_dir = Path(migrations_dir)
    baselines = sorted(mig_dir.glob("0_*_init.py"))
    if not baselines:
        print(f"!! 迁移目录里找不到基线迁移(0_*_init.py): {mig_dir}")
        return 1
    baseline_file = baselines[0]
    content = baseline_file.read_text()

    conn = sqlite3.connect(str(db))
    try:
        exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='aerich'"
        ).fetchone()
        if exists is None:
            conn.execute(AERICH_TABLE_DDL)
            conn.commit()
            print("  已创建 aerich 账本表")
        else:
            print("  aerich 账本表已存在，跳过建表")

        if fresh:
            print("  --fresh：只创建账本表，不标记基线（upgrade 将应用基线迁移建表）")
            return 0
        already = conn.execute(
            "SELECT id FROM aerich WHERE version=? AND app=?", (baseline_file.name, app)
        ).fetchone()
        if already:
            print(f"  基线 {baseline_file.name} 已在账本中，跳过写入")
            return 0
        conn.execute(
            'INSERT INTO "aerich" ("version", "app", "content") VALUES (?, ?, ?)',
            (baseline_file.name, app, content),
        )
        conn.commit()
        print(f"  已写入基线: {baseline_file.name} (app={app})")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--fresh"]
    fresh = "--fresh" in sys.argv[1:]
    if len(args) < 2:
        print(__doc__)
        print("用法: baseline_existing_db.py <sqlite库路径> <迁移目录> [app名] [--fresh]")
        print("  --fresh  全新库：只创建账本表、不标记基线（随后 upgrade 应用基线迁移建表）")
        raise SystemExit(2)
    app_name = args[2] if len(args) > 2 else "models"
    raise SystemExit(main(args[0], args[1], app_name, fresh))
