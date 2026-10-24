#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
按数据库方言选择基线迁移（SA-MIG-S2 整改第 1 项）。

背景：aerich 0.7.2 的 `init-db` 生成的是**当前连接方言**的 DDL——SQLite 版含
`AUTOINCREMENT`、`JSON` 与 `/* */` 注释，在 MySQL/PG 上直接执行会报语法错误
（UB26 实测：MySQL 1064、PG `syntax error at or near "AUTOINCREMENT"`）。
aerich 本身不支持「单份基线多方言」，因此本仓库按方言各存一份基线：

    migrations/dialects/sqlite/0_init.py
    migrations/dialects/mysql/0_init.py
    migrations/dialects/postgres/0_init.py

`migrations/models/` 仍是 aerich 的工作目录（默认 SQLite 基线放在那里）。
切到其它方言时，用本脚本把对应方言基线安装进 `migrations/models/`：

    python scripts/migrations/select_dialect_baseline.py mysql

用法约束：**只在你确定目标库方言时执行一次**，随后 `aerich upgrade`。
安装动作会替换 `migrations/models/0_*_init.py`——该文件已进版本库，
切方言会产生 diff，提交前请确认目标方言与部署环境一致。
"""
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
DIALECTS_DIR = REPO / "migrations" / "dialects"
MODELS_DIR = REPO / "migrations" / "models"

#: 方言 -> 从连接串 scheme 识别（tortoise 的 scheme 名）
SUPPORTED = ("sqlite", "mysql", "postgres")

#: 三份方言基线统一使用的文件名——**必须与 aerich 账本里记录的版本名一致**。
#: 变更此名会导致已基线化的库把基线当成未应用而重复建表。
BASELINE_FILENAME = "0_20261024125437_init.py"


def detect_dialect(db_url: str) -> str:
    """从 Tortoise 连接串推断方言。"""
    scheme = (db_url or "").split("://", 1)[0].lower()
    if scheme in ("mysql", "mariadb"):
        return "mysql"
    if scheme in ("postgres", "psycopg", "asyncpg"):
        return "postgres"
    if scheme in ("sqlite",):
        return "sqlite"
    raise SystemExit(f"!! 无法识别的数据库方言: {scheme!r}（支持 {', '.join(SUPPORTED)}）")


def install(dialect: str, target_dir: Path = MODELS_DIR) -> Path:
    """把指定方言的基线装进 aerich 的迁移目录，返回写入的路径。"""
    if dialect not in SUPPORTED:
        raise SystemExit(f"!! 不支持的方言: {dialect}（支持 {', '.join(SUPPORTED)}）")
    src = DIALECTS_DIR / dialect / BASELINE_FILENAME
    if not src.is_file():
        raise SystemExit(f"!! 方言基线不存在: {src}")
    target_dir.mkdir(parents=True, exist_ok=True)
    # 清掉已有的基线（保持「每个迁移目录只有一份 0_*_init」）
    for old in target_dir.glob("0_*_init.py"):
        old.unlink()
        print(f"  移除旧基线: {old.name}")
    # 文件名必须与账本里记录的版本名一致：aerich 以「文件名」为版本键，
    # 若安装名与账本不一致（例如账本记 0_20261024125437_init.py 而这里装成
    # 0_mysql_init.py），upgrade 会把基线当成「没跑过」，去重建已存在的表。
    dst = target_dir / BASELINE_FILENAME
    shutil.copyfile(src, dst)
    print(f"  已安装 {dialect} 基线 -> {dst.relative_to(REPO)}")
    return dst


def main(argv) -> int:
    from_detect = "--auto" in argv
    args = [a for a in argv if a != "--auto"]
    if from_detect:
        import os

        db_url = os.environ.get("DATABASE_URL", "")
        dialect = detect_dialect(db_url)
        print(f"  按 DATABASE_URL 自动识别方言: {dialect}")
    elif args:
        dialect = args[0].lower()
    else:
        print(__doc__)
        print("用法: select_dialect_baseline.py <sqlite|mysql|postgres>  |  --auto")
        return 2
    install(dialect)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
