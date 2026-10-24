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
     （本脚本完成；content 是 aerich 约定的「当前模型快照 JSON」——后续
     ``aerich migrate`` 以它为比较基准，写成迁移文件文本会让 migrate 失效）；
  3. 之后 ``aerich upgrade`` 即为无操作（no-op），账本对齐；
  4. 以后每次改模型 → ``aerich migrate`` → ``aerich upgrade``，恢复正常迭代。

**结构核对（v0.3.2 整改）**：写账本之前必须先核对「库里真实结构」与「模型快照」
是否一致；不一致就以非 0 退出，不写账本。否则账本会宣称已对齐而实际缺列，
`aerich upgrade` 永远不会补（S2 复审的 P1 问题）。

支持 SQLite / MySQL / PostgreSQL：方言由 ``--url`` 指定的连接串推断，
或直接给 SQLite 文件路径。

幂等：重复执行安全（表已存在则跳过建表；基线行已存在则跳过写入）。
用法：
  python scripts/migrations/baseline_existing_db.py <sqlite路径> <迁移目录> [app名] [--fresh]
  python scripts/migrations/baseline_existing_db.py --url "mysql://u:p@h/db" <迁移目录>
"""

import asyncio
import json
import sqlite3
import sys
from pathlib import Path
from typing import Optional

# 脚本在 scripts/migrations/ 下：仓库根加入 sys.path 以便导入 app.models
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

#: 各方言的 aerich 账本表 DDL（字段与 aerich 0.7.2 的 Tortoise 模型一致）
AERICH_TABLE_DDL_BY_DIALECT = {
    "sqlite": (
        'CREATE TABLE IF NOT EXISTS "aerich" ('
        '"id" INTEGER PRIMARY KEY AUTOINCREMENT, '
        '"version" VARCHAR(255) NOT NULL, '
        '"app" VARCHAR(60) NOT NULL, '
        '"content" TEXT NOT NULL)'
    ),
    "mysql": (
        "CREATE TABLE IF NOT EXISTS `aerich` ("
        "`id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY, "
        "`version` VARCHAR(255) NOT NULL, "
        "`app` VARCHAR(60) NOT NULL, "
        "`content` JSON NOT NULL) CHARACTER SET utf8mb4"
    ),
    "postgres": (
        'CREATE TABLE IF NOT EXISTS "aerich" ('
        '"id" SERIAL NOT NULL PRIMARY KEY, '
        '"version" VARCHAR(255) NOT NULL, '
        '"app" VARCHAR(60) NOT NULL, '
        '"content" JSONB NOT NULL)'
    ),
}

AERICH_TABLE_DDL = AERICH_TABLE_DDL_BY_DIALECT["sqlite"]


def models_snapshot(db_path: str, app: str) -> str:
    """当前模型的 aerich 快照（与 aerich upgrade 写入账本的 content 同源同格式）。"""
    from aerich.utils import get_models_describe
    from tortoise import Tortoise

    from app.aerich_config import build_tortoise_config

    async def _run() -> str:
        await Tortoise.init(config=build_tortoise_config(f"sqlite:///{db_path}"))
        try:
            return json.dumps(get_models_describe(app))
        finally:
            await Tortoise.close_connections()

    return asyncio.run(_run())


#: 三方基线统一文件名（与 aerich 账本版本键一致）
BASELINE_FILENAME = "0_20261024125437_init.py"

DIALECTS_DIR = Path(__file__).resolve().parent.parent.parent / "migrations" / "dialects"


def _dialect_of(db_url: str) -> str:
    scheme = (db_url or "").split("://", 1)[0].lower()
    if scheme in ("mysql", "mariadb"):
        return "mysql"
    if scheme in ("postgres", "psycopg", "asyncpg"):
        return "postgres"
    return "sqlite"


def verify_installed_baseline_matches_dialect(db_url: str,
                                              models_dir: Path) -> Optional[str]:
    """核对 migrations/models/ 里装的**全部**迁移是否都是目标方言那份（md5 比对）。

    装错方言的后果：SQLite 基线在 MySQL/PG 上执行会直接报语法错误；反过来虽能跑，
    但 DDL 类型不匹配（例如 PG 的 SERIAL vs SQLite 的 AUTOINCREMENT）。在写账本之前
    拦住，比事后排查便宜得多。

    范围包含**增量迁移**（``1_*``、``2_*`` …），不只基线——只比基线的话，切方言后
    沿用旧方言的增量会被放行，upgrade 在 MySQL 上执行 SQLite 语法。
    """
    import hashlib

    dialect = _dialect_of(db_url)
    src_dir = DIALECTS_DIR / dialect
    src = src_dir / BASELINE_FILENAME
    installed = models_dir / BASELINE_FILENAME
    if not src.is_file():
        return f"方言基线不存在: {src}"
    if not installed.is_file():
        return (f"migrations/models/ 下找不到基线 {BASELINE_FILENAME}；"
                f"请先执行 select_dialect_baseline.py {dialect}")

    def _md5(p: Path) -> str:
        return hashlib.md5(p.read_bytes()).hexdigest()

    if _md5(src) != _md5(installed):
        other = [d.name for d in DIALECTS_DIR.iterdir() if d.is_dir()]
        return (
            f"当前安装的基线不是 {dialect} 方言（md5 不匹配: "
            f"installed={_md5(installed)[:8]} expected={_md5(src)[:8]}）；"
            f"请先执行 `python scripts/migrations/select_dialect_baseline.py {dialect}`"
            f"（可用方言: {', '.join(sorted(other))}）"
        )

    # 增量迁移同样要逐文件核对
    expected = {
        f.name: _md5(f) for f in src_dir.glob("*.py") if not f.name.startswith("__")
    }
    for name, want in sorted(expected.items()):
        target = models_dir / name
        if not target.is_file():
            return (f"migrations/models/ 缺少 {dialect} 方言的迁移 {name}；"
                    f"请先执行 select_dialect_baseline.py {dialect}")
        if _md5(target) != want:
            return (
                f"迁移 {name} 不是 {dialect} 方言版本（md5 不匹配）；"
                f"请先执行 `python scripts/migrations/select_dialect_baseline.py {dialect}`"
            )
    return None


def _dump_live_schema(db_url: str) -> dict:
    """用 Tortoise 连上真实库，导出 表->列 结构（跨方言，忽略 aerich 账本表）。"""
    from tortoise import Tortoise

    async def _run() -> dict:
        cfg = {
            "connections": {"default": db_url},
            "apps": {"models": {"models": ["app.models"], "default_connection": "default"}},
        }
        await Tortoise.init(config=cfg)
        try:
            conn = Tortoise.get_connection("default")
            dialect = getattr(conn.capabilities, "dialect", "")
            if dialect == "sqlite":
                rows = await conn.execute_query_dict(
                    "SELECT m.name AS t, p.name AS c FROM sqlite_master m "
                    "JOIN pragma_table_info(m.name) p WHERE m.type='table' "
                    "AND m.name NOT LIKE 'sqlite_%' AND m.name != 'aerich'")
            elif "mysql" in dialect or "maria" in dialect:
                rows = await conn.execute_query_dict(
                    "SELECT table_name AS t, column_name AS c FROM information_schema.columns "
                    "WHERE table_schema = DATABASE() AND table_name != 'aerich'")
            else:  # postgres 系
                rows = await conn.execute_query_dict(
                    "SELECT table_name AS t, column_name AS c FROM information_schema.columns "
                    "WHERE table_schema = current_schema() AND table_name != 'aerich'")
            out: dict = {}
            for r in rows:
                out.setdefault(str(r["t"]), set()).add(str(r["c"]))
            return out
        finally:
            await Tortoise.close_connections()

    return asyncio.run(_run())


def _expected_schema_from_models() -> dict:
    """从当前模型推断「应当存在」的表->列（Tortoise 元数据，不连库）。"""
    from tortoise import Tortoise

    async def _run() -> dict:
        cfg = {
            "connections": {"default": "sqlite://:memory:"},
            "apps": {"models": {"models": ["app.models"], "default_connection": "default"}},
        }
        await Tortoise.init(config=cfg)
        try:
            from tortoise.fields.relational import (
                BackwardFKRelation,
                BackwardOneToOneRelation,
                ManyToManyFieldInstance,
            )

            skip_types = (BackwardFKRelation, BackwardOneToOneRelation,
                          ManyToManyFieldInstance)
            out: dict = {}
            for model in Tortoise.apps["models"].values():
                table = model._meta.db_table
                if table == "aerich":
                    continue
                cols = set()
                for name, field in model._meta.fields_map.items():
                    # 反向关系与 M2M 不产生本表列；FK 在库里是 <name>_id
                    if isinstance(field, skip_types):
                        continue
                    cls_name = field.__class__.__name__
                    if cls_name in ("ForeignKeyFieldInstance",
                                    "OneToOneFieldInstance"):
                        cols.add(f"{name}_id")
                    elif name.startswith("_"):
                        # Tortoise 内部字段（如 JSONField 的 _data）不落库
                        continue
                    else:
                        cols.add(name)
                out[table] = cols
            return out
        finally:
            await Tortoise.close_connections()

    return asyncio.run(_run())


def verify_schema_matches_models(db_url: str) -> list:
    """核对库结构与模型。返回差异列表（空 = 一致）。

    只比「表与列是否齐备」：库中缺表/缺列是致命差异（基线化会把缺列的库
    错标为已对齐）；库中多出的列不阻断（可能来自手写脚本的增量，由迁移链
    在后续版本收敛）。
    """
    live = _dump_live_schema(db_url)
    expected = _expected_schema_from_models()
    problems = []
    for table, cols in sorted(expected.items()):
        if table not in live:
            problems.append(f"缺表: {table}")
            continue
        missing = sorted(cols - live[table])
        if missing:
            problems.append(f"{table} 缺列: {', '.join(missing)}")
    return problems


def main(db_path: str, migrations_dir: str, app: str = "models", fresh: bool = False,
         db_url: str = None) -> int:
    db = Path(db_path) if db_path else None
    if db_url is None:
        # 仅 SQLite 走文件路径；其它方言由 --url 传入 DSN，不检查文件
        if db is None or not db.is_file():
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

    if db_url is None:
        db_url = f"sqlite:///{db}"
    dialect = db_url.split("://", 1)[0].lower()
    if dialect in ("mariadb",):
        dialect = "mysql"
    if dialect not in AERICH_TABLE_DDL_BY_DIALECT:
        print(f"!! 不支持的数据库方言: {dialect}", file=sys.stderr)
        return 2

    if dialect == "sqlite":
        if db is None:
            print("!! SQLite 需要提供库文件路径或 sqlite:/// 形式的 --url", file=sys.stderr)
            return 2
        # 方言一致性：fresh 分支也要校验（装错方言时 --fresh 同样会把错的基线装进去）
        dialect_err = verify_installed_baseline_matches_dialect(
            db_url, Path(migrations_dir))
        if dialect_err:
            print(f"!! {dialect_err}", file=sys.stderr)
            return 4
        return _run_sqlite(db, db_url, baseline_file, app, fresh)

    # 非 SQLite：走 Tortoise（asyncpg / aiomysql），不依赖本地 sqlite3
    # fresh 同样要校验方言：装错的基线会让 upgrade 在目标库上直接失败
    dialect_err = verify_installed_baseline_matches_dialect(
        db_url, Path(migrations_dir))
    if dialect_err:
        print(f"!! {dialect_err}", file=sys.stderr)
        return 4
    problems = [] if fresh else verify_schema_matches_models(db_url)
    if problems:
        print("!! 库结构与模型不一致，拒绝写入基线：", file=sys.stderr)
        for item in problems:
            print(f"   - {item}", file=sys.stderr)
        return 3
    return asyncio.run(_run_async_dialect(db_url, dialect, baseline_file, app, fresh))


def _run_sqlite(db: Path, db_url: str, baseline_file: Path, app: str, fresh: bool) -> int:
    conn = sqlite3.connect(str(db))
    try:
        exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='aerich'"
        ).fetchone()
        if exists is None:
            conn.execute(AERICH_TABLE_DDL_BY_DIALECT["sqlite"])
            conn.commit()
            print("  已创建 aerich 账本表")
        else:
            print("  aerich 账本表已存在，跳过建表")

        if fresh:
            print("  --fresh：只创建账本表，不标记基线（upgrade 将应用基线迁移建表）")
            return 0

        problems = verify_schema_matches_models(db_url)
        if problems:
            print("!! 库结构与模型不一致，拒绝写入基线（写账本前必须对齐）：", file=sys.stderr)
            for item in problems:
                print(f"   - {item}", file=sys.stderr)
            print("   请先跑 scripts/migrate_v0_3_2_must_change_password.py 或手工补列后重试。",
                  file=sys.stderr)
            return 3

        already = conn.execute(
            "SELECT id FROM aerich WHERE version=? AND app=?", (baseline_file.name, app)
        ).fetchone()
        if already:
            print(f"  基线 {baseline_file.name} 已在账本中，跳过写入")
            return 0
        conn.execute(
            'INSERT INTO "aerich" ("version", "app", "content") VALUES (?, ?, ?)',
            (baseline_file.name, app, models_snapshot(str(db), app)),
        )
        conn.commit()
        print(f"  已写入基线: {baseline_file.name} (app={app})")
        return 0
    finally:
        conn.close()


async def _run_async_dialect(db_url: str, dialect: str, baseline_file: Path,
                             app: str, fresh: bool) -> int:
    """MySQL / PostgreSQL：用 Tortoise 建账本表并写基线行。"""
    from tortoise import Tortoise

    cfg = {
        "connections": {"default": db_url},
        "apps": {"models": {"models": ["app.models", "aerich.models"],
                            "default_connection": "default"}},
    }
    await Tortoise.init(config=cfg)
    try:
        conn = Tortoise.get_connection("default")
        ddl = AERICH_TABLE_DDL_BY_DIALECT[dialect]
        has = await conn.execute_query_dict(
            "SELECT table_name FROM information_schema.tables "
            f"WHERE table_name='aerich' AND table_schema="
            + ("DATABASE()" if dialect == "mysql" else "current_schema()")
        )
        if not has:
            await conn.execute_script(ddl)
            print("  已创建 aerich 账本表")
        else:
            print("  aerich 账本表已存在，跳过建表")

        if fresh:
            print("  --fresh：只创建账本表，不标记基线")
            return 0

        from aerich.utils import get_models_describe

        content = json.dumps(get_models_describe(app))
        rows = await conn.execute_query_dict(
            "SELECT id FROM aerich WHERE version=%s AND app=%s"
            if dialect == "mysql" else
            "SELECT id FROM aerich WHERE version=$1 AND app=$2",
            [baseline_file.name, app],
        )
        if rows:
            print(f"  基线 {baseline_file.name} 已在账本中，跳过写入")
            return 0
        if dialect == "mysql":
            await conn.execute_query(
                "INSERT INTO aerich (version, app, content) VALUES (%s, %s, %s)",
                [baseline_file.name, app, content])
        else:
            await conn.execute_query(
                "INSERT INTO aerich (version, app, content) VALUES ($1, $2, $3)",
                [baseline_file.name, app, content])
        print(f"  已写入基线: {baseline_file.name} (app={app})")
        return 0
    finally:
        await Tortoise.close_connections()


if __name__ == "__main__":
    argv = sys.argv[1:]
    fresh = "--fresh" in argv
    url_arg = None
    if "--url" in argv:
        i = argv.index("--url")
        if i + 1 >= len(argv):
            raise SystemExit("!! --url 需要连接串")
        url_arg = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    args = [a for a in argv if a != "--fresh"]
    if url_arg:
        if not args:
            print(__doc__)
            raise SystemExit(2)
        mig, app_name = args[0], (args[1] if len(args) > 1 else "models")
        raise SystemExit(main("", mig, app_name, fresh, db_url=url_arg))
    if len(args) < 2:
        print(__doc__)
        print("用法: baseline_existing_db.py <sqlite库路径> <迁移目录> [app名] [--fresh]")
        print("      baseline_existing_db.py --url <连接串> <迁移目录> [app名] [--fresh]")
        print("  --fresh  全新库：只创建账本表、不标记基线（随后 upgrade 应用基线迁移建表）")
        raise SystemExit(2)
    app_name = args[2] if len(args) > 2 else "models"
    raise SystemExit(main(args[0], args[1], app_name, fresh))
