#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
迁移守门脚本：迁移链产出的表结构与当前模型不一致（模型改了没生成迁移 / 迁移写错）-> 退出码 1。

做法（全程在临时 SQLite 里，不碰真实库、不写仓库）：
  1. 临时库 A：创建 aerich 账本表，执行 upgrade 应用 migrations/ 下全部迁移；
  2. 临时库 B：按当前 app.models 执行 generate_schemas（模型的「标准答案」）；
  3. 逐表对比 A、B 的列（类型/非空/默认值/主键）、索引、外键；有差异即失败。

为什么不用 ``aerich migrate`` 做守门：aerich 的比较基准是账本里存的模型快照，
而 upgrade 会用「当前模型」写快照，所以在 CI 里先 upgrade 再 migrate 永远判定一致（空转）。

退出码：0 一致；1 有漂移；2 脚本自身出错（读不到迁移目录、跑不通都算失败，不会静默通过）。
用法：python scripts/check_migrations.py [迁移目录，默认 migrations]
"""

import asyncio
import importlib.util
import sqlite3
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

IGNORED_TABLES = {"aerich"}
# 不做类型归一：BOOLEAN 与 INT 在 SQLite 里虽同为整数存储，但归一成 INT 会
# 掩盖真实的类型变更（例如把某列从 INT 改成 BOOLEAN）。手写补列脚本与 aerich
# 基线若产生该差异，应当暴露出来由人判断，而不是静默抹平。
TYPE_ALIASES: dict = {}


def dump_sqlite_schema(db_file) -> dict:
    """导出 SQLite 库的结构快照（表 -> 列/索引/外键），忽略 aerich 账本表与 sqlite 内部表。"""
    conn = sqlite3.connect(str(db_file))
    try:
        tables = [
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            if r[0] not in IGNORED_TABLES
        ]
        snapshot = {}
        for t in sorted(tables):
            cols = sorted(
                (r[1], TYPE_ALIASES.get(r[2].upper(), r[2].upper()), r[3], r[4], r[5])
                for r in conn.execute(f'PRAGMA table_info("{t}")')
            )
            indexes = []
            for idx in conn.execute(f'PRAGMA index_list("{t}")'):
                idx_cols = tuple(r[2] for r in conn.execute(f'PRAGMA index_info("{idx[1]}")'))
                indexes.append((bool(idx[2]), idx_cols))
            fks = sorted((r[2], r[3], r[4], r[6]) for r in conn.execute(f'PRAGMA foreign_key_list("{t}")'))
            snapshot[t] = {"columns": cols, "indexes": sorted(indexes), "foreign_keys": fks}
        return snapshot
    finally:
        conn.close()


def diff_schemas(migrated: dict, expected: dict) -> list:
    """返回人类可读的差异列表；空列表表示一致。"""
    problems = []
    for t in sorted(set(migrated) | set(expected)):
        if t not in migrated:
            problems.append(f"表 {t}: 模型有、迁移链没有")
        elif t not in expected:
            problems.append(f"表 {t}: 迁移链有、模型没有")
        else:
            for key in ("columns", "indexes", "foreign_keys"):
                if migrated[t][key] != expected[t][key]:
                    only_m = [x for x in migrated[t][key] if x not in expected[t][key]]
                    only_e = [x for x in expected[t][key] if x not in migrated[t][key]]
                    problems.append(f"表 {t}.{key}: 仅迁移链={only_m} 仅模型={only_e}")
    return problems


def check_dialect_baselines(repo: Path = None) -> list:
    """检查三份方言基线的迁移文件名集合是否一致（纯文件检查，CI 用）。

    文件名是 aerich 的版本键：若三份方言基线的文件名不一致，切方言后账本里
    记录的版本名与目录里的文件名对不上，upgrade 会把基线当成未应用而重复建表。
    """
    repo = repo or Path(__file__).resolve().parent.parent
    dialects_dir = repo / "migrations" / "dialects"
    if not dialects_dir.is_dir():
        return [f"方言基线目录不存在: {dialects_dir}"]
    problems = []
    seen = {}
    for d in sorted(p for p in dialects_dir.iterdir() if p.is_dir()):
        names = {f.name for f in d.glob("*.py") if not f.name.startswith("__")}
        seen[d.name] = names
    if not seen:
        return ["方言基线目录为空"]
    reference = next(iter(seen.values()))
    for dialect, names in seen.items():
        if names != reference:
            problems.append(
                f"方言基线文件名不一致: {dialect}={sorted(names)} "
                f"vs {sorted(reference)}"
            )
    # 与 migrations/models/ 里实际安装的也要对得上。
    # 口径必须与上面一致：比较**全部**迁移文件名，不能只取 0_*_init.py——
    # 增量迁移（1_*、2_* …）也是账本的版本键，漏掉它们会让「models/ 缺一条增量」
    # 这种真实错位看起来像「一致」。
    models_dir = repo / "migrations" / "models"
    installed = {f.name for f in models_dir.glob("*.py") if not f.name.startswith("__")}
    for dialect, names in seen.items():
        if installed and names != installed:
            missing = sorted(names - installed)
            extra = sorted(installed - names)
            detail = []
            if missing:
                detail.append(f"models/ 缺少 {missing}")
            if extra:
                detail.append(f"models/ 多出 {extra}")
            problems.append(
                f"{dialect} 迁移文件名 {sorted(names)} 与 migrations/models/ "
                f"实际安装的 {sorted(installed)} 不一致（账本版本键会错位；"
                + "；".join(detail) + "）"
            )
            break
    return problems


def _create_ledger_table(db_file: Path) -> None:
    """复用基线脚本里的账本表 DDL，避免两份定义漂移。"""
    spec = importlib.util.spec_from_file_location(
        "baseline_existing_db", REPO / "scripts" / "migrations" / "baseline_existing_db.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    conn = sqlite3.connect(str(db_file))
    try:
        conn.execute(mod.AERICH_TABLE_DDL)
        conn.commit()
    finally:
        conn.close()


async def check(migrations_dir: Path) -> int:
    from aerich import Command
    from tortoise import Tortoise

    from app.aerich_config import build_tortoise_config

    with tempfile.TemporaryDirectory(prefix="check-migrations-") as tmp:
        db_a = Path(tmp) / "migrated.sqlite3"
        db_b = Path(tmp) / "models.sqlite3"
        db_a.touch()
        _create_ledger_table(db_a)

        # A：迁移链
        command = Command(build_tortoise_config(f"sqlite:///{db_a}"), app="models", location=str(migrations_dir))
        try:
            await command.init()
            await command.upgrade(run_in_transaction=False)
        finally:
            await Tortoise.close_connections()

        # B：当前模型
        await Tortoise.init(db_url=f"sqlite:///{db_b}", modules={"models": ["app.models"]})
        try:
            await Tortoise.generate_schemas()
        finally:
            await Tortoise.close_connections()

        migrated, expected = dump_sqlite_schema(db_a), dump_sqlite_schema(db_b)
        if not expected:
            raise RuntimeError("模型侧结构为空，守门无效")
        problems = diff_schemas(migrated, expected)

    if problems:
        print("!! 迁移链与当前模型不一致（需要 aerich migrate 生成新迁移，或修正迁移）：")
        for p in problems:
            print("   - " + p)
        return 1
    print(f"OK 迁移链与当前模型一致（{len(expected)} 张表）")
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    mig = Path(argv[0]) if argv else REPO / "migrations"
    if not (mig / "models").is_dir():
        print(f"!! 迁移目录不存在或无 models 子目录: {mig}", file=sys.stderr)
        return 2

    # 先做纯文件检查：三份方言基线的文件名集合必须一致（F3 接入 CI）
    dialect_problems = check_dialect_baselines()
    if dialect_problems:
        print("!! 方言基线文件名不一致：", file=sys.stderr)
        for item in dialect_problems:
            print(f"   - {item}", file=sys.stderr)
        return 1

    try:
        return asyncio.run(check(mig))
    except Exception as exc:  # 跑不通必须报错，不能静默通过
        print(f"!! 检查失败（脚本自身错误）: {exc!r}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
