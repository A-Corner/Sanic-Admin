#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
迁移链（aerich 方案 A）集成测试（SA-MIG-S1）。

三条链路，每条在独立子进程里完整跑完（Tortoise 是进程内单例，子进程
隔离保证每条链路从干净状态开始；子进程失败即测试失败）。

1. 全新库：基线脚本 --fresh（只建账本表）→ upgrade 应用基线迁移建业务表；
2. 存量库：generate_schemas（仅 app.models，模拟 aerich 前的生产库）→
   基线脚本打标 → upgrade 必须为 no-op 且账本对齐；
3. 基线脚本幂等（重复执行安全）。
"""

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MIGRATIONS_DIR = REPO / "migrations" / "models"
BASELINE_SCRIPT = REPO / "scripts" / "migrations" / "baseline_existing_db.py"
PYTHON = sys.executable

FRESH_BODY = '''
import asyncio, json, subprocess, sys
from tortoise import Tortoise
from app.aerich_config import build_tortoise_config
from aerich import Command

async def main():
    db = "__DB__"
    r = subprocess.run([sys.executable, "__SCRIPT__", db, "__MIGDIR__", "--fresh"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-300:]

    config = build_tortoise_config("sqlite:///" + db)
    command = Command(config, app="models", location="__MIGDIR__")
    await command.init()
    migrated = await command.upgrade(run_in_transaction=False)
    assert migrated, "全新库 upgrade 应应用基线迁移"

    await Tortoise.init(config=config)
    conn = Tortoise.get_connection("default")
    tables = {r["name"] for r in (await conn.execute_query_dict(
        "SELECT name FROM sqlite_master WHERE type='table'"))}
    for expected in ("account", "role", "system_setting", "profile", "aerich"):
        assert expected in tables, f"表 {expected} 应存在"
    ledger = await conn.execute_query_dict("SELECT version, app FROM aerich")
    assert any(v["version"].startswith("0_") for v in ledger)

asyncio.run(main())
'''

EXISTING_BODY = '''
import asyncio, json, subprocess, sys
from tortoise import Tortoise
from app.aerich_config import build_tortoise_config
from aerich import Command

async def main():
    db = "__DB__"
    legacy = {"connections": {"default": "sqlite:///" + db},
              "apps": {"models": {"models": ["app.models"],
                                   "default_connection": "default"}}}
    await Tortoise.init(config=legacy)
    await Tortoise.generate_schemas(safe=False)
    conn = Tortoise.get_connection("default")
    pre = {r["name"] for r in (await conn.execute_query_dict(
        "SELECT name FROM sqlite_master WHERE type='table'"))}
    await Tortoise.close_connections()
    assert "account" in pre and "aerich" not in pre, f"前置不符: {pre}"

    r = subprocess.run([sys.executable, "__SCRIPT__", db, "__MIGDIR__"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-300:]

    ledger = await conn.execute_query_dict("SELECT version, app FROM aerich")
    assert any(v["version"].startswith("0_") for v in ledger)

    config = build_tortoise_config("sqlite:///" + db)
    command = Command(config, app="models", location="__MIGDIR__")
    await command.init()
    migrated = await command.upgrade(run_in_transaction=False)
    assert migrated == [], f"存量库 upgrade 应为 no-op，实际: {migrated}"

asyncio.run(main())
'''

IDEMPOTENT_BODY = '''
import asyncio, subprocess, sys
from tortoise import Tortoise

async def main():
    db = "__DB__"
    legacy = {"connections": {"default": "sqlite:///" + db},
              "apps": {"models": {"models": ["app.models"],
                                   "default_connection": "default"}}}
    await Tortoise.init(config=legacy)
    await Tortoise.generate_schemas(safe=False)
    await Tortoise.close_connections()
    for i in range(2):
        r = subprocess.run([sys.executable, "__SCRIPT__", db, "__MIGDIR__"],
                           capture_output=True, text=True)
        assert r.returncode == 0, f"第 {i+1} 次失败: {r.stderr[-200:]}"

asyncio.run(main())
'''


def _stage(body: str, db_file) -> None:
    body = (body.replace("__DB__", str(db_file))
                .replace("__SCRIPT__", str(BASELINE_SCRIPT))
                .replace("__MIGDIR__", str(MIGRATIONS_DIR)))
    body = "\n".join(l for l in body.split("\n") if l.strip() != "asyncio.run(main())")
    code = "import asyncio, json, subprocess, sys\n\nasync def main():\n" + "\n".join(
        ("    " + line if line.strip() else line) for line in body.split("\n"))
    code += "\nasyncio.run(main())\n"
    result = subprocess.run([PYTHON, "-c", code], capture_output=True,
                            text=True, timeout=120, cwd=str(REPO))
    assert result.returncode == 0, (
        f"--- stdout ---\n{result.stdout[-600:]}\n--- stderr ---\n{result.stderr[-600:]}")


def test_fresh_db_flow(tmp_path):
    _stage(FRESH_BODY, tmp_path / "fresh.sqlite3")


def test_existing_db_baseline_then_noop_upgrade(tmp_path):
    _stage(EXISTING_BODY, tmp_path / "existing.sqlite3")


def test_baseline_script_is_idempotent(tmp_path):
    _stage(IDEMPOTENT_BODY, tmp_path / "idem.sqlite3")
