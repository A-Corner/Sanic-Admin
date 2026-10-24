#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
迁移链（aerich 方案 A）集成测试（SA-MIG-S1 / S2）。

Tortoise 是进程内单例，所有涉及 Tortoise/aerich 的步骤都放进独立子进程跑
（失败即测试失败）；表结构对比用纯 sqlite3 在测试进程里完成。

S1 链路：
  1. 全新库：基线脚本 --fresh（只建账本表）→ upgrade 应用基线迁移建业务表；
  2. 存量库：generate_schemas → 基线脚本打标 → upgrade 必须为 no-op；
  3. 基线脚本幂等。

S2 正向对照：
  (a) 新库 upgrade 后表结构 == 模型 generate_schemas 的结构；
  (b) 模型与迁移链不一致时 scripts/check_migrations.py 退出码非 0
      （并有一条「一致时退出码为 0」的对照，证明守门不是恒红/恒绿）；
  (c) v0.3.1 形态库（无 must_change_password 列）依次：手写迁移脚本 → 基线化 →
      upgrade，全部成功且最终表结构一致；并有一条「不跑手写脚本」的反例，
      证明结构对比能抓出缺列。
"""

import copy
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MIGRATIONS_DIR = REPO / "migrations" / "models"
MIGRATIONS_ROOT = REPO / "migrations"
BASELINE_SCRIPT = REPO / "scripts" / "migrations" / "baseline_existing_db.py"
HANDWRITTEN_SCRIPT = REPO / "scripts" / "migrate_v0_3_2_must_change_password.py"
CHECK_SCRIPT = REPO / "scripts" / "check_migrations.py"
PYTHON = sys.executable
TEST_ADMIN_PASSWORD = "Mig-Test-Initial-Pass-1"


def _load_check_module():
    spec = importlib.util.spec_from_file_location("check_migrations", CHECK_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


check_migrations = _load_check_module()


def _env(db_file) -> dict:
    env = dict(os.environ)
    env.update(
        {
            "SANIC_ENV": "development",
            "DATABASE_URL": f"sqlite:///{db_file}",
            "DB_URL": f"sqlite:///{db_file}",
            "INITIAL_ADMIN_PASSWORD": TEST_ADMIN_PASSWORD,
        }
    )
    return env


def _run(args, db_file, timeout=180):
    result = subprocess.run([PYTHON, *args], capture_output=True, text=True, timeout=timeout, cwd=str(REPO), env=_env(db_file))
    return result


def _run_ok(args, db_file):
    result = _run(args, db_file)
    assert result.returncode == 0, (
        f"{args} 失败 rc={result.returncode}\n--- stdout ---\n{result.stdout[-800:]}\n--- stderr ---\n{result.stderr[-800:]}"
    )
    return result


# 子进程里执行的 Tortoise / aerich 步骤（argv: db 迁移目录）
GENERATE_CODE = """
import asyncio, sys
from tortoise import Tortoise
async def main():
    await Tortoise.init(db_url="sqlite:///" + sys.argv[1], modules={"models": ["app.models"]})
    await Tortoise.generate_schemas(safe=False)
    await Tortoise.close_connections()
asyncio.run(main())
"""

UPGRADE_CODE = """
import asyncio, json, sys
from aerich import Command
from tortoise import Tortoise
from app.aerich_config import build_tortoise_config
async def main():
    command = Command(build_tortoise_config("sqlite:///" + sys.argv[1]), app="models", location=sys.argv[2])
    await command.init()
    try:
        print("MIGRATED=" + json.dumps(await command.upgrade(run_in_transaction=False)))
    finally:
        await Tortoise.close_connections()
asyncio.run(main())
"""

# 在迁移目录副本上执行 aerich migrate：返回空串 = 账本快照与当前模型无差异
MIGRATE_CODE = """
import asyncio, sys
from aerich import Command
from tortoise import Tortoise
from app.aerich_config import build_tortoise_config
async def main():
    command = Command(build_tortoise_config("sqlite:///" + sys.argv[1]), app="models", location=sys.argv[2])
    await command.init()
    try:
        print("GENERATED=[" + await command.migrate("probe") + "]")
    finally:
        await Tortoise.close_connections()
asyncio.run(main())
"""

# 造 v0.3.1 形态的库：完整建表 + 初始管理员（口令仍是交付口令）→ 删掉 must_change_password 列
LEGACY_V031_CODE = """
import asyncio, sqlite3, sys
from tortoise import Tortoise
from app.auth.authentication import create_initial_admin_account
async def main():
    await Tortoise.init(db_url="sqlite:///" + sys.argv[1], modules={"models": ["app.models"]})
    await Tortoise.generate_schemas(safe=False)
    await create_initial_admin_account()
    await Tortoise.close_connections()
    conn = sqlite3.connect(sys.argv[1])
    conn.execute("UPDATE account SET must_change_password = 0")
    conn.execute("ALTER TABLE account DROP COLUMN must_change_password")
    conn.commit()
    conn.close()
asyncio.run(main())
"""


def _generated(stdout: str) -> str:
    line = [ln for ln in stdout.splitlines() if ln.startswith("GENERATED=[")][-1]
    return line[len("GENERATED=[") : -1]


def _migrated(stdout: str) -> list:
    line = [ln for ln in stdout.splitlines() if ln.startswith("MIGRATED=")][-1]
    return json.loads(line[len("MIGRATED=") :])


def _expected_schema(tmp_path) -> dict:
    """模型的标准答案：当前 app.models 直接 generate_schemas 得到的结构。"""
    ref = tmp_path / "reference.sqlite3"
    _run_ok(["-c", GENERATE_CODE, str(ref)], ref)
    schema = check_migrations.dump_sqlite_schema(ref)
    assert len(schema) >= 10 and "account" in schema, f"标准答案结构异常: {sorted(schema)}"
    return schema


# ------------------------------------------------------------------ S1 链路


def test_fresh_db_flow(tmp_path):
    db = tmp_path / "fresh.sqlite3"
    _run_ok([str(BASELINE_SCRIPT), str(db), str(MIGRATIONS_DIR), "--fresh"], db)
    out = _run_ok(["-c", UPGRADE_CODE, str(db), str(MIGRATIONS_ROOT)], db).stdout
    assert _migrated(out), "全新库 upgrade 应应用基线迁移"
    conn = sqlite3.connect(str(db))
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    ledger = conn.execute("SELECT version FROM aerich").fetchall()
    conn.close()
    for expected in ("account", "role", "system_setting", "profile", "aerich"):
        assert expected in tables, f"表 {expected} 应存在"
    assert any(v[0].startswith("0_") for v in ledger)


def test_existing_db_baseline_then_noop_upgrade(tmp_path):
    db = tmp_path / "existing.sqlite3"
    _run_ok(["-c", GENERATE_CODE, str(db)], db)
    conn = sqlite3.connect(str(db))
    pre = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert "account" in pre and "aerich" not in pre, f"前置不符: {pre}"

    _run_ok([str(BASELINE_SCRIPT), str(db), str(MIGRATIONS_DIR)], db)
    out = _run_ok(["-c", UPGRADE_CODE, str(db), str(MIGRATIONS_ROOT)], db).stdout
    assert _migrated(out) == [], f"存量库 upgrade 应为 no-op，实际: {out}"


def test_baseline_script_is_idempotent(tmp_path):
    db = tmp_path / "idem.sqlite3"
    _run_ok(["-c", GENERATE_CODE, str(db)], db)
    for _ in range(2):
        _run_ok([str(BASELINE_SCRIPT), str(db), str(MIGRATIONS_DIR)], db)
    conn = sqlite3.connect(str(db))
    count = conn.execute("SELECT COUNT(*) FROM aerich").fetchone()[0]
    conn.close()
    assert count == 1


# ------------------------------------------------------------------ S2 (a)


def test_a_fresh_upgrade_schema_matches_models(tmp_path):
    db = tmp_path / "fresh-a.sqlite3"
    _run_ok([str(BASELINE_SCRIPT), str(db), str(MIGRATIONS_DIR), "--fresh"], db)
    _run_ok(["-c", UPGRADE_CODE, str(db), str(MIGRATIONS_ROOT)], db)

    migrated = check_migrations.dump_sqlite_schema(db)
    expected = _expected_schema(tmp_path)
    assert check_migrations.diff_schemas(migrated, expected) == []
    # 新基线必须带 must_change_password（旧基线缺这一列）
    assert any(c[0] == "must_change_password" for c in migrated["account"]["columns"])

    # 正向对照：把一列从迁移结果里抹掉，对比函数必须报差异
    broken = json.loads(json.dumps(migrated))
    broken["account"]["columns"] = [c for c in broken["account"]["columns"] if c[0] != "must_change_password"]
    assert check_migrations.diff_schemas(broken, expected), "结构对比对缺列无感知，对照无效"


# ------------------------------------------------------------------ S2 (b)


def test_b_check_migrations_passes_when_consistent(tmp_path):
    result = _run([str(CHECK_SCRIPT)], tmp_path / "unused.sqlite3")
    assert result.returncode == 0, result.stdout[-600:] + result.stderr[-600:]


def test_b_check_migrations_fails_when_models_ahead_of_migrations(tmp_path):
    """模型比迁移链多一列（等价于「改了模型没生成迁移」）：守门必须非 0 退出。"""
    behind = tmp_path / "migrations"
    shutil.copytree(MIGRATIONS_ROOT, behind)
    baseline = next((behind / "models").glob("0_*_init.py"))
    text = baseline.read_text()
    assert '"must_change_password" INT NOT NULL  DEFAULT 0' in text, "基线格式变化，更新本对照"
    text = text.replace(',\n    "must_change_password" INT NOT NULL  DEFAULT 0', "")
    assert "must_change_password" not in text
    baseline.write_text(text)

    result = _run([str(CHECK_SCRIPT), str(behind)], tmp_path / "unused.sqlite3")
    assert result.returncode == 1, f"守门应判漂移(1)，实际 {result.returncode}\n{result.stdout[-600:]}{result.stderr[-600:]}"
    assert "must_change_password" in result.stdout


def test_b_check_migrations_errors_when_migrations_missing(tmp_path):
    """读不到迁移目录时必须报错，不能给出「一致」。"""
    result = _run([str(CHECK_SCRIPT), str(tmp_path / "nope")], tmp_path / "unused.sqlite3")
    assert result.returncode == 2


# ------------------------------------------------------------------ S2 (c)


def _make_v031_db(tmp_path, name):
    db = tmp_path / name
    _run_ok(["-c", LEGACY_V031_CODE, str(db)], db)
    conn = sqlite3.connect(str(db))
    cols = [r[1] for r in conn.execute("PRAGMA table_info(account)")]
    n_admin = conn.execute("SELECT COUNT(*) FROM account").fetchone()[0]
    conn.close()
    assert "must_change_password" not in cols and n_admin == 1, "v0.3.1 形态前置不成立"
    return db


def test_c_v031_db_handwritten_then_baseline_then_upgrade(tmp_path):
    db = _make_v031_db(tmp_path, "v031.sqlite3")

    # 1) 手写脚本：补列并置位（口令仍等于交付口令的管理员）
    _run_ok([str(HANDWRITTEN_SCRIPT)], db)
    conn = sqlite3.connect(str(db))
    flags = [r[0] for r in conn.execute("SELECT must_change_password FROM account WHERE is_admin = 1")]
    conn.close()
    assert flags == [1], f"管理员应被置位 must_change_password: {flags}"

    # 2) 基线化
    _run_ok([str(BASELINE_SCRIPT), str(db), str(MIGRATIONS_DIR)], db)

    # 3) upgrade：no-op，不报错
    out = _run_ok(["-c", UPGRADE_CODE, str(db), str(MIGRATIONS_ROOT)], db).stdout
    assert _migrated(out) == []

    # 4) 表结构与模型一致
    assert check_migrations.diff_schemas(check_migrations.dump_sqlite_schema(db), _expected_schema(tmp_path)) == []

    # 5) 账本快照有效：在迁移目录副本上 aerich migrate 应「无变化」
    mig_copy = tmp_path / "mig-copy"
    shutil.copytree(MIGRATIONS_ROOT, mig_copy)
    gen = _run_ok(["-c", MIGRATE_CODE, str(db), str(mig_copy)], db).stdout
    assert _generated(gen) == "", f"基线快照无效，migrate 误判有变化: {gen[-400:]}"


def test_c_without_handwritten_script_baseline_is_refused(tmp_path):
    """反例：v0.3.1 库不跑手写脚本直接基线化——**基线脚本必须拒绝写入账本**。

    v0.3.2 整改第 2 项：基线化前先核对库结构与模型，缺列时以非 0 退出（rc=3），
    不写账本。若放行，账本会宣称已对齐而库里实际缺列，之后 `aerich upgrade`
    永远不补（S2 复审的 P1）。本测试同时证明 (c) 的三步顺序不是形式要求。
    """
    db = _make_v031_db(tmp_path, "v031-skip.sqlite3")
    result = subprocess.run(
        [PYTHON, str(BASELINE_SCRIPT), str(db), str(MIGRATIONS_DIR)],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 3, (
        f"缺列时必须 rc=3 拒绝基线化，实际 rc={result.returncode}\n"
        f"stdout={result.stdout[-400:]}\nstderr={result.stderr[-400:]}"
    )
    assert "must_change_password" in result.stderr, (
        f"拒绝理由应点名缺失的列: {result.stderr[-400:]}"
    )
    # 账本表即便被建，也不应写入基线行（否则 upgrade 会误判已对齐）
    conn = sqlite3.connect(str(db))
    try:
        rows = conn.execute("SELECT version FROM aerich").fetchall()
    finally:
        conn.close()
    assert rows == [], f"拒绝时不应写入任何基线行，实际: {rows}"


# ---------------------------------------------------------------------------
# 整改第 8 项：守门的三组变异反例
# 证明 diff_schemas 能识别「类型 / 索引 / 默认值」这三类模型漂移，
# 而不是只对缺表缺列报警。
# ---------------------------------------------------------------------------

def _snapshot_of(models_db: Path) -> dict:
    """用给定库文件的真实结构做快照（与 _expected_schema 同源同格式）。"""
    return check_migrations.dump_sqlite_schema(models_db)


def _baseline_of(tmp_path, name: str) -> Path:
    """生成一个「当前模型」库，用于取变异基底。"""
    db = tmp_path / name
    _run_ok(["-c", GENERATE_CODE, str(db)], db)
    return db


def test_mutation_column_type_change_is_detected(tmp_path):
    """变异：改一个列的类型 —— 守门必须报错（列格式: 名称/类型/非空/默认/主键）。"""
    base = _snapshot_of(_baseline_of(tmp_path, "type-base.sqlite3"))
    expected = _expected_schema(tmp_path)
    assert check_migrations.diff_schemas(base, expected) == []

    mutated = copy.deepcopy(base)
    cols = mutated["account"]["columns"]
    i = next(k for k, c in enumerate(cols) if c[0] == "username")
    name, _type, notnull, default, pk = cols[i]
    cols[i] = (name, "TEXT(999)", notnull, default, pk)

    diffs = check_migrations.diff_schemas(mutated, expected)
    assert diffs, "类型变化必须被守门发现"


def test_mutation_index_change_is_detected(tmp_path):
    """变异：删掉一个索引 —— 守门必须报错。"""
    base = _snapshot_of(_baseline_of(tmp_path, "idx-base.sqlite3"))
    expected = _expected_schema(tmp_path)
    table = next(t for t, v in base.items() if v["indexes"])

    mutated = copy.deepcopy(base)
    mutated[table]["indexes"] = mutated[table]["indexes"][1:]

    diffs = check_migrations.diff_schemas(mutated, expected)
    assert diffs, "索引变化必须被守门发现"


def test_mutation_default_value_change_is_detected(tmp_path):
    """变异：改一个列的默认值 —— 守门必须报错。"""
    base = _snapshot_of(_baseline_of(tmp_path, "dflt-base.sqlite3"))
    expected = _expected_schema(tmp_path)

    mutated = copy.deepcopy(base)
    cols = mutated["system_setting"]["columns"]
    i = next(k for k, c in enumerate(cols) if c[0] == "category" and c[3])
    name, ctype, notnull, _default, pk = cols[i]
    cols[i] = (name, ctype, notnull, "'MUTATED'", pk)

    diffs = check_migrations.diff_schemas(mutated, expected)
    assert diffs, "默认值变化必须被守门发现"


def test_dialect_baselines_share_one_filename():
    """三份方言基线的文件名必须一致，且与 migrations/models/ 里安装的那份对得上。

    文件名是 aerich 的版本键：不一致会让切换方言后的 upgrade 把基线当成未应用，
    去重建已经存在的表（复审整改第 2 项）。
    """
    problems = check_migrations.check_dialect_baselines()
    assert problems == [], f"方言基线文件名不一致: {problems}"


def test_check_dialect_baselines_detects_mismatch(tmp_path):
    """正向对照（F3）：方言目录里文件名集合不一致时，检查必须报错。

    用临时仓库构造「sqlite 与 mysql 基线文件名不同」，断言 check_dialect_baselines
    返回非空问题列表——证明该检查的判定条件确实有效，而不是恒返回空。
    """
    fake_repo = tmp_path / "repo"
    dialects = fake_repo / "migrations" / "dialects"
    for name in ("sqlite", "mysql", "postgres"):
        (dialects / name).mkdir(parents=True)
    (dialects / "sqlite" / "0_aaa_init.py").write_text("# a\n")
    (dialects / "mysql" / "0_bbb_init.py").write_text("# b\n")      # 故意不一致
    (dialects / "postgres" / "0_aaa_init.py").write_text("# c\n")
    (fake_repo / "migrations" / "models").mkdir(parents=True)

    problems = check_migrations.check_dialect_baselines(repo=fake_repo)
    assert problems, "文件名不一致时必须报错"
    assert any("不一致" in p for p in problems), f"错误信息应点明不一致: {problems}"


def test_check_dialect_baselines_passes_on_real_repo():
    """真实仓库的方言基线文件名应一致（与上一条构成正反对照）。"""
    assert check_migrations.check_dialect_baselines() == []


def test_dialect_mismatch_is_rejected(tmp_path):
    """正向对照（F2）：装的基线与目标方言不符时，基线化必须拒绝（rc=4）。

    构造：SQLite 形态的存量库 + 把 mysql 方言基线装进 migrations/models/，
    然后按 sqlite 的 DATABASE_URL 跑基线化 —— md5 校验必须拦下。
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "baseline_existing_db", BASELINE_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # 正例：真实仓库里 sqlite 方言的基线应与自身 md5 一致
    models_dir = REPO / "migrations" / "models"
    err = mod.verify_installed_baseline_matches_dialect(
        f"sqlite:///{tmp_path/'x.db'}", models_dir)
    # 若当前装的是 sqlite 基线则应为 None；否则会提示需 select_dialect_baseline
    assert err is None or "select_dialect_baseline" in err

    # 反例：拿 mysql 的基线冒充 sqlite
    wrong_dir = tmp_path / "wrong"
    wrong_dir.mkdir()
    import shutil
    shutil.copyfile(REPO / "migrations" / "dialects" / "mysql" / "0_20261024125437_init.py",
                    wrong_dir / "0_20261024125437_init.py")
    err2 = mod.verify_installed_baseline_matches_dialect(
        f"sqlite:///{tmp_path/'x.db'}", wrong_dir)
    assert err2 is not None, "装错方言必须报错"
    assert "select_dialect_baseline" in err2, f"错误信息应给出修复命令: {err2}"
