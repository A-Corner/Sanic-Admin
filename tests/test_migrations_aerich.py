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

import pytest

REPO = Path(__file__).resolve().parent.parent
MIGRATIONS_DIR = REPO / "migrations" / "models"
MIGRATIONS_ROOT = REPO / "migrations"
BASELINE_SCRIPT = REPO / "scripts" / "migrations" / "baseline_existing_db.py"
HANDWRITTEN_SCRIPT = REPO / "scripts" / "migrate_v0_3_2_must_change_password.py"
CHECK_SCRIPT = REPO / "scripts" / "check_migrations.py"
SELECT_SCRIPT = REPO / "scripts" / "migrations" / "select_dialect_baseline.py"
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
    """
    存量库（表已存在、没有账本）基线化后，upgrade 不应破坏结构。

    本轮起迁移链不只一条基线（还有 specgen 增量），所以 upgrade **会**记录增量。
    但存量库的表是用**当前模型**建的，已经含 customer/orders，增量的
    ``CREATE TABLE IF NOT EXISTS`` 是空操作——断言点因此从「一条都不跑」改为
    「跑完结构与基线化时一致」。语义上仍然守住「不破坏存量库」这个目的。
    """
    db = tmp_path / "existing.sqlite3"
    _run_ok(["-c", GENERATE_CODE, str(db)], db)
    conn = sqlite3.connect(str(db))
    pre = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert "account" in pre and "aerich" not in pre, f"前置不符: {pre}"
    pre_schema = check_migrations.dump_sqlite_schema(db)

    _run_ok([str(BASELINE_SCRIPT), str(db), str(MIGRATIONS_DIR)], db)
    out = _run_ok(["-c", UPGRADE_CODE, str(db), str(MIGRATIONS_ROOT)], db).stdout
    # 基线之外只允许出现增量迁移；若冒出别的版本号，说明迁移链被改动过
    extra = [m for m in _migrated(out) if not m.startswith("1_")]
    assert extra == [], f"upgrade 应只应用 specgen 增量，实际: {out}"

    post_schema = check_migrations.dump_sqlite_schema(db)
    assert post_schema == pre_schema, "存量库 upgrade 改变了表结构"


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

    # 3) upgrade：基线化之后只剩 specgen 增量待应用（存量库表已含它创建的表，
    #    IF NOT EXISTS 使其为空操作）；不应报错，也不应冒出其它版本
    out = _run_ok(["-c", UPGRADE_CODE, str(db), str(MIGRATIONS_ROOT)], db).stdout
    assert [m for m in _migrated(out) if not m.startswith("1_")] == [], out

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
    """方言一致性校验（F2）：装错方言必须报错，正例必须严格返回 None。

    覆盖 main() 的 rc=4 路径（sqlite 与 mysql 两种冒充），以及
    verify_installed_baseline_matches_dialect 的直接调用。
    """
    import importlib.util
    import shutil
    import subprocess

    spec = importlib.util.spec_from_file_location(
        "baseline_existing_db", BASELINE_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    baseline_name = mod.BASELINE_FILENAME
    models_dir = REPO / "migrations" / "models"
    dialects_dir = REPO / "migrations" / "dialects"

    # --- 正例：装的是 sqlite 基线，按 sqlite URL 校验应严格为 None ---
    sqlite_src = dialects_dir / "sqlite" / baseline_name
    if sqlite_src.is_file() and (models_dir / baseline_name).is_file():
        if sqlite_src.read_bytes() == (models_dir / baseline_name).read_bytes():
            assert mod.verify_installed_baseline_matches_dialect(
                f"sqlite:///{tmp_path/'x.db'}", models_dir) is None, \
                "装的正是 sqlite 基线时，校验必须返回 None"

    # --- 反例 1：mysql 基线冒充 sqlite ---
    wrong = tmp_path / "wrong-sqlite"
    wrong.mkdir()
    shutil.copyfile(dialects_dir / "mysql" / baseline_name, wrong / baseline_name)
    err = mod.verify_installed_baseline_matches_dialect(
        f"sqlite:///{tmp_path/'y.db'}", wrong)
    assert err is not None and "select_dialect_baseline" in err

    # --- 反例 2：sqlite 基线冒充 mysql ---
    wrong2 = tmp_path / "wrong-mysql"
    wrong2.mkdir()
    shutil.copyfile(dialects_dir / "sqlite" / baseline_name, wrong2 / baseline_name)
    err2 = mod.verify_installed_baseline_matches_dialect(
        "mysql://u:p@127.0.0.1:3306/db", wrong2)
    assert err2 is not None and "select_dialect_baseline" in err2

    # --- main() 的 rc=4 路径：用 sqlite 库 + 装 mysql 基线 ---
    db = tmp_path / "rc4.sqlite3"
    _run_ok(["-c", GENERATE_CODE, str(db)], db)
    # 在临时克隆的仓库里跑 main()，避免改动真实 migrations/models
    fake_repo = tmp_path / "fakerepo"
    (fake_repo / "scripts" / "migrations").mkdir(parents=True)
    (fake_repo / "migrations" / "models").mkdir(parents=True)
    for d in ("sqlite", "mysql", "postgres"):
        (fake_repo / "migrations" / "dialects" / d).mkdir(parents=True)
        shutil.copyfile(dialects_dir / d / baseline_name,
                        fake_repo / "migrations" / "dialects" / d / baseline_name)
    # 故意装成 mysql 的那份
    shutil.copyfile(dialects_dir / "mysql" / baseline_name,
                    fake_repo / "migrations" / "models" / baseline_name)
    shutil.copyfile(BASELINE_SCRIPT,
                    fake_repo / "scripts" / "migrations" / "baseline_existing_db.py")
    (fake_repo / "app").mkdir()
    (fake_repo / "app" / "__init__.py").write_text("")

    result = subprocess.run(
        [PYTHON, str(fake_repo / "scripts" / "migrations" / "baseline_existing_db.py"),
         str(db), str(fake_repo / "migrations" / "models")],
        capture_output=True, text=True, timeout=120, cwd=str(fake_repo),
    )
    assert result.returncode == 4, (
        f"装错方言时 main() 必须 rc=4，实际 rc={result.returncode}\n"
        f"stdout={result.stdout[-300:]}\nstderr={result.stderr[-300:]}"
    )
    assert "select_dialect_baseline" in result.stderr


# ---------------------------------------------------------------------------
# 切方言必须连增量迁移一起装（只换基线会在 MySQL/PG 上执行 SQLite 语法）
# ---------------------------------------------------------------------------


def _load_select_module():
    spec = importlib.util.spec_from_file_location(
        "select_dialect_baseline", SELECT_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_select_dialect_installs_increments_too(tmp_path):
    """
    切方言后，`migrations/models/` 里的增量迁移必须与目标方言那份逐字节相同。

    只换基线是不够的：增量里的类型也分方言（MySQL `DATETIME(6)` vs
    PG `TIMESTAMPTZ`），沿用旧方言的增量会在 upgrade 时执行错误语法。
    """
    mod = _load_select_module()
    models_dir = tmp_path / "models"
    models_dir.mkdir()

    # 先把 sqlite 那份装进去（模拟当前是 sqlite 部署）
    for src in sorted((REPO / "migrations" / "dialects" / "sqlite").glob("*.py")):
        shutil.copyfile(src, models_dir / src.name)

    # 切到 mysql
    mod.install("mysql", models_dir)

    mysql_dir = REPO / "migrations" / "dialects" / "mysql"
    for src in sorted(mysql_dir.glob("*.py")):
        target = models_dir / src.name
        assert target.is_file(), f"切到 mysql 后缺少 {src.name}"
        assert target.read_bytes() == src.read_bytes(), (
            f"{src.name} 装进去的不是 mysql 版本"
        )

    # 正向对照：mysql 与 sqlite 的增量内容必须真的不同，否则上面的断言是空转
    sqlite_dir = REPO / "migrations" / "dialects" / "sqlite"
    inc = [p.name for p in mysql_dir.glob("*.py") if not p.name.startswith("0_")]
    assert inc, "没有增量迁移可供对照，测试前提不成立"
    differ = [
        n for n in inc
        if (mysql_dir / n).read_bytes() != (sqlite_dir / n).read_bytes()
    ]
    assert differ, "mysql 与 sqlite 的增量内容完全相同，本用例无法证明方言区分生效"


def test_verify_rejects_wrong_dialect_increment(tmp_path):
    """
    增量装错方言必须被方言校验拦住（原来只比基线，增量错了会漏过）。
    """
    spec = importlib.util.spec_from_file_location(
        "baseline_existing_db", BASELINE_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    models_dir = tmp_path / "models"
    models_dir.mkdir()
    # 基线装对（mysql），增量故意装成 sqlite 的
    shutil.copyfile(REPO / "migrations" / "dialects" / "mysql" / mod.BASELINE_FILENAME,
                    models_dir / mod.BASELINE_FILENAME)
    sqlite_incs = [
        p for p in (REPO / "migrations" / "dialects" / "sqlite").glob("*.py")
        if not p.name.startswith("0_")
    ]
    assert sqlite_incs, "没有 sqlite 增量可供对照"
    for src in sqlite_incs:
        shutil.copyfile(src, models_dir / src.name)

    err = mod.verify_installed_baseline_matches_dialect(
        "mysql://u:p@127.0.0.1:3306/db", models_dir)
    assert err is not None, "增量装成 sqlite 版时，方言校验必须报错"
    assert "select_dialect_baseline" in err

    # 正向对照：换成正确的 mysql 增量后必须通过
    for src in (REPO / "migrations" / "dialects" / "mysql").glob("*.py"):
        shutil.copyfile(src, models_dir / src.name)
    assert mod.verify_installed_baseline_matches_dialect(
        "mysql://u:p@127.0.0.1:3306/db", models_dir) is None


def test_select_dialect_rejects_incomplete_dialect_set(tmp_path):
    """三方言增量不成套时（某方言少一条）必须报错，而不是静默装半套。"""
    mod = _load_select_module()
    fake = tmp_path / "dialects"
    for d in ("sqlite", "mysql", "postgres"):
        (fake / d).mkdir(parents=True)
        # 每家都放基线
        shutil.copyfile(REPO / "migrations" / "dialects" / d / mod.BASELINE_FILENAME,
                        fake / d / mod.BASELINE_FILENAME)
    # sqlite 多一条增量，其它两家没有
    (fake / "sqlite" / "1_x_specgen.py").write_text("# only sqlite\n")

    models_dir = tmp_path / "models"
    models_dir.mkdir()
    orig = mod.DIALECTS_DIR
    mod.DIALECTS_DIR = fake
    try:
        with pytest.raises(SystemExit) as exc:
            mod.install("sqlite", models_dir)
        assert "不成套" in str(exc.value)
    finally:
        mod.DIALECTS_DIR = orig


# ---------------------------------------------------------------------------
# 迁移 DDL 的引号转义：只有真连 MySQL 才会暴露，必须静态守住
# ---------------------------------------------------------------------------


def test_mysql_baseline_comment_quotes_are_escaped():
    """
    MySQL 基线里注释文本内含单引号时，Python 源码必须写 `\\\\'`（两个字符）。

    写 `\\'` 会被 Python 三引号字符串还原成裸 `'`，实际发出的 SQL 就变成
    `COMMENT '令牌类型，如 'activation', ...'`——MySQL 报 1064。
    这个缺陷本地 sqlite 测试与 check_migrations 都发现不了（它们不执行 MySQL
    DDL），只能靠真实 MySQL 实跑或本用例。

    守的是「实际发出的 SQL 里，注释字符串内部没有未转义的裸引号」。
    """
    import asyncio
    import importlib.util

    path = REPO / "migrations" / "dialects" / "mysql" / "0_20261024125437_init.py"
    assert path.is_file(), f"MySQL 基线不存在: {path}"
    spec = importlib.util.spec_from_file_location("mysql_baseline", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    sql = asyncio.run(mod.upgrade(None))

    # 逐行找 COMMENT '...'，检查其中的单引号是否都已用反斜杠转义
    import re

    problems = []
    for lineno, line in enumerate(sql.splitlines(), 1):
        m = re.search(r"COMMENT\s+'(.*)',?\s*$", line.strip())
        if not m:
            continue
        body = m.group(1)
        # 去掉已转义的 \' 后，仍出现的 ' 就是裸引号
        unescaped = body.replace("\\'", "")
        if "'" in unescaped:
            problems.append(f"第 {lineno} 行注释里有未转义的引号：{line.strip()[:100]}")
    assert not problems, "MySQL DDL 注释中的单引号未正确转义：\n" + "\n".join(problems)

    # 正向对照：确认令牌类型那条注释确实含引号，否则上面的循环是空转
    assert "token_type" in sql, "基线里找不到 token_type 列，用例前提不成立"
    token_line = next(ln for ln in sql.splitlines() if "token_type" in ln)
    assert "activation" in token_line, "token_type 注释内容与预期不符"
