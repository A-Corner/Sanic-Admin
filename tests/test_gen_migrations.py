#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
`python -m tools.specgen migrate` 的端到端测试。

这组用例守的是一个**主线缺陷**（#11 合入时漏带了 `tools/specgen/migrations.py`
与 `cli.py` 的 migrate 子命令）：master 曾处于「`check_migrations` 会红、却没有任何
工具能修」的死胡同——改了规格、模型变了，只能手写迁移。

核心对照（CPL 指定）：
  给规格加一个字段 -> `check_migrations` 退出码 1
  -> 执行 `specgen migrate`
  -> `check_migrations` 退出码 0，且三种方言的增量都已生成
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from tools.specgen import migrations as mig  # noqa: E402

PYTHON = sys.executable
CHECK_SCRIPT = REPO / "scripts" / "check_migrations.py"


def _env() -> dict:
    env = dict(os.environ)
    env.update({
        "SANIC_ENV": "development",
        "INITIAL_ADMIN_PASSWORD": "Mig-Test-Initial-Pass-1",
    })
    # 子进程必须只从 sandbox 导入。仓库根若在 PYTHONPATH 里，`app.models`
    # 会解析到仓库那份（旧模型），导致「加了字段却 check 仍绿」的假象。
    env.pop("PYTHONPATH", None)
    return env


def _run(args, cwd, timeout=300):
    env = _env()
    # 确保子进程优先从 cwd 解析包（`-m tools.specgen` 与 `app.models` 都是）
    env["PYTHONPATH"] = str(cwd)
    return subprocess.run(
        [PYTHON, *args], capture_output=True, text=True,
        timeout=timeout, cwd=str(cwd), env=env)


def _check_exit(repo_root: Path) -> int:
    """
    在 **sandbox 自己的** check_migrations 副本上跑，返回真实退出码。

    不能直接用仓库里的 scripts/check_migrations.py：它用
    `REPO = Path(__file__).parent.parent` 定位仓库，并 `sys.path.insert` 让
    `app.models` 从那里导入——传别的迁移目录只会换迁移侧，模型侧仍是**真实仓库**
    的旧模型，于是「加了字段」看起来毫无变化（退出码 0），整个对照空转。
    必须跑 sandbox 里的副本，两侧才都指向 sandbox。
    """
    script = repo_root / "scripts" / "check_migrations.py"
    if not script.is_file():
        raise AssertionError(f"sandbox 里没有 check_migrations.py：{script}")
    return _run([str(script), str(repo_root / "migrations")], repo_root).returncode


@pytest.fixture()
def sandbox(tmp_path):
    """
    把生成器与迁移链复制到临时仓库根，测试只改副本。

    只复制必需部分：`tools/specgen`、`scripts/`、`specs/`、`migrations/`，
    以及 `app/`（check_migrations 要导入 app.models 与生成的模型）。
    """
    for rel in ("tools", "scripts", "specs", "migrations", "app", "amis"):
        src = REPO / rel
        if src.exists():
            shutil.copytree(src, tmp_path / rel,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    # 干净起点：不带上跑测试残留的 __pycache__
    return tmp_path


# ---------------------------------------------------------------------------
# 前提：migrate 子命令必须存在
# ---------------------------------------------------------------------------


def test_migrate_subcommand_is_registered():
    """`specgen migrate` 必须是被认可的子命令（#11 遗漏时这里是坏的）。"""
    result = _run(["-m", "tools.specgen", "--help"], REPO)
    assert result.returncode == 0, result.stderr[-500:]
    assert "migrate" in result.stdout, (
        "specgen 的 CLI 里没有 migrate 子命令——"
        "#11 遗漏 tools/specgen/migrations.py 与 cli.py 的该子命令")


def test_migrations_module_importable():
    """`tools.specgen.migrations` 必须可导入，且暴露三方言常量。"""
    assert mig.DIALECTS == ("sqlite", "mysql", "postgres")


# ---------------------------------------------------------------------------
# 核心对照：加字段 -> check 红 -> migrate -> check 绿
# ---------------------------------------------------------------------------


def test_new_field_makes_check_fail_then_migrate_fixes_it(sandbox):
    """
    CPL 指定的主对照：
      1. 给 customer 规格加一个字段 -> check_migrations 退出码 1
      2. 执行 specgen generate + migrate
      3. check_migrations 退出码 0
      4. 三种方言都产出了新迁移
    """
    # --- 前提：干净起点是绿的 ---
    assert _check_exit(sandbox) == 0, "沙箱初始状态应一致，否则对照不成立"

    # --- 1. 加字段 ---
    spec = sandbox / "specs" / "customer.yaml"
    original = spec.read_text(encoding="utf-8")
    spec.write_text(
        original.replace("  - name: notes", "  - name: vip_level\n    type: int\n    label: 会员等级\n  - name: notes"),
        encoding="utf-8")
    assert spec.read_text(encoding="utf-8") != original, "规格替换未生效，对照不成立"

    gen = _run(["-m", "tools.specgen", "generate"], sandbox)
    assert gen.returncode == 0, f"generate 失败：{gen.stderr[-500:]}"

    # --- 2. 模型变了但迁移没跟上 -> 必须红 ---
    assert _check_exit(sandbox) == 1, (
        "加了字段却没生成迁移时，check_migrations 必须返回 1")

    # --- 3. migrate ---
    before = {
        d: {p.name for p in (sandbox / "migrations" / "dialects" / d).glob("*.py")}
        for d in mig.DIALECTS
    }
    result = _run(["-m", "tools.specgen", "migrate"], sandbox)
    assert result.returncode == 0, f"migrate 失败：{result.stderr[-800:]}"

    # --- 4. 三种方言都新增了同一个文件名 ---
    after = {
        d: {p.name for p in (sandbox / "migrations" / "dialects" / d).glob("*.py")}
        for d in mig.DIALECTS
    }
    added = {d: after[d] - before[d] for d in mig.DIALECTS}
    for d in mig.DIALECTS:
        assert added[d], f"{d} 没有产出新迁移"
    names = {d: sorted(v)[0] for d, v in added.items()}
    assert len(set(names.values())) == 1, (
        f"三方言的迁移文件名必须一致（aerich 以文件名作账本版本键）：{names}")

    # --- 5. check 恢复绿 ---
    assert _check_exit(sandbox) == 0, "migrate 之后 check_migrations 必须回到 0"


def test_migrate_generates_add_column_not_full_table(sandbox):
    """
    加字段应产出 `ALTER TABLE ... ADD`，而不是重建整张表。

    重建会丢数据；这条守住「增量」的语义。
    """
    spec = sandbox / "specs" / "customer.yaml"
    spec.write_text(
        spec.read_text(encoding="utf-8").replace(
            "  - name: notes", "  - name: vip_level\n    type: int\n    label: 会员等级\n  - name: notes"),
        encoding="utf-8")
    assert _run(["-m", "tools.specgen", "generate"], sandbox).returncode == 0

    before = {p.name for p in (sandbox / "migrations" / "dialects" / "sqlite").glob("*.py")}
    assert _run(["-m", "tools.specgen", "migrate"], sandbox).returncode == 0
    new = [
        p for p in (sandbox / "migrations" / "dialects" / "sqlite").glob("*.py")
        if p.name not in before
    ]
    assert len(new) == 1, f"应恰好新增一个迁移，实际 {[p.name for p in new]}"

    text = new[0].read_text(encoding="utf-8")
    assert "ADD" in text.upper(), "加字段的迁移应包含 ALTER TABLE ... ADD"
    assert "vip_level" in text, "迁移里应提到新字段"
    # 只加列，不该重建 customer 表
    assert "CREATE TABLE" not in text, (
        "加字段不应重建整表（会丢数据），实际生成的迁移里出现了 CREATE TABLE")


def test_migrate_is_noop_when_consistent(sandbox):
    """迁移链已覆盖模型时，migrate 不产出空迁移。"""
    before = {
        d: {p.name for p in (sandbox / "migrations" / "dialects" / d).glob("*.py")}
        for d in mig.DIALECTS
    }
    result = _run(["-m", "tools.specgen", "migrate"], sandbox)
    assert result.returncode == 0, result.stderr[-500:]
    after = {
        d: {p.name for p in (sandbox / "migrations" / "dialects" / d).glob("*.py")}
        for d in mig.DIALECTS
    }
    assert before == after, "一致时不应产出新迁移"
    assert "无需新迁移" in result.stdout or "无需" in result.stdout, result.stdout[-300:]


# ---------------------------------------------------------------------------
# 正向对照：check 真的会因缺迁移而红（否则上面的对照是空转）
# ---------------------------------------------------------------------------


def test_check_fails_when_increment_removed(sandbox):
    """
    正向对照：把增量迁移拿掉（等价于「模型领先于迁移链」），check 必须红。

    没有这条，上面 test_new_field_makes_check_fail_then_migrate_fixes_it 里
    的「退出码 1」可能只是别的原因恰好返回 1。
    """
    # 取每个方言当前的最大版本号（不写死 2_*，master 上增量起始序号可能不同）
    removed = []
    for d in mig.DIALECTS:
        files = sorted(
            (p for p in (sandbox / "migrations" / "dialects" / d).glob("*.py")
             if not p.name.startswith("0_")),
            key=lambda p: mig._version_num(p.name))
        assert files, f"{d} 没有增量迁移可供移除，前提不成立"
        newest = files[-1]
        newest.unlink()
        removed.append(newest.name)
        for p in (sandbox / "migrations" / "models").glob(newest.name):
            p.unlink()
    assert removed, "没有增量可供移除，前提不成立"

    assert _check_exit(sandbox) == 1, "缺增量迁移时 check_migrations 必须返回 1"


# ---------------------------------------------------------------------------
# 硬化：不该静默放过的变更必须报错
# ---------------------------------------------------------------------------


def _col(name, ty, extra=""):
    return f'    "{name}" {ty}{extra}'


def test_type_change_is_rejected_not_silently_ignored():
    """
    F1：同一列改类型必须进 unsupported，而不是「列名一样就放过」。

    早先 plan() 只对列名做集合差，`VARCHAR(16)` 改成 `VARCHAR(32)`、
    `INT` 改成 `BIGINT` 全被静默放过，生成「无需迁移」的假结论。
    """
    rendered = {"t": 'CREATE TABLE IF NOT EXISTS "t" (\n'
                     + _col("id", "INTEGER") + ",\n"
                     + _col("name", "VARCHAR(32)") + "\n);"}
    existing = {"t": ["id", "name"]}
    existing_defs = {"t": {"id": '    "id" INTEGER', "name": '    "name" VARCHAR(16)'}}
    _nt, _nc, unsupported = mig.plan(rendered, existing, existing_defs)
    assert unsupported, "改类型必须报错，实际静默放过"
    assert "name" in " ".join(unsupported)


def test_default_value_change_is_rejected():
    """F1：改默认值同样必须报错。"""
    rendered = {"t": 'CREATE TABLE IF NOT EXISTS "t" (\n'
                     + _col("status", "VARCHAR(16)", " DEFAULT 'closed'") + "\n);"}
    existing = {"t": ["status"]}
    existing_defs = {"t": {"status": '    "status" VARCHAR(16) DEFAULT \'open\''}}
    _nt, _nc, unsupported = mig.plan(rendered, existing, existing_defs)
    assert unsupported, "改默认值必须报错"


def test_adding_unique_to_existing_column_is_rejected():
    """F1：给已有列加 UNIQUE 必须报错（要单独 ADD CONSTRAINT）。"""
    rendered = {"t": 'CREATE TABLE IF NOT EXISTS "t" (\n'
                     + _col("email", "VARCHAR(255)", " NOT NULL UNIQUE") + "\n);"}
    existing = {"t": ["email"]}
    existing_defs = {"t": {"email": '    "email" VARCHAR(255) NOT NULL'}}
    _nt, _nc, unsupported = mig.plan(rendered, existing, existing_defs)
    assert unsupported, "加 UNIQUE 必须报错"


def test_unchanged_definition_is_not_flagged():
    """正向对照：定义完全一致时不得误报（否则上面几条可能是恒红）。"""
    rendered = {"t": 'CREATE TABLE IF NOT EXISTS "t" (\n'
                     + _col("name", "VARCHAR(16)") + "\n);"}
    existing = {"t": ["name"]}
    existing_defs = {"t": {"name": '    "name" VARCHAR(16)'}}
    nt, nc, unsupported = mig.plan(rendered, existing, existing_defs)
    assert unsupported == [], f"定义未变时不该报错：{unsupported}"
    assert nt == [] and nc == []


def test_new_unique_column_is_rejected():
    """
    F2：新增列带 UNIQUE 必须拒绝。

    `ALTER TABLE ... ADD COLUMN ... UNIQUE` 在 PG/SQLite 上行内唯一约束不被支持
    （SQLite 直接报错），需要单独的 ADD CONSTRAINT。
    """
    rendered = {"t": 'CREATE TABLE IF NOT EXISTS "t" (\n'
                     + _col("id", "INTEGER") + ",\n"
                     + _col("code", "VARCHAR(32)", " UNIQUE") + "\n);"}
    _nt, nc, unsupported = mig.plan(rendered, {"t": ["id"]}, {"t": {"id": '    "id" INTEGER'}})
    assert not nc, "带 UNIQUE 的新列不该进自动迁移"
    assert unsupported and "code" in " ".join(unsupported)


def test_new_fk_column_is_rejected():
    """F2：新增列带外键同样必须拒绝。"""
    rendered = {"t": 'CREATE TABLE IF NOT EXISTS "t" (\n'
                     + _col("id", "INTEGER") + ",\n"
                     + _col("other_id", "INT", ' REFERENCES "other" ("id")') + "\n);"}
    _nt, nc, unsupported = mig.plan(rendered, {"t": ["id"]}, {"t": {"id": '    "id" INTEGER'}})
    assert not nc
    assert unsupported and "other_id" in " ".join(unsupported)


def test_new_not_null_column_without_default_is_rejected():
    """
    F3：新增 NOT NULL 且无 DEFAULT 的列必须拒绝。

    已有行无值可填，ALTER 会因非空约束失败。
    """
    rendered = {"t": 'CREATE TABLE IF NOT EXISTS "t" (\n'
                     + _col("id", "INTEGER") + ",\n"
                     + _col("mandatory", "VARCHAR(16)", " NOT NULL") + "\n);"}
    _nt, nc, unsupported = mig.plan(rendered, {"t": ["id"]}, {"t": {"id": '    "id" INTEGER'}})
    assert not nc, "NOT NULL 无 DEFAULT 的新列不该自动迁移"
    assert unsupported and "DEFAULT" in " ".join(unsupported)


def test_new_nullable_column_is_allowed():
    """正向对照：可空新列（或 NOT NULL 带 DEFAULT）必须放行。"""
    rendered = {"t": 'CREATE TABLE IF NOT EXISTS "t" (\n'
                     + _col("id", "INTEGER") + ",\n"
                     + _col("nick", "VARCHAR(16)") + ",\n"
                     + _col("level", "INT", " NOT NULL DEFAULT 1") + "\n);"}
    _nt, nc, unsupported = mig.plan(rendered, {"t": ["id"]}, {"t": {"id": '    "id" INTEGER'}})
    assert unsupported == [], f"不该报错：{unsupported}"
    # plan() 按列名字母序输出
    assert [mig._column_name(d) for _t, d in nc] == ["level", "nick"]


# ---------------------------------------------------------------------------
# F4：MySQL 引号替换不误伤字符串；PG 新增列带 COMMENT ON
# ---------------------------------------------------------------------------


def test_mysql_quotes_does_not_touch_string_literals():
    """
    F4：`_mysql_quotes` 只该换标识符，不能改注释里的双引号。

    早先用一把梭正则，`COMMENT '如 "foo" 这类'` 里的 "foo" 会被换成反引号。
    """
    sql = 'ALTER TABLE "t" ADD "col" VARCHAR(32) COMMENT \'如 "foo" 与 "bar"\''
    out = mig._mysql_quotes(sql)
    assert '`t`' in out and '`col`' in out, "标识符应换成反引号"
    assert '"foo"' in out and '"bar"' in out, f"字符串里的双引号被误改：{out}"


def test_mysql_quotes_handles_escaped_single_quote():
    """注释里同时含 ' 与 " 时也要正确——断言整体相等，不用零散子串。"""
    sql = (
        'ALTER TABLE "t" ADD "col" VARCHAR(32) '
        "COMMENT '含 \\' 单引号与 \" 双引号的注释'"
    )
    expected = (
        "ALTER TABLE `t` ADD `col` VARCHAR(32) "
        "COMMENT '含 \\' 单引号与 \" 双引号的注释'"
    )
    assert mig._mysql_quotes(sql) == expected


def test_mysql_increment_has_content_and_downgrade():
    """测试补强：MySQL 增量要有实际 SQL 内容，且 downgrade 非空。"""
    rendered = {"t": 'CREATE TABLE IF NOT EXISTS `t` (\n'
                     + "    `a` VARCHAR(16) NOT NULL /* 甲 */\n);"}
    content = mig.render_migration("mysql", ["t"], [], rendered)
    assert "CREATE TABLE" in content
    assert "DROP TABLE IF EXISTS" in content, "downgrade 不能为空"
    assert "`t`" in content, "MySQL 版应用反引号"


def test_postgres_increment_has_content_and_downgrade():
    """测试补强：PG 增量要有实际 SQL 内容，且 downgrade 非空。"""
    rendered = {"t": 'CREATE TABLE IF NOT EXISTS "t" (\n'
                     + '    "a" VARCHAR(16) NOT NULL\n);'}
    content = mig.render_migration("postgres", ["t"], [], rendered)
    assert "CREATE TABLE" in content
    assert "DROP TABLE IF EXISTS" in content


def test_positive_control_failure_reason_is_visible(sandbox):
    """
    测试补强：正向对照要断言**红灯的原因**，不只断言退出码非 0。

    只看退出码的话，「因别的原因恰好返回 1」也会让对照通过。
    """
    for d in mig.DIALECTS:
        files = sorted(
            (p for p in (sandbox / "migrations" / "dialects" / d).glob("*.py")
             if not p.name.startswith("0_")),
            key=lambda p: mig._version_num(p.name))
        if files:
            files[-1].unlink()
    for p in (sandbox / "migrations" / "models").glob("[1-9]_*.py"):
        p.unlink()

    script = sandbox / "scripts" / "check_migrations.py"
    result = _run([str(script), str(sandbox / "migrations")], sandbox)
    assert result.returncode == 1, result.stdout[-400:]
    # 必须是「模型有、迁移链没有」这一类原因，而不是脚本自身报错
    assert "模型有、迁移链没有" in result.stdout, (
        f"退出码 1 但原因不是缺迁移，对照不干净：{result.stdout[-400:]}")


# ---------------------------------------------------------------------------
# 无驱动可渲染：生成迁移不该要求装 MySQL/PG 驱动
# ---------------------------------------------------------------------------


def test_render_works_without_db_drivers():
    """
    在**屏蔽全部数据库驱动**的环境里，三方言仍必须能渲染出 DDL。

    这是 CI 上真实踩到的失败：`import tortoise.backends.mysql.schema_generator`
    会先执行包 `__init__.py`，而它 `from .client import MySQLClient` →
    `import aiomysql`；`Tortoise.init(db_url="mysql://…")` 也会实例化真实 client。
    CI 只装 `requirements.txt`（不含 aiomysql/asyncmy/asyncpg），于是
    `specgen migrate` 直接以 ModuleNotFoundError 失败——而本地 venv 恰好装过
    驱动，测试全绿。

    渲染只用模型的元数据，与连接无关。这条用例把「不需要驱动」变成硬约束：
    谁再把驱动 import 引回渲染路径，这里就红。
    """
    code = """
import sys
# 屏蔽所有 MySQL / PG 驱动：再 import 会抛 ModuleNotFoundError
for _m in ("aiomysql", "asyncmy", "asyncpg", "psycopg", "psycopg2"):
    sys.modules[_m] = None
sys.path.insert(0, {root!r})
from tools.specgen import migrations as m

for _d in m.DIALECTS:
    rendered = m.render_ddl_for(_d)
    assert rendered, f"{{_d}} 渲染结果为空"
    # 方言特征必须正确（用 id 列的主键写法区分三方言）
    head = rendered["customer"]
    if _d == "sqlite":
        assert "AUTOINCREMENT" in head, head[:200]
    elif _d == "mysql":
        assert "AUTO_INCREMENT" in head and "`" in head, head[:200]
    else:
        assert "SERIAL" in head, head[:200]
print("OK_WITHOUT_DRIVERS")
""".format(root=str(REPO))
    result = subprocess.run([PYTHON, "-c", code], capture_output=True, text=True,
                            timeout=300, cwd=str(REPO), env=_env())
    assert result.returncode == 0, (
        "无驱动环境下渲染失败——渲染路径又引入了数据库驱动依赖：\n"
        + result.stderr[-1500:])
    assert "OK_WITHOUT_DRIVERS" in result.stdout


# ---------------------------------------------------------------------------
# 复审第二轮：用真实渲染做输入，单独方言也要能拒绝
# ---------------------------------------------------------------------------


def test_mysql_fk_detected_from_real_render_alone():
    """
    F2（MySQL 单独成立）：MySQL 的 FK 是表级 `CONSTRAINT .. FOREIGN KEY`，
    必须由 split_columns 归并回列。**用真实渲染结果**，不靠跨方言汇总兜底。
    """
    ddl = mig.render_ddl_for("mysql")
    _t, cols, _tail = mig.split_columns(ddl["orders"])
    assert "REFERENCES" in cols["customer_id"].upper(), (
        f"MySQL 真实渲染的 orders.customer_id 没有归并外键：{cols['customer_id']!r}")

    # 单独用 MySQL 的渲染结果做 plan，也能判定「新列带外键 -> 拒绝」
    rendered = {"orders": ddl["orders"]}
    _nt, nc, unsupported = mig.plan(
        rendered, {"orders": ["id", "title", "customer_id"]},
        {"orders": {"id": "`id` INT NOT NULL", "title": "`title` VARCHAR(128) NOT NULL",
                    "customer_id": "`customer_id` INT NOT NULL"}})
    assert unsupported, "MySQL 单独渲染结果里，新列带外键应被拒绝"
    assert any("customer_id" in u or "带外键" in u for u in unsupported), unsupported


def test_default_case_change_is_detected():
    """
    F1（大小写）：默认值只改大小写也必须检测出来。

    `normalize_column_def` 早先整串 `.upper()`，`DEFAULT 'open'` 与 `'OPEN'`
    会被抹成一样，这种语义变化被漏报。
    """
    a = mig.normalize_column_def("    \"status\" VARCHAR(16) DEFAULT 'open'")
    b = mig.normalize_column_def("    \"status\" VARCHAR(16) DEFAULT 'OPEN'")
    assert a != b, f"只改字面量大小写应能区分，实际都是 {a!r}"


def test_keyword_case_is_still_normalized():
    """反向对照：关键字大小写不该造成差异（否则每天都会被误报）。"""
    a = mig.normalize_column_def("    \"x\" varchar(16) DEFAULT 'a'")
    b = mig.normalize_column_def("    \"x\" VARCHAR(16) DEFAULT 'a'")
    assert a == b, f"关键字大小写不该产生差异：{a!r} vs {b!r}"


def test_mysql_increment_has_add_and_drop_column():
    """测试补强：MySQL 加列增量要同时有 `ADD` 与 downgrade 的 `DROP COLUMN`。"""
    rendered = {"t": "CREATE TABLE IF NOT EXISTS `t` (\n"
                     + "    `a` INT NOT NULL DEFAULT 1 /* 甲 */\n);"}
    content = mig.render_migration("mysql", [], [("t", "    `a` INT NOT NULL DEFAULT 1 /* 甲 */")],
                                   rendered)
    assert "ALTER TABLE `t` ADD `a`" in content, content
    assert "DROP COLUMN `a`" in content, "downgrade 缺少 DROP COLUMN"


def test_postgres_increment_has_add_and_drop_column():
    """测试补强：PG 加列增量要同时有 `ADD` 与 downgrade 的 `DROP COLUMN`。"""
    rendered = {"t": 'CREATE TABLE IF NOT EXISTS "t" (\n'
                     + '    "a" INT NOT NULL DEFAULT 1 /* 甲 */\n);'}
    content = mig.render_migration(
        "postgres", [], [("t", '    "a" INT NOT NULL DEFAULT 1 /* 甲 */')], rendered)
    assert 'ALTER TABLE "t" ADD "a"' in content, content
    assert 'DROP COLUMN "a"' in content, "downgrade 缺少 DROP COLUMN"


def test_render_without_drivers_checks_mysql_charset():
    """测试补强：无驱动渲染的 MySQL 结果要带 `CHARACTER SET`。"""
    code = """
import sys
for _m in ("aiomysql", "asyncmy", "asyncpg", "psycopg", "psycopg2"):
    sys.modules[_m] = None
sys.path.insert(0, {root!r})
from tools.specgen import migrations as m
rendered = m.render_ddl_for("mysql")
assert "CHARACTER SET" in rendered["customer"], rendered["customer"][:400]
print("OK_CHARSET")
""".format(root=str(REPO))
    result = subprocess.run([PYTHON, "-c", code], capture_output=True, text=True,
                            timeout=300, cwd=str(REPO), env=_env())
    assert result.returncode == 0, result.stderr[-1200:]
    assert "OK_CHARSET" in result.stdout


def test_tortoise_version_is_asserted():
    """F4（版本断言）：tortoise 版本不符时必须给明确报错，而不是静默产出错 DDL。"""
    import inspect
    src = inspect.getsource(mig._load_generator_class)
    assert "0.20." in src, "缺少 tortoise 0.20.x 的版本断言"
    assert "MigrationPlanError" in src, "版本不符时应抛 MigrationPlanError"


def test_postgres_comment_comes_from_real_render():
    """
    F4（PG，复审第二轮）：新增列的注释必须能从**真实渲染结果**里取到。

    PG 的列注释是 `CREATE TABLE` 之后独立的 `COMMENT ON COLUMN` 语句。
    `split_columns` 早先只截到 `);`，真实流程里新列拿到的注释永远是空——
    加列的 `COMMENT ON` 因此永远不会生成。早先这条测试用手写 SQL 做输入，
    所以掩盖了问题。

    这里全程用 `render_ddl_for("postgres")` 的真实输出。
    """
    ddl = mig.render_ddl_for("postgres")
    _t, cols, _tail = mig.split_columns(ddl["customer"])
    notes_def = cols["notes"]
    assert "备注" in notes_def, (
        f"split_columns 没能从真实 PG 渲染里取回列注释：{notes_def!r}\n"
        "（PG 的注释是 CREATE TABLE 之后的独立 COMMENT ON 语句，必须归并回来）")

    content = mig.render_migration("postgres", [], [("customer", notes_def)], ddl)
    assert "COMMENT ON COLUMN" in content, "PG 新增列缺少 COMMENT ON COLUMN"
    assert "备注" in content, content[-400:]


def test_postgres_comment_escape_from_real_render():
    """
    F4（PG 转义，用真实渲染）：注释里的单引号必须按 PG 规则 `''` 双写。

    真实配置里 `verification_tokens` 的注释含单引号（`如 'activation', ...`），
    用它做输入比手写更接近生产。
    """
    ddl = mig.render_ddl_for("postgres")
    _t, cols, _tail = mig.split_columns(ddl["verification_tokens"])
    token_def = cols["token_type"]
    assert "'" in token_def, f"取到的列定义应含单引号注释：{token_def!r}"

    content = mig.render_migration("postgres", [], [("verification_tokens", token_def)], ddl)
    assert "COMMENT ON COLUMN" in content
    # PG 里注释内部每个 ' 都要变成 ''；出现单个裸 ' 就说明转义错了
    import re
    m = re.search(r"COMMENT ON COLUMN [^;]+;", content)
    assert m, f"没生成 COMMENT ON 语句：{content[-400:]}"
    body = m.group(0)
    assert "''" in body, f"PG 注释里的单引号必须双写：{body}"
    # 去掉所有成对的 '' 后，字符串里不该再有 '（' 只应作为语句边界出现）
    inner = body[body.index("IS ") + 3:].rstrip(";")
    if inner.endswith("'"):
        inner = inner[1:-1]
    assert "'" not in inner.replace("''", ""), f"存在未转义的裸单引号：{body}"
