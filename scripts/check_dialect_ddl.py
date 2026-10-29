#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
方言 DDL 实跑校验（CI 用）。

为什么需要它：`check_migrations.py` 只把迁移 DDL 当**文本**比对，从不真正执行。
MySQL 的 DDL 与 SQLite 不同（反引号、`AUTO_INCREMENT`、`COMMENT`、`DATETIME(6)`），
语法错误在本地与 CI 一路绿灯，到生产才炸——真实案例：
`migrations/dialects/mysql/0_*_init.py` 里写 `\\'`，被 Python 还原成裸引号，
MySQL 报 1064，任何全新部署都在基线第一步失败。

本脚本在**真实** MySQL / PostgreSQL 上跑完整迁移链（0+1），然后用
`information_schema` 断言关键列的类型与约束。

用法：
    python scripts/check_dialect_ddl.py <sqlite|mysql|postgres> [--existing]

    --existing  存量库形态：先用当前模型建表（模拟 v0.3.2 的 generate_schemas），
                再基线化，最后 upgrade —— 断言**只应用增量**、基线不重跑。

    --with-amount-seed  SPEC-005 数据换算场景（在**非空** orders 表上验证）：
                空库先跑 0_*+1_*+2_*（不含 3_*，得旧形态 amount REAL/DOUBLE），
                插入种子值（含 *100 后是 xxx.999… 的关键回归值），跑 3_*，
                逐行断言 amount == round(原值*100) 精确相等；另造一库插 12.345
                （半分尾数），断言迁移中止且一行未写。
                **为什么必须在有数据的库上跑**：空库时 CASE 的分支一行都不会命中，
                「守卫查错表」「断言用 CAST」这两类缺陷在空库上必然全绿
                （PR #89 审核实测）。见 tests/test_spec005_migration_data.py
                的模块 docstring（SQLite 侧同源用例）。

退出码：0 全部断言通过；1 断言失败；2 脚本/环境错误。
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

#: 各方言下「关键列 -> 期望类型」的断言。
#: 这些类型差异正是跨方言部署最容易出错的地方（date / datetime / bool / 浮点）。
EXPECTED_TYPES = {
    "mysql": {
        "customer": {
            "id": "int",
            "deleted": "tinyint",       # BOOL 在 MySQL 落成 tinyint(1)
            "birthday": "date",
            "onboarded_at": "datetime",
            "email": "varchar",
            "notes": "longtext",         # TextField 在 MySQL 是 LONGTEXT
        },
        "orders": {
            "amount": "int",          # SPEC-005：金额改最小单位整数（分）
            "quantity": "int",
            "customer_id": "int",
        },
    },
    "postgres": {
        "customer": {
            "id": "integer",
            "deleted": "boolean",
            "birthday": "date",
            "onboarded_at": "timestamp with time zone",
            "email": "character varying",
            "notes": "text",
        },
        "orders": {
            "amount": "integer",      # SPEC-005：金额改最小单位整数（分）
            "quantity": "integer",
            "customer_id": "integer",
        },
    },
}

#: 必须存在的唯一约束与唯一列
EXPECTED_UNIQUE = {"customer": ["email"]}
#: 必须存在的外键：(表, 列) -> (目标表, 目标列, ON DELETE 规则)
#: ON DELETE RESTRICT 来自规格 `belongs_to.on_delete`，删客户时不能级联删订单。
EXPECTED_FK = {("orders", "customer_id"): ("customer", "id", "RESTRICT")}


def _load_baseline_module():
    spec = importlib.util.spec_from_file_location(
        "baseline_existing_db", REPO / "scripts" / "migrations" / "baseline_existing_db.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


async def _assert_schema(conn, dialect: str) -> list:
    """用 information_schema 断言列类型/唯一/外键，返回问题列表（空 = 通过）。"""
    problems = []
    expected = EXPECTED_TYPES.get(dialect, {})

    for table, cols in expected.items():
        rows = await conn.execute_query_dict(
            "SELECT column_name AS c, data_type AS t, is_nullable AS n "
            "FROM information_schema.columns "
            "WHERE table_schema = " +
            ("DATABASE()" if dialect == "mysql" else "current_schema()") +
            " AND table_name = " + ("%s" if dialect == "mysql" else "$1") +
            " ORDER BY ordinal_position", [table])
        if not rows:
            problems.append(f"表 {table} 不存在（{dialect}）")
            continue
        actual = {str(r["c"]).lower(): str(r["t"]).lower() for r in rows}
        for col, want in cols.items():
            got = actual.get(col)
            if got is None:
                problems.append(f"{table}.{col} 不存在（{dialect}）")
            elif got != want:
                problems.append(f"{table}.{col} 类型不符：期望 {want}，实际 {got}")

    # 唯一约束
    for table, cols in EXPECTED_UNIQUE.items():
        if dialect == "mysql":
            rows = await conn.execute_query_dict(
                "SELECT column_name AS c FROM information_schema.statistics "
                "WHERE table_schema = DATABASE() AND table_name = %s "
                "AND non_unique = 0", [table])
        else:
            rows = await conn.execute_query_dict(
                "SELECT kcu.column_name AS c FROM information_schema.table_constraints tc "
                "JOIN information_schema.key_column_usage kcu "
                "  ON tc.constraint_name = kcu.constraint_name "
                "WHERE tc.table_name = $1 AND tc.constraint_type = 'UNIQUE'", [table])
        uniques = {str(r["c"]).lower() for r in rows}
        for col in cols:
            if col not in uniques:
                problems.append(f"{table}.{col} 缺少唯一约束（{dialect}）")

    # 外键（含 ON DELETE 规则：用 referential_constraints 查 delete_rule）
    for (table, col), (ref_table, ref_col, want_rule) in EXPECTED_FK.items():
        if dialect == "mysql":
            rows = await conn.execute_query_dict(
                "SELECT kcu.column_name AS c, kcu.referenced_table_name AS rt, "
                "kcu.referenced_column_name AS rc, rc.delete_rule AS dr "
                "FROM information_schema.key_column_usage kcu "
                "JOIN information_schema.referential_constraints rc "
                "  ON kcu.constraint_name = rc.constraint_name "
                " AND kcu.constraint_schema = rc.constraint_schema "
                "WHERE kcu.table_schema = DATABASE() AND kcu.table_name = %s "
                "AND kcu.referenced_table_name IS NOT NULL", [table])
        else:
            rows = await conn.execute_query_dict(
                "SELECT kcu.column_name AS c, ccu.table_name AS rt, "
                "ccu.column_name AS rc, rc.delete_rule AS dr "
                "FROM information_schema.table_constraints tc "
                "JOIN information_schema.key_column_usage kcu "
                "  ON tc.constraint_name = kcu.constraint_name "
                "JOIN information_schema.constraint_column_usage ccu "
                "  ON tc.constraint_name = ccu.constraint_name "
                "JOIN information_schema.referential_constraints rc "
                "  ON tc.constraint_name = rc.constraint_name "
                "WHERE tc.table_name = $1 AND tc.constraint_type = 'FOREIGN KEY'", [table])
        found = {
            (str(r["c"]).lower(), str(r["rt"]).lower(), str(r["rc"]).lower(),
             str(r["dr"]).upper())
            for r in rows
        }
        want = (col, ref_table, ref_col, want_rule.upper())
        if want not in found:
            problems.append(
                f"{table}.{col} 外键不符：期望 -> {ref_table}.{ref_col} ON DELETE {want_rule}，"
                f"实际 {sorted(found)}（{dialect}）")
    return problems


async def _build_existing_schema(url: str) -> None:
    """
    模拟 v0.3.2 的存量库：用当前模型建表，不写 aerich 账本。

    **必须按外键依赖排序**：MySQL 在 `STRICT` 模式下建带外键的表时，被引用的表
    必须已存在（否则 `errno 1824: Failed to open the referenced table`）。
    Tortoise 的 `generate_schemas` 内部会做这个排序，这里手工建表就得自己做。
    做法：反复尝试建表，把「引用未就绪」的表留到下一轮，直到没有进展；
    剩下建不出来的就是真问题（循环外键或写错），明确报错而不是静默跳过。
    """
    from tortoise import Tortoise

    conn_name = "default"
    await Tortoise.init(db_url=url, modules={"models": ["app.models"]})
    try:
        conn = Tortoise.get_connection(conn_name)
        gen = conn.schema_generator(conn)

        pending = []  # [(表名, CREATE 语句, [m2m 语句])]
        for model in Tortoise.apps["models"].values():
            if model._meta.db_table == "aerich":
                continue
            info = gen._get_table_sql(model, safe=True)
            pending.append((
                model._meta.db_table,
                info["table_creation_string"],
                list(info.get("m2m_tables") or ()),
            ))

        last_error = None
        while pending:
            progressed = False
            still = []
            for table, create_sql, m2m_sqls in pending:
                try:
                    await conn.execute_script(create_sql)
                    for m2m in m2m_sqls:
                        await conn.execute_script(m2m)
                    progressed = True
                except Exception as exc:  # noqa: BLE001 引用未就绪时留到下一轮
                    last_error = exc
                    still.append((table, create_sql, m2m_sqls))
            pending = still
            if not progressed and pending:
                names = [t for t, _, _ in pending]
                raise RuntimeError(
                    f"存量库建表无法推进，剩余 {names}（最后错误: {last_error!r}）")
    finally:
        await Tortoise.close_connections()


async def _ensure_database(dialect: str, url: str) -> None:
    """
    确保目标库存在。

    CI 的 services 只创建 `$MYSQL_DATABASE` / `$POSTGRES_DB` 指定的那一个库。
    存量库用例用另一个库名（`sanic_a_ex`），不在这里建就会连接失败——而连接失败
    很容易被误读成「迁移有问题」。这里显式建库，连不上就明确报错。
    """
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    db_name = parts.path.lstrip("/")
    if not db_name:
        raise RuntimeError(f"连接串里没有库名：{url}")
    # 连到该方言自带的维护库上执行 CREATE DATABASE
    admin_db = "mysql" if dialect == "mysql" else "postgres"
    admin_url = url.replace(f"/{db_name}", f"/{admin_db}", 1)

    from tortoise import Tortoise

    await Tortoise.init(db_url=admin_url, modules={"models": []})
    try:
        conn = Tortoise.get_connection("default")
        if dialect == "mysql":
            await conn.execute_script(
                f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4")
        else:
            # PostgreSQL **不支持** `CREATE DATABASE IF NOT EXISTS`——那是 MySQL 语法，
            # 在 PG 上会报 `syntax error at or near "NOT"`。改为先查 pg_database。
            exists = await conn.execute_query_dict(
                "SELECT 1 AS x FROM pg_database WHERE datname = $1", [db_name])
            if not exists:
                await conn.execute_script(f'CREATE DATABASE "{db_name}"')
    finally:
        await Tortoise.close_connections()


async def _recreate_database(dialect: str, url: str) -> None:
    """
    删掉并重建目标库。

    存量库用例**必须**从未建表的干净库开始：上一次运行留下的表会让
    `CREATE TABLE` 撞 `already exists`，看起来像脚本 bug 而不是环境不干净。
    """
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    db_name = parts.path.lstrip("/")
    admin_db = "mysql" if dialect == "mysql" else "postgres"
    admin_url = url.replace(f"/{db_name}", f"/{admin_db}", 1)

    from tortoise import Tortoise

    await Tortoise.init(db_url=admin_url, modules={"models": []})
    try:
        conn = Tortoise.get_connection("default")
        if dialect == "mysql":
            await conn.execute_script(f"DROP DATABASE IF EXISTS `{db_name}`")
            await conn.execute_script(
                f"CREATE DATABASE `{db_name}` CHARACTER SET utf8mb4")
        else:
            # PG 不能删当前连接的库，但这里连的是 postgres 维护库，可以删目标库
            try:
                await conn.execute_script(f'DROP DATABASE IF EXISTS "{db_name}"')
            except Exception as exc:
                if "being accessed by other users" in str(exc).lower():
                    raise RuntimeError(
                        f"数据库 {db_name} 仍有连接，无法重建；"
                        f"先断开再跑（CI 里每次 job 都是新容器，不应出现）") from exc
                raise
            await conn.execute_script(f'CREATE DATABASE "{db_name}"')
    finally:
        await Tortoise.close_connections()


async def run(dialect: str, url: str, existing: bool) -> int:
    from aerich import Command
    from tortoise import Tortoise

    from app.aerich_config import build_tortoise_config

    migrations_root = REPO / "migrations"
    models_dir = migrations_root / "models"

    problems: list = []

    # 存量库必须从干净库开始；新库只需确保存在。
    if existing:
        await _recreate_database(dialect, url)
        await _build_existing_schema(url)
        bed = _load_baseline_module()
        # baseline_existing_db 内部用 asyncio.run()，在已运行的事件循环里会抛
        # 「asyncio.run() cannot be called from a running event loop」。
        # 放到独立线程里跑（线程内没有事件循环）。
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            rc = pool.submit(
                bed.main, "", str(models_dir), "models", False, url).result()
        if rc != 0:
            print(f"!! 基线化失败 rc={rc}", file=sys.stderr)
            return 2

    if not existing:
        # 新库：确保存在（CI 的 services 只建 matrix 指定的那一个库）
        await _ensure_database(dialect, url)

    cmd = Command(build_tortoise_config(url), app="models", location=str(migrations_root))
    await cmd.init()
    try:
        applied = list(await cmd.upgrade(run_in_transaction=(dialect != "sqlite")))
    finally:
        pass

    conn = Tortoise.get_connection("default")
    problems += await _assert_schema(conn, dialect)
    await Tortoise.close_connections()

    print(f"  [{dialect}{' 存量库' if existing else ' 新库'}] 应用迁移: {applied}")
    if existing:
        # 存量库：基线已被 baseline_existing_db 标记为已应用，upgrade 只该跑增量
        # 『不该重跑基线』要按**基线文件名**判断，不能写死版本号。
        # 早先写死 `startswith("1_")`，一加第 2 条增量（M3 的 ticket 迁移）就误报
        # 「存量库重跑了基线」——实际跑的是正常增量。
        baseline_names = {p.name for p in models_dir.glob("0_*.py")}
        reran_baseline = [m for m in applied if m in baseline_names]
        if reran_baseline:
            problems.append(f"存量库不应重跑基线，实际重跑了 {reran_baseline}")
        if not applied:
            problems.append("存量库没有应用任何增量迁移（增量缺失？）")

    if problems:
        print(f"!! {dialect} 断言失败：", file=sys.stderr)
        for p in problems:
            print(f"   - {p}", file=sys.stderr)
        return 1
    print(f"  OK {dialect}：{len(applied)} 条迁移，schema 断言全部通过")
    return 0




# ---------------------------------------------------------------------------
# SPEC-005 数据换算场景（--with-amount-seed）
# ---------------------------------------------------------------------------

#: 种子表：元值 -> 期望分值（round(元*100)）。全部可精确换算。
#: 1.14/2.28/0.29/0.57/19.99 是 *100 后为 xxx.999… 的关键回归值：
#: 断言若用 CAST（向零截断）会产生 1.0 的假残差把它们全部判死（PR #89 审核实测）。
AMOUNT_SEEDS = [
    (12.34, 1234),
    (1.14, 114),
    (2.28, 228),
    (0.29, 29),
    (0.57, 57),
    (19.99, 1999),
    (0.01, 1),
    (0, 0),
    (21474836.47, 2147483647),   # 32 位 INT 上界
    (-12.34, -1234),             # 业务未禁止负数（规格无 min/max，_INT_RULE 只查类型）
    (0.30000000000000004, 30),   # 0.1+0.2 的浮点累加值，精确对应 30 分
]
#: 半分尾数：唯一应触发「不精确 → 中止」的值
AMOUNT_INEXACT = 12.345


def _load_dialect_migration(dialect: str, min_version: int):
    """加载 migrations/dialects/<方言>/ 下版本号 >= min_version 的迁移模块（按序）。"""
    base = REPO / "migrations" / "dialects" / dialect
    files = sorted(
        (p for p in base.glob("*.py") if not p.name.startswith("__")),
        key=lambda p: int(p.name.split("_", 1)[0]),
    )
    out = []
    for path in files:
        version = int(path.name.split("_", 1)[0])
        if version < min_version:
            continue
        spec = importlib.util.spec_from_file_location(path.stem, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        out.append(mod)
    return out


def _q(dialect: str, ident: str) -> str:
    """按方言给标识符加引号。"""
    return f"`{ident}`" if dialect == "mysql" else f'"{ident}"'


async def _amount_seed_scenario(dialect: str, url: str) -> list:
    """非空 orders 表上的精确换算与中止验证，返回问题列表（空 = 通过）。"""
    from tortoise import Tortoise

    problems: list = []
    tq = _q(dialect, "orders")
    oq = _q(dialect, "orders_old")
    cq = _q(dialect, "customer")

    # ---- 场景 A：全部可精确换算 ----
    print(f"  [{dialect}][seed] 场景 A：非空表精确换算（{len(AMOUNT_SEEDS)} 条种子）")
    await _recreate_database(dialect, url)
    await _ensure_database(dialect, url)
    await Tortoise.init(db_url=_tortoise_url(dialect, url), modules={"models": []})
    conn = Tortoise.get_connection("default")

    # 跑 0_*+1_*+2_*（旧形态 orders：amount REAL/DOUBLE），**跳过 3_**
    pre = [m for m in _load_dialect_migration(dialect, 0)
           if not m.__name__.startswith("3_")]
    for mod in pre:
        await conn.execute_script(await mod.upgrade(conn))
    await conn.execute_script(
        f"INSERT INTO {cq} ({_q(dialect,'id')}, {_q(dialect,'name')}, "
        f"{_q(dialect,'email')}, {_q(dialect,'status')}) "
        f"VALUES (1, 'seed', 'seed@example.com', 'active');"
    )
    for i, (yuan, _) in enumerate(AMOUNT_SEEDS, 1):
        await conn.execute_script(
            f"INSERT INTO {tq} ({_q(dialect,'title')}, {_q(dialect,'amount')}, "
            f"{_q(dialect,'quantity')}, {_q(dialect,'status')}, {_q(dialect,'customer_id')}) "
            f"VALUES ('o{i}', {yuan!r}, 1, 'pending', 1);"
        )

    mig3 = _load_dialect_migration(dialect, 3)
    if not mig3:
        problems.append("找不到 3_* 迁移（SPEC-005），数据场景无法验证")
    else:
        await conn.execute_script(await mig3[0].upgrade(conn))
        rows = await conn.execute_query_dict(
            f"SELECT {_q(dialect,'title')} AS t, {_q(dialect,'amount')} AS a FROM {tq} "
            f"ORDER BY CAST(SUBSTR({_q(dialect,'title')}, 2) AS "
            f"{'UNSIGNED' if dialect == 'mysql' else 'INTEGER'});"
        )
        if len(rows) != len(AMOUNT_SEEDS):
            problems.append(f"换算后行数 {len(rows)} != 种子 {len(AMOUNT_SEEDS)}（有行被丢）")
        for (yuan, exp), row in zip(AMOUNT_SEEDS, rows):
            # **精确等于**：不是容差比较。容差 1e-3 只用于迁移内部的「能否换算」判定。
            if row["a"] != exp:
                problems.append(f"{yuan!r} 元换算为 {row['a']} 分，期望 {exp} 分")

    await Tortoise.close_connections()

    # ---- 场景 B：半分尾数必须中止且一行不写 ----
    print(f"  [{dialect}][seed] 场景 B：{AMOUNT_INEXACT} 必须中止")
    await _recreate_database(dialect, url)
    await _ensure_database(dialect, url)
    await Tortoise.init(db_url=_tortoise_url(dialect, url), modules={"models": []})
    conn = Tortoise.get_connection("default")
    for mod in pre:
        await conn.execute_script(await mod.upgrade(conn))
    await conn.execute_script(
        f"INSERT INTO {cq} ({_q(dialect,'id')}, {_q(dialect,'name')}, "
        f"{_q(dialect,'email')}, {_q(dialect,'status')}) "
        f"VALUES (1, 'seed', 'seed@example.com', 'active');"
    )
    await conn.execute_script(
        f"INSERT INTO {tq} ({_q(dialect,'title')}, {_q(dialect,'amount')}, "
        f"{_q(dialect,'quantity')}, {_q(dialect,'status')}, {_q(dialect,'customer_id')}) "
        f"VALUES ('bad', {AMOUNT_INEXACT!r}, 1, 'pending', 1);"
    )
    aborted = None
    try:
        await conn.execute_script(await mig3[0].upgrade(conn))
    except Exception as exc:  # 预期路径
        aborted = exc
    if aborted is None:
        problems.append(
            f"{AMOUNT_INEXACT}（半分尾数）未触发迁移中止——「不精确即停」失效")
    else:
        # **顺序**：先断言失败原因正确，再查数据终态，最后由调用方 exit 非 0。
        if "NOT NULL" not in str(aborted) and "null" not in str(aborted).lower():
            problems.append(f"中止原因应是 NOT NULL 违反，实际：{aborted!r}")

        # 数据终态断言（**方言无关的「可接受终态集合」**）：
        # 三方言的多语句事务语义不同——
        #   SQLite（executescript 逐语句自动提交）：RENAME/CREATE 残留，
        #     终态 = orders(新,0行) + orders_old(1行原值)
        #   PG（简单查询隐式单事务）：整脚本回滚，终态 = orders(旧,1行原值)，无 orders_old
        #   MySQL（asyncmy 逐语句）：与 SQLite 同
        # 所以不能断言「orders_old 必须存在」。方言无关的不变量是：
        #   ① 原值 {INEXACT!r} 必须仍在（orders 或 orders_old 之一）——数据未丢；
        #   ② 任何表里都不得出现它的换算形式（{TRUNC} 截断 / {ROUNDDOWN} ROUND静默 /
        #      {ROUNDUP} 进位）——没有静默改值。
        bad_forms = (12, 1234, 1235)  # trunc / round静默(1234.5→1234 on ties-to-even) / half-away
        lost, mutated = True, []
        for tbl in (tq, oq):
            try:
                vals = await conn.execute_query_dict(
                    f"SELECT {_q(dialect, 'amount')} AS a FROM {tbl}")
            except Exception:
                continue  # 表不存在 = 全回滚语义下的合法终态
            for r in vals:
                lost = False
                if r["a"] in bad_forms:
                    mutated.append(f"{tbl}.amount={r['a']}")
        if lost:
            problems.append(f"原值 {AMOUNT_INEXACT} 在 orders/orders_old 中都找不到——数据丢了")
        if mutated:
            problems.append(f"发现被静默改值的行：{mutated}（截断/换算形式，裁定禁止）")
    await Tortoise.close_connections()
    return problems


def _tortoise_url(dialect: str, url: str) -> str:
    """把命令行传入的 DSN 转成 Tortoise 可用的 db_url。

    mysql/postgres 原样返回（DSN 已是 tortoise 认的 scheme）。
    sqlite 传的是文件路径，需补 ``sqlite://`` 前缀。
    （注意：`--with-amount-seed` 不接受 sqlite——换库场景要有 DROP/CREATE DATABASE，
    sqlite 无此语义；SQLite 侧覆盖在 tests/test_spec005_migration_data.py。）
    """
    if dialect in ("mysql", "postgres"):
        return url
    return url if url.startswith("sqlite://") else f"sqlite://{url}"


async def run_amount_seed(dialect: str, url: str) -> int:
    if dialect == "sqlite":
        # `_recreate_database` 只实现了 mysql/postgres（sqlite 没有 DROP/CREATE DATABASE
        # 语义，换库靠换文件）。本场景的 CI 目标是 mysql/postgres 两个真容器 job；
        # SQLite 侧的等价覆盖在 tests/test_spec005_migration_data.py（内存库，四用例）。
        print("!! --with-amount-seed 只支持 mysql/postgres；"
              "SQLite 请跑 tests/test_spec005_migration_data.py", file=sys.stderr)
        return 2
    problems = await _amount_seed_scenario(dialect, url)
    if problems:
        print(f"!! {dialect} 数据换算断言失败：", file=sys.stderr)
        for p in problems:
            print(f"   - {p}", file=sys.stderr)
        return 1
    print(f"  OK {dialect}：非空 orders 表精确换算 {len(AMOUNT_SEEDS)} 条 + "
          f"半分尾数中止验证，全部通过")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    existing = "--existing" in argv
    with_seed = "--with-amount-seed" in argv
    args = [a for a in argv if a not in ("--existing", "--with-amount-seed")]
    if not args:
        print(__doc__)
        return 2
    dialect = args[0].lower()
    if dialect not in ("sqlite", "mysql", "postgres"):
        print(f"!! 不支持的方言: {dialect}", file=sys.stderr)
        return 2

    url = args[1] if len(args) > 1 else None
    if url is None:
        print("!! 需要数据库连接串", file=sys.stderr)
        return 2

    try:
        if with_seed:
            return asyncio.run(run_amount_seed(dialect, url))
        return asyncio.run(run(dialect, url, existing))
    except Exception as exc:  # 跑不通必须报错，不能静默通过
        print(f"!! 检查失败（脚本或数据库错误）: {exc!r}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
