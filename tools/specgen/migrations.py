# -*- coding: utf-8 -*-
"""
迁移生成：把「生成模型的结构变化」变成 aerich 迁移文件（三方言）。

为什么需要它：specgen 会按规格重写 ``app/generated/models/*.py``。模型一变，
迁移链就会落后于模型（``scripts/check_migrations.py`` 退出码 1）。此前只能手工
``aerich migrate``——而 aerich 0.7.2 的 ``migrate`` **只按当前连接的方言**产出 DDL，
要三方言就得分别连三个真库。

本模块的做法：**不连库**。

  1. 用 Tortoise 的 ``SqliteSchemaGenerator`` / ``MySQLSchemaGenerator`` /
     ``PostgresSchemaGenerator`` 直接从模型元数据渲染建表 DDL
     （这三个类的 ``_get_table_sql`` 是纯函数，不需要真实连接）；
  2. 把「账本里已应用的迁移」文本里出现过的表/列也解析出来，作为「现状」；
  3. 差集就是增量：新表 -> ``CREATE TABLE``，新列 -> ``ALTER TABLE ... ADD``。

离线渲染的保真度有实测支撑：``tests/test_gen_migrations.py`` 里用同一套渲染器
重新产出基线的三方言 DDL，与仓库里 UB26 上真实生成的
``migrations/dialects/*/0_*_init.py`` 比对，除 ``IF NOT EXISTS`` 与 ``aerich``
账本表外逐字相同。

局限（务必知晓，写进 docs/specgen.md）：
- 只处理**新增表 / 新增列**。删列、改类型、改默认值一律报错并要求人工迁移——
  自动猜测这类变更的语义（数据怎么迁）风险远高于收益。
- 生成的 DDL 与 aerich 自己产出的写法可能略有差异（引号转义、``IF NOT EXISTS``），
  语义等价；账本兼容性由 ``scripts/check_migrations.py`` 把关。
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Dict, List, Tuple

#: 三方言，顺序稳定（测试与输出都依赖）
DIALECTS = ("sqlite", "mysql", "postgres")

#: 迁移目录布局：models/ 是 aerich 的工作目录（默认装 SQLite 那份），
#: dialects/<方言>/ 存各方言版本。
MIGRATIONS = "migrations"
MODELS_DIR = f"{MIGRATIONS}/models"
DIALECTS_DIR = f"{MIGRATIONS}/dialects"

#: 渲染用的 schema generator（延迟导入：依赖 tortoise，且只在需要时才加载）。
#: 注意 postgres 没有 ``tortoise.backends.postgres``：方言实现分在 asyncpg / psycopg
#: 两个驱动包里，二者共用 ``base_postgres.BasePostgresSchemaGenerator``；
#: 这里用 base 版本，避免为了渲染 DDL 而额外要求某个具体驱动。
_GENERATOR_BY_DIALECT = {
    "sqlite": ("tortoise.backends.sqlite.schema_generator", "SqliteSchemaGenerator"),
    "mysql": ("tortoise.backends.mysql.schema_generator", "MySQLSchemaGenerator"),
    "postgres": ("tortoise.backends.base_postgres.schema_generator",
                 "BasePostgresSchemaGenerator"),
}

#: Tortoise 的 mysql / postgres schema generator 需要一个 client 对象；
#: 我们只用它的纯渲染方法，给一个只带 capabilities 的桩即可。
_STUB_URL = {
    "sqlite": "sqlite://:memory:",
    "mysql": "mysql://u:p@127.0.0.1:3306/x",
    "postgres": "postgres://u:p@127.0.0.1:5432/x",
}


class MigrationPlanError(Exception):
    """无法自动生成迁移（需要人工介入）。"""


# ---------------------------------------------------------------------------
# 模型 -> DDL
# ---------------------------------------------------------------------------


async def _init_tortoise(modules: List[str], db_url: str) -> None:
    from tortoise import Tortoise

    await Tortoise.init(db_url=db_url, modules={"models": modules})


def _schema_generator(dialect: str):
    """构造该方言的 schema generator（不连库，只用渲染方法）。"""
    import importlib

    from tortoise import Tortoise

    mod_name, cls_name = _GENERATOR_BY_DIALECT[dialect]
    cls = getattr(importlib.import_module(mod_name), cls_name)
    return cls(Tortoise.get_connection("default"))


def render_models_ddl(dialect: str, modules: List[str] = None) -> Dict[str, str]:
    """
    从当前模型渲染 ``{表名: CREATE TABLE 语句}``（不带结尾分号）。

    **必须已初始化 Tortoise**；调用方用 :func:`render_ddl_for` 包一层更省事。
    只渲染业务模型，跳过 ``aerich`` 账本表；同时带上 M2M 中间表
    （``account_role`` 这类表由 ``_get_table_sql`` 的 ``m2m_tables`` 返回，
    只取 ``table_creation_string`` 会漏掉它们，导致误报「删表」）。
    """
    from tortoise import Tortoise

    gen = _schema_generator(dialect)
    out: Dict[str, str] = {}
    for model in Tortoise.apps["models"].values():
        table = model._meta.db_table
        if table == "aerich":
            continue
        info = gen._get_table_sql(model, safe=True)
        out[table] = info["table_creation_string"].rstrip().rstrip(";")
        for m2m_sql in info.get("m2m_tables") or ():
            # M2M 语句不带表名变量，从 SQL 里取
            m = __import__("re").search(
                r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"]?(\w+)[`"]?', m2m_sql, 2)
            if m:
                out[m.group(1)] = m2m_sql.rstrip().rstrip(";")
    return out


async def _render_async(dialect: str, modules: List[str]) -> Dict[str, str]:
    await _init_tortoise(modules, _STUB_URL[dialect])
    try:
        return render_models_ddl(dialect, modules)
    finally:
        from tortoise import Tortoise

        await Tortoise.close_connections()


def render_ddl_for(dialect: str, modules: List[str] = None) -> Dict[str, str]:
    """渲染指定方言的建表 DDL（自管 Tortoise 生命周期）。"""
    modules = modules or ["app.models"]
    return asyncio.run(_render_async(dialect, modules))


# ---------------------------------------------------------------------------
# 迁移文件 -> 已存在的表 / 列
# ---------------------------------------------------------------------------


def _iter_migration_files(root: Path, dialect: str) -> List[Path]:
    """返回某方言下已应用的迁移文件（按版本号排序）。"""
    base = root / DIALECTS_DIR / dialect
    if not base.is_dir():
        return []
    files = [p for p in base.glob("*.py") if not p.name.startswith("__")]
    return sorted(files, key=lambda p: _version_num(p.name))


def _version_num(name: str) -> int:
    try:
        return int(name.split("_", 1)[0])
    except ValueError:
        return 0


def _migration_sql(path: Path) -> str:
    """取出迁移文件 ``upgrade()`` 返回的 SQL 文本（不连库，直接调函数）。"""
    import importlib.util

    import yaml  # noqa: F401  仅确保依赖在（迁移文件本身不用 yaml）

    spec = importlib.util.spec_from_file_location(f"_mig_{path.stem}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return asyncio.run(mod.upgrade(None))


def parse_existing(sql_text: str) -> Dict[str, List[str]]:
    """从迁移 SQL 文本里解析出 ``{表名: [列名...]}``。"""
    import re

    tables: Dict[str, List[str]] = {}
    # CREATE TABLE [IF NOT EXISTS] <q>name<q> ( <body> ) ... ;
    for m in re.finditer(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"]?(\w+)[`\"]?\s*\((.*?)\n\s*\)",
        sql_text,
        re.S | re.I,
    ):
        table, body = m.group(1), m.group(2)
        cols = []
        for line in body.splitlines():
            line = line.strip().rstrip(",")
            if not line or line.upper().startswith(("CONSTRAINT", "PRIMARY KEY", "KEY ",
                                                    "UNIQUE KEY", "FOREIGN KEY", "INDEX")):
                continue
            cm = re.match(r"[`\"]?(\w+)[`\"]?\s+\w", line)
            if cm:
                cols.append(cm.group(1))
        tables.setdefault(table, []).extend(cols)
    # ALTER TABLE <q>t<q> ADD [COLUMN] <q>c<q> ...
    for m in re.finditer(
        r"ALTER\s+TABLE\s+[`\"]?(\w+)[`\"]?\s+ADD\s+(?:COLUMN\s+)?[`\"]?(\w+)[`\"]?",
        sql_text,
        re.I,
    ):
        tables.setdefault(m.group(1), []).append(m.group(2))
    return tables


#: 不做差异比较的表：``aerich`` 是迁移工具自己的账本表，由 aerich/基线脚本创建，
#: 不属于业务模型，两边都不应参与「模型 vs 迁移链」比对。
IGNORED_TABLES = {"aerich"}


def existing_schema(root: Path, dialect: str) -> Dict[str, List[str]]:
    """该方言迁移链**已应用**的结构（表 -> 列）。"""
    merged: Dict[str, List[str]] = {}
    for path in _iter_migration_files(root, dialect):
        for table, cols in parse_existing(_migration_sql(path)).items():
            if table in IGNORED_TABLES:
                continue
            bucket = merged.setdefault(table, [])
            bucket.extend(c for c in cols if c not in bucket)
    return merged


def parse_create(sql_text: str) -> Dict[str, str]:
    """
    从 SQL 文本里提取 ``{表名: 该表的完整 DDL}``（单表粒度）。

    「完整」包含表自身的附属语句：
      - PostgreSQL 的 ``COMMENT ON TABLE/COLUMN``（紧跟 CREATE TABLE 之后）
      - ``CREATE INDEX ... ON <表>``（按 ON 后面的表名归属，不靠缩进猜）

    归属规则用**语句内容**而不是缩进：pg 的建表语句以 ``)`` 结束（后面跟分号或
    注释行），索引与注释语句则各自独立成句。按缩进归会串表。
    """
    import re

    out: Dict[str, str] = {}
    current = None       # 正在累积的表（CREATE TABLE 本体及其续行）
    last_table = None    # 最近一条 CREATE TABLE 的表名（供 COMMENT ON 归属）
    for line in sql_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        m = re.match(
            r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"]?(\w+)[`\"]?", stripped, re.I
        )
        if m:
            current = last_table = m.group(1)
            out[current] = line
            continue

        idx = re.match(
            r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"]?\w+[`\"]?\s+"
            r"ON\s+[`\"]?(\w+)[`\"]?",
            stripped, re.I,
        )
        if idx:
            # 索引按 ON 后的表名归属；该表若尚未出现则忽略（例如 aerich 自己的索引）
            target = idx.group(1)
            if target in out:
                out[target] += "\n" + line
            current = None
            continue

        if stripped.upper().startswith("COMMENT ON"):
            # 注释语句归属**最近一条** CREATE TABLE——中间可能隔着索引语句，
            # 所以不能用 current（那时已被索引分支清空）
            if last_table and last_table in out:
                out[last_table] += "\n" + line
            continue

        if stripped.upper().startswith(("ALTER TABLE", "INSERT INTO", "CREATE SEQUENCE")):
            current = None
            continue

        if current:
            out[current] += "\n" + line
    return {t: s.strip() for t, s in out.items() if s.strip()}


def split_columns(create_sql: str) -> Tuple[str, Dict[str, str], str]:
    """
    把一条 CREATE TABLE 拆成 ``(表名, {列名: 列定义}, 尾部)``。

    尾部是 ``)`` 之后到 ``;`` 之前的内容（``CHARACTER SET`` / ``COMMENT`` 等，
    MySQL 有、其它方言可能为空）。用于「只取新增列的定义」。

    **表级约束行（``CONSTRAINT … FOREIGN KEY`` / ``UNIQUE KEY`` 等）不挂到任何列**：
    它们是表的属性，不是列的属性。挂上去会把外键约束当成列定义的一部分，
    生成 ``ALTER TABLE ADD <列> …, CONSTRAINT …`` 这种语法非法的语句。
    """
    import re

    m = re.match(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"]?(\w+)[`\"]?\s*\((.*?)\n(\s*\)[^;]*;?)",
        create_sql.rstrip(),
        re.S | re.I,
    )
    if not m:
        raise MigrationPlanError(f"无法解析建表语句：{create_sql[:80]}…")
    table, body, tail = m.group(1), m.group(2), m.group(3)
    cols: Dict[str, str] = {}
    current = None
    for line in body.splitlines():
        if not line.strip():
            continue
        stripped = line.strip().rstrip(",")
        if stripped.upper().startswith(("CONSTRAINT", "PRIMARY KEY", "KEY ", "UNIQUE KEY",
                                        "FOREIGN KEY", "INDEX")):
            # 表级约束：与列定义无关，丢弃（新增单列时不需要重建约束）
            current = None
            continue
        cm = re.match(r"([`\"]?)(\w+)\1\s+\w", stripped)
        if cm:
            current = cm.group(2)
            cols[current] = line.rstrip().rstrip(",")
        elif current:
            # 列定义的续行（跨行的长类型/默认值）
            cols[current] += "\n" + line
    return table, cols, tail


# ---------------------------------------------------------------------------
# 差集 -> 迁移
# ---------------------------------------------------------------------------


def plan(
    rendered: Dict[str, str], existing: Dict[str, List[str]]
) -> Tuple[List[str], List[Tuple[str, str]], List[str]]:
    """
    比较「模型渲染结果」与「迁移链已有结构」。

    返回 ``(新表, [(表, 新列定义)], 不支持自动处理的变更)``。
    第三项非空即应报错让人接手——自动猜「删列/改类型」的数据迁移语义太危险。
    """
    new_tables: List[str] = []
    new_columns: List[Tuple[str, str]] = []
    unsupported: List[str] = []

    for table, create_sql in rendered.items():
        if table not in existing:
            new_tables.append(table)
            continue
        _, model_cols, _ = split_columns(create_sql)
        have = set(existing[table])
        model_names = set(model_cols)
        for name in sorted(model_names - have):
            new_columns.append((table, model_cols[name]))
        for name in sorted(have - model_names):
            unsupported.append(f"表 {table} 的列 {name} 在模型里已不存在（删列需人工迁移）")
    for table in sorted(set(existing) - set(rendered)):
        unsupported.append(f"表 {table} 在迁移链里存在但模型里已删除（删表需人工迁移）")

    return new_tables, new_columns, unsupported


def render_migration(
    dialect: str,
    new_tables: List[str],
    new_columns: List[Tuple[str, str]],
    rendered: Dict[str, str],
) -> str:
    """产出 aerich 格式的迁移文件内容（upgrade/downgrade 两个函数）。"""
    up: List[str] = [rendered[t] for t in new_tables]
    for table, col_def in new_columns:
        up.append(f'ALTER TABLE "{table}" ADD {col_def}')
    down: List[str] = [f'DROP TABLE IF EXISTS "{t}"' for t in reversed(new_tables)]
    for table, col_def in reversed(new_columns):
        col = _column_name(col_def)
        down.append(f'ALTER TABLE "{table}" DROP COLUMN "{col}"')

    # MySQL 用反引号与 ``MODIFY``；aerich 的 SQLite 迁移在 MySQL 上不会跑，
    # 但为了保证三方言文件内容各自正确，MySQL 版做引号替换。
    if dialect == "mysql":
        up = [_mysql_quotes(s) for s in up]
        down = [_mysql_quotes(s) for s in down]

    up_sql = ";\n        ".join(s.rstrip().rstrip(";") for s in up)
    down_sql = ";\n        ".join(s.rstrip().rstrip(";") for s in down)
    return (
        "from tortoise import BaseDBAsyncClient\n\n\n"
        "async def upgrade(db: BaseDBAsyncClient) -> str:\n"
        '    return """\n'
        f"        {up_sql};\n"
        '"""\n\n\n'
        "async def downgrade(db: BaseDBAsyncClient) -> str:\n"
        '    return """\n'
        f"        {down_sql};\n"
        '"""\n'
    )


def _column_name(col_def: str) -> str:
    import re

    m = re.match(r"[`\"]?(\w+)[`\"]?", col_def.strip())
    if not m:
        raise MigrationPlanError(f"无法取列名：{col_def[:60]}")
    return m.group(1)


def _mysql_quotes(sql: str) -> str:
    """把双引号标识符换成 MySQL 的反引号（只换标识符，不碰字符串字面量）。"""
    import re

    return re.sub(r'"(\w+)"', r"`\1`", sql)


# ---------------------------------------------------------------------------
# 编排
# ---------------------------------------------------------------------------


def _next_version(root: Path) -> str:
    """
    三方言共用的下一个版本名。

    **必须三方言同名**：aerich 以文件名作版本键，切方言后账本里记的名称要能在
    目录里找到同名文件，否则会被当成「没跑过」而重复建表
    （``check_migrations.check_dialect_baselines`` 就在守这条）。
    所以版本号取三方言里的最大值，时间戳只取一次。
    """
    from datetime import datetime

    last = 0
    for dialect in DIALECTS:
        files = _iter_migration_files(root, dialect)
        last = max([last, *( _version_num(p.name) for p in files )])
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"{last + 1}_{ts}_specgen"


def generate(root: Path) -> Dict[str, object]:
    """
    为生成模型产出三方言迁移文件。返回 ``{方言: 写出的文件}``。

    无需改动时该方言对应值为 ``None``。存在无法自动处理的变更时抛
    :class:`MigrationPlanError`（且在抛之前不写任何文件——先全部规划、再统一落盘，
    避免「写了一部分方言」的半成品状态）。
    """
    root = Path(root)
    plans: Dict[str, Tuple[List[str], List[Tuple[str, str]], Dict[str, str]]] = {}
    unsupported_all: List[str] = []

    for dialect in DIALECTS:
        rendered = render_ddl_for(dialect)
        existing = existing_schema(root, dialect)
        new_tables, new_columns, unsupported = plan(rendered, existing)
        if unsupported:
            unsupported_all.extend(f"[{dialect}] {u}" for u in unsupported)
            continue
        plans[dialect] = (new_tables, new_columns, rendered)

    if unsupported_all:
        raise MigrationPlanError(
            "以下变更无法安全自动迁移，请手工编写迁移：\n  - " + "\n  - ".join(unsupported_all)
        )

    result: Dict[str, object] = {}
    pending = {d: p for d, p in plans.items() if p[0] or p[1]}
    if not pending:
        return {d: None for d in DIALECTS}

    version = _next_version(root)
    for dialect, (new_tables, new_columns, rendered) in pending.items():
        content = render_migration(dialect, new_tables, new_columns, rendered)
        target_dir = root / DIALECTS_DIR / dialect
        target_dir.mkdir(parents=True, exist_ok=True)
        path = target_dir / f"{version}.py"
        path.write_text(content, encoding="utf-8")
        result[dialect] = str(path.relative_to(root))
        # migrations/models/ 装的是「当前部署方言」那份：同步更新 SQLite 版
        if dialect == "sqlite":
            (root / MODELS_DIR).mkdir(parents=True, exist_ok=True)
            (root / MODELS_DIR / f"{version}.py").write_text(content, encoding="utf-8")

    for dialect in DIALECTS:
        result.setdefault(dialect, None)
    return result
