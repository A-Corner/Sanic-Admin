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
from typing import Dict, List, Optional, Tuple

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

#: Tortoise 初始化用的 URL —— **三方言一律 sqlite 内存库**。
#:
#: 模型元数据（表名、列、类型、FK）与连接方言无关，Tortoise 只需一个能导入的
#: 后端来建立模型注册表。用 `mysql://` 会 `import aiomysql`、`postgres://` 会
#: `import asyncpg`——生成迁移的机器（尤其 CI）没装这些驱动，会直接失败。
#: 真正决定 DDL 方言的是 :func:`_schema_generator` 里选的 generator 类。
_STUB_URL = dict.fromkeys(("sqlite", "mysql", "postgres"), "sqlite://:memory:")


class MigrationPlanError(Exception):
    """无法自动生成迁移（需要人工介入）。"""


# ---------------------------------------------------------------------------
# 模型 -> DDL
# ---------------------------------------------------------------------------


async def _init_tortoise(modules: List[str], db_url: str) -> None:
    from tortoise import Tortoise

    await Tortoise.init(db_url=db_url, modules={"models": modules})


class _SchemaOnlyClient:
    """
    只够渲染用的桩 client。

    为什么需要它：`_get_table_sql` 是纯函数，只用 client 的 `capabilities` 与
    `schema_generator`。但 `Tortoise.get_connection()` 会按 URL scheme 实例化
    **真实驱动**——`mysql://` 会去 `import aiomysql`，`postgres://` 会 `import asyncpg`。
    生成迁移的机器不需要装这些驱动（CI 就没装），一次 `specgen migrate` 会因为
    缺驱动失败。

    这个桩提供渲染所需的最小表面，让「渲染」与「连接」彻底解耦。
    """

    def __init__(self, dialect: str):
        self.capabilities = type("Caps", (), {
            "dialect": dialect,
            "support_for_update": False,
            "support_index_hint": False,
            "support_nowait": False,
            "support_json_attributes": False,
            "can_rollback_ddl": False,
            "inline_comment": dialect in ("mysql", "sqlite"),
            "schema": None,
        })()
        # MySQL 的 `_table_generate_extra` 读 `client.charset`（决定
        # `CHARACTER SET utf8mb4` 那一行）。真实 client 从连接串取，这里给项目
        # 统一用的 utf8mb4 —— 与基线 DDL 里出现的一致。
        self.charset = "utf8mb4" if dialect == "mysql" else None
        self.schema_generator = None  # 由 _schema_generator 回填


def _load_generator_class(dialect: str):
    """
    加载该方言的 schema generator **类**，不触发驱动的包级 import。

    坑：`import tortoise.backends.mysql.schema_generator` 会先执行包
    `__init__.py`，而它写着 `from .client import MySQLClient` → `import aiomysql`。
    也就是说只要走正常 import，没装驱动的机器（CI）就跑不了。

    `schema_generator.py` 自己的模块级 import 是干净的（client 只在
    `TYPE_CHECKING` 下引入），所以这里用 `spec_from_file_location` 直接按文件路径
    加载，绕过包的 `__init__`。
    """
    import importlib.util
    from pathlib import Path

    import tortoise

    # 版本断言：本模块依赖 tortoise 0.20 的 _get_table_sql 返回结构
    # （含 m2m_tables/schema_generator 私有方法）。0.21+ 改过签名，
    # 渲染结果可能不再可信——明确报错比静默产出错误 DDL 安全。
    from importlib.metadata import version as _pkg_version

    _tv = _pkg_version("tortoise-orm")
    if not _tv.startswith("0.20."):
        raise MigrationPlanError(
            f"迁移生成依赖 tortoise-orm 0.20.x 的渲染接口，当前安装 {_tv}。"
            f"升级 tortoise 后需同步复核 tools/specgen/migrations.py 的 "
            f"_get_table_sql 用法（含 m2m_tables 与 schema_generator 私有方法）。")

    mod_rel, cls_name = _GENERATOR_BY_DIALECT[dialect]
    # "tortoise.backends.mysql.schema_generator" -> <tortoise 包>/backends/mysql/schema_generator.py
    parts = mod_rel.split(".")
    file_path = Path(tortoise.__file__).parent.joinpath(*parts[1:-1], parts[-1] + ".py")
    if not file_path.is_file():
        raise MigrationPlanError(f"找不到 {dialect} 的 schema generator：{file_path}")

    spec = importlib.util.spec_from_file_location(f"_specgen_{dialect}_sg", file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return getattr(module, cls_name)


def _schema_generator(dialect: str):
    """
    构造该方言的 schema generator（**不连库、不 import 驱动**）。

    用 :class:`_SchemaOnlyClient` 作为 client 桩，而不是
    `Tortoise.get_connection("default")`——后者会按 URL 加载真实驱动。
    """
    cls = _load_generator_class(dialect)
    client = _SchemaOnlyClient(dialect)
    gen = cls(client)
    client.schema_generator = gen
    return gen


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
    return {t: list(d) for t, d in parse_existing_definitions(sql_text).items()}


def _create_stmt_with_followups(sql_text: str, table: str) -> str:
    """
    从整段迁移 SQL 里取出「某表的 CREATE TABLE + 其后的 COMMENT ON 语句」。

    PG 的列注释在 `CREATE TABLE` 之后独立成句，`split_columns` 需要它们才能
    把注释归并回列。历史迁移里表与注释可能隔着索引语句，所以这里按
    「从 CREATE TABLE 起，到下一个非 COMMENT/非本表的语句前」截取。
    """
    import re

    m = re.search(
        r"(CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"]?" + re.escape(table)
        + r"[`\"]?\s*\(.*?\n\s*\)[^;]*;)",
        sql_text, re.S | re.I,
    )
    if not m:
        return ""
    stmt = m.group(1)
    # 收集该表后续的 COMMENT ON COLUMN / COMMENT ON TABLE
    for cmt in re.finditer(
        r"COMMENT\s+ON\s+(?:COLUMN\s+)?[`\"]?" + re.escape(table) + r"[`\"]?"
        r"(?:\s*\.\s*[`\"]?\w+[`\"]?)?\s+IS\s+'(?:[^']|'')*'\s*;",
        sql_text, re.I,
    ):
        stmt += "\n" + cmt.group(0)
    return stmt


def parse_existing_definitions(sql_text: str) -> Dict[str, Dict[str, str]]:
    """
    从迁移 SQL 文本里解析出 ``{表名: {列名: 列定义}}``。

    保留完整定义（不只列名），供 :func:`plan` 比较「同一列的定义是否变了」——
    只比列名会把「改类型 / 改默认值 / 加 UNIQUE」全部静默放过。
    """
    import re

    tables: Dict[str, Dict[str, str]] = {}
    # CREATE TABLE [IF NOT EXISTS] <q>name<q> ( <body> ) ... ;
    # 先用一个**宽松**的表名扫描找出所有表，再逐表尝试完整解析：
    # 外层用严格正则过滤的话，写法不合（例如单行 `CREATE TABLE t (id INT)`，
    # 没有 `\n )`）的表会被**静默跳过**——比降级告警更糟，因为完全无声。
    found = {
        m.group(1)
        for m in re.finditer(
            r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"]?(\w+)[`\"]?",
            sql_text, re.I)
    }
    for table in sorted(found):
        # 复用 split_columns 的解析（含表级 FK/UNIQUE 归并与 PG COMMENT ON 归并），
        # 保证「历史迁移里读到的定义」与「模型渲染的定义」用同一套口径解析。
        full = _create_stmt_with_followups(sql_text, table)
        if not full:
            # 严格正则匹配不到（例如单行写法）。这里**降级**：只记录该表存在、
            # 跳过列级解析，而不是让 split_columns 抛 MigrationPlanError 把整个
            # 迁移生成打断——一张表解析不出来不该拖垮其它表。但必须说清后果。
            tables.setdefault(table, {})
            import warnings

            warnings.warn(
                f"迁移链里表 {table} 的 CREATE TABLE 无法解析出列定义，"
                f"已降级为「只记录表存在」。该表的列变更将无法自动检测，"
                f"请人工核对。源 SQL 片段：{sql_text[:120]!r}",
                RuntimeWarning, stacklevel=2)
            continue
        _tname, cols, _tail = split_columns(full)
        tables.setdefault(table, {}).update(cols)
    # ALTER TABLE <q>t<q> ADD [COLUMN] <q>c<q> <定义>
    for m in re.finditer(
        r"ALTER\s+TABLE\s+[`\"]?(\w+)[`\"]?\s+ADD\s+(?:COLUMN\s+)?([`\"]?\w+[`\"]?\s+[^;]+)",
        sql_text,
        re.I,
    ):
        table, rest = m.group(1), m.group(2).strip()
        cm = re.match(r"[`\"]?(\w+)[`\"]?", rest)
        if cm:
            tables.setdefault(table, {})[cm.group(1)] = rest
    return tables


#: 不做差异比较的表：``aerich`` 是迁移工具自己的账本表，由 aerich/基线脚本创建，
#: 不属于业务模型，两边都不应参与「模型 vs 迁移链」比对。
IGNORED_TABLES = {"aerich"}


def existing_schema(root: Path, dialect: str) -> Dict[str, List[str]]:
    """该方言迁移链**已应用**的结构（表 -> 列名）。"""
    return {
        t: list(d) for t, d in existing_definitions(root, dialect).items()
    }


def existing_definitions(root: Path, dialect: str) -> Dict[str, Dict[str, str]]:
    """
    该方言迁移链**已应用**的完整列定义（表 -> {列名: 定义}）。

    与 :func:`existing_schema` 的区别：后者只有列名，够用来判断「有没有新列」，
    但判断不了「同一列的定义是否变了」。plan() 需要后者。
    """
    merged: Dict[str, Dict[str, str]] = {}
    for path in _iter_migration_files(root, dialect):
        for table, cols in parse_existing_definitions(_migration_sql(path)).items():
            if table in IGNORED_TABLES:
                continue
            merged.setdefault(table, {}).update(cols)
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
    把一条 ``CREATE TABLE``（含其后的附属语句）拆成
    ``(表名, {列名: 列定义}, 尾部)``。

    「含附属语句」是关键：
      - **PostgreSQL** 的列注释是 `CREATE TABLE` **之后**独立的
        `COMMENT ON COLUMN "t"."c" IS '..'` 语句，不在列定义里。早先只切到
        `);` 就停，结果真实渲染下新列拿到的注释永远是空 —— 加列的
        `COMMENT ON` 因此永远不会生成（测试用手写 SQL 做输入才「通过」）。
      - **MySQL** 的外键是表级 `CONSTRAINT .. FOREIGN KEY (col) REFERENCES ..`，
        早先丢弃后，新列的外键约束检测只能靠「别的方言也丢」这种跨方言巧合兜住。

    现在：
      - 表级 ``CONSTRAINT ... FOREIGN KEY (col) ...`` 归并回 ``col`` 的定义；
      - 表级 ``UNIQUE KEY (col)`` / ``UNIQUE (col)`` 给 ``col`` 标记 UNIQUE；
      - ``COMMENT ON COLUMN "t"."c" IS '..'`` 转成该列定义里的 ``/* .. */``。

    尾部是 ``)`` 之后到 ``;`` 之前的内容（``CHARACTER SET`` / ``COMMENT`` 等）。
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

        fk = re.match(
            r"CONSTRAINT\s+[`\"]?\w+[`\"]?\s+FOREIGN\s+KEY\s*\(\s*[`\"]?(\w+)[`\"]?\s*\)"
            r"\s+REFERENCES\s+[`\"]?(\w+)[`\"]?\s*\(\s*[`\"]?(\w+)[`\"]?\s*\)"
            r"(?:\s+ON\s+DELETE\s+(\w+(?:\s+\w+)?))?",
            stripped, re.I,
        )
        if fk:
            col, ref_table, ref_col, on_delete = fk.group(1), fk.group(2), fk.group(3), fk.group(4)
            if col in cols:
                cols[col] += (f" REFERENCES \"{ref_table}\" (\"{ref_col}\")"
                              + (f" ON DELETE {on_delete}" if on_delete else ""))
            current = None
            continue

        # 表级唯一约束：可能是复合的 `(a, b)`。单列才归并回列；复合约束不产生列。
        uq = re.match(
            r"(?:UNIQUE\s+KEY\s+[`\"]?\w+[`\"]?|UNIQUE|CONSTRAINT\s+[`\"]?\w+[`\"]?\s+UNIQUE)"
            r"\s*\(([^)]*)\)",
            stripped, re.I,
        )
        if uq:
            names = [x.strip().strip("`\"") for x in uq.group(1).split(",") if x.strip()]
            if len(names) == 1 and names[0] in cols and "UNIQUE" not in cols[names[0]].upper():
                cols[names[0]] += " UNIQUE"
            current = None
            continue

        # 其余表级约束一律跳过：不能落进「列定义」分支，否则会造出名为
        # UNIQUE / KEY / CONSTRAINT / CHECK 的伪列。
        if stripped.upper().startswith((
                "PRIMARY KEY", "UNIQUE", "KEY ", "FOREIGN KEY", "INDEX",
                "CONSTRAINT", "CHECK", "FULLTEXT", "SPATIAL")):
            current = None
            continue

        cm = re.match(r"([`\"]?)(\w+)\1\s+\w", stripped)
        if cm:
            current = cm.group(2)
            cols[current] = line.rstrip().rstrip(",")
        elif current:
            # 列定义的续行（跨行的长类型/默认值）
            cols[current] += "\n" + line

    # PostgreSQL：把表后的 COMMENT ON COLUMN 归并回列定义
    for cmt in re.finditer(
        r"COMMENT\s+ON\s+COLUMN\s+[`\"]?(\w+)[`\"]?\.\s*[`\"]?(\w+)[`\"]?\s+IS\s+'((?:[^']|'')*)'",
        create_sql, re.I,
    ):
        tbl, col, text = cmt.group(1), cmt.group(2), cmt.group(3)
        if tbl.lower() != table.lower():
            continue
        if col in cols and "/*" not in cols[col]:
            cols[col] += f" /* {text.replace(chr(39)*2, chr(39))} */"

    return table, cols, tail


# ---------------------------------------------------------------------------
# 差集 -> 迁移
# ---------------------------------------------------------------------------


def normalize_column_def(col_def: str) -> str:
    """
    把列定义规范化成一个可比较的串：类型 + 非空 + 默认值 + 唯一 + 外键目标。

    只保留语义项，丢掉引号、多余空白、注释（`/* */` 与 MySQL 的 `COMMENT '...'`）：
    注释变化不该触发「结构变更」，但类型/默认值/约束变化必须能看出来。

    **只把关键字转大写，字符串字面量保持原样**：早先整串 `.upper()`，`DEFAULT 'open'`
    改成 `'closed'` 会被误判成「只有大小写差异」而漏报；反过来只改字面量的大小写
    （`'OPEN'` → `'open'`，语义确实变了）也会被抹平。
    """
    import re

    s = col_def.strip().rstrip(",")
    # 去掉行注释与块注释（含 MySQL 的 COMMENT '...'）
    s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)
    s = re.sub(r"\bCOMMENT\s+'(?:[^'\\]|\\.)*'", " ", s, flags=re.I)
    # 统一引号与空白
    s = s.replace("`", '"').replace("\\'", "'")
    s = re.sub(r"\s+", " ", s).strip()
    # 去掉开头的列名（本函数只比较「列定义」部分）
    s = re.sub(r'^"\w+"\s+', "", s)

    # 只对大写单引号之外的片段做 upper，字面量原样保留
    parts = re.split(r"('(?:[^']|'')*')", s)
    return "".join(
        p if i % 2 == 1 else p.upper() for i, p in enumerate(parts)
    )


def _new_column_blocker(col_def: str) -> Optional[str]:
    """
    判断「新增列」是否能用一条 `ALTER TABLE ... ADD` 安全表达；不能则返回原因。

    两类必须拒绝（都在真实数据库上会失败或语义不明）：

    - **带 UNIQUE / 外键**：`ALTER TABLE ADD COLUMN` 的行内 `UNIQUE` 在 PG 与
      SQLite 上不受支持（SQLite 直接报错，PG 会忽略或建出无名约束），外键同理。
      这类需要 `ADD CONSTRAINT` 单独一条语句，属人工迁移。
    - **NOT NULL 且无 DEFAULT**：已有行没有值可填，ALTER 会因非空约束失败。
      要么给 default，要么分三步（加可空列 → 回填 → 改非空），后者是人工决定。

    返回 None 表示可以自动生成。
    """
    upper = col_def.upper()
    if "UNIQUE" in upper:
        return "带 UNIQUE 约束的新列需要单独 ADD CONSTRAINT，请手写迁移"
    if "REFERENCES" in upper or "FOREIGN KEY" in upper:
        return "带外键的新列需要单独 ADD CONSTRAINT，请手写迁移"
    not_null = "NOT NULL" in upper
    has_default = "DEFAULT" in upper
    if not_null and not has_default:
        return ("NOT NULL 且无 DEFAULT 的新列会让已有行无值可填，"
                "请在规格里给 default，或手写三步迁移（可空→回填→非空）")
    return None


def plan(
    rendered: Dict[str, str],
    existing: Dict[str, List[str]],
    existing_definitions: Dict[str, Dict[str, str]] = None,
) -> Tuple[List[str], List[Tuple[str, str]], List[str]]:
    """
    比较「模型渲染结果」与「迁移链已有结构」。

    返回 ``(新表, [(表, 新列定义)], 不支持自动处理的变更)``。
    第三项非空即应报错让人接手——自动猜「删列/改类型」的数据迁移语义太危险。

    **不只比列名**：早先只对列名做集合差，改类型、改默认值、加 UNIQUE 都会被
    静默放过，生成「无需迁移」的假结论，与文件头承诺不符。现在对**共同列**做
    定义规范化后比较，任何不一致都进 unsupported。
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
            col_def = model_cols[name]
            reason = _new_column_blocker(col_def)
            if reason:
                unsupported.append(f"表 {table} 的新列 {name}：{reason}")
            else:
                new_columns.append((table, col_def))
        for name in sorted(have - model_names):
            unsupported.append(f"表 {table} 的列 {name} 在模型里已不存在（删列需人工迁移）")

        # 共同列：定义必须一致（类型/非空/默认值/唯一）
        existing_defs = existing_definitions.get(table, {}) if existing_definitions else {}
        for name in sorted(model_names & have):
            want = normalize_column_def(model_cols[name])
            got = existing_defs.get(name)
            if got is None:
                # 拿不到历史定义时不敢断言一致，保守跳过（只在调用方未提供时发生）
                continue
            if normalize_column_def(got) != want:
                unsupported.append(
                    f"表 {table} 的列 {name} 定义变了（改类型/默认值/唯一约束属人工迁移）："
                    f"迁移链={normalize_column_def(got)!r} 模型={want!r}")
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
        # col_def 来自渲染结果，带前导缩进；直接拼会产出 `ADD     "a"` 这种多余空白
        up.append(f'ALTER TABLE "{table}" ADD {col_def.strip()}')
        # PostgreSQL 的列注释是独立语句，不在列定义里。不补的话新增列会丢注释，
        # 与「模型声明了 description」不一致（PG 基线里每列都有 COMMENT ON）。
        comment = _extract_comment(col_def)
        if dialect == "postgres" and comment:
            col = _column_name(col_def)
            up.append(
                f'COMMENT ON COLUMN "{table}"."{col}" IS '
                f"'{comment.replace(chr(39), chr(39) * 2)}'")
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


def _extract_comment(col_def: str) -> str:
    """从列定义里取出注释文本（MySQL 的 `COMMENT '...'` 或块的 `/* ... */`）。"""
    import re

    m = re.search(r"COMMENT\s+'((?:[^'\\]|\\.)*)'", col_def, re.I)
    if m:
        return m.group(1).replace("\\'", "'")
    m = re.search(r"/\*\s*(.*?)\s*\*/", col_def, re.S)
    if m:
        return m.group(1).strip()
    return ""


def _column_name(col_def: str) -> str:
    import re

    m = re.match(r"[`\"]?(\w+)[`\"]?", col_def.strip())
    if not m:
        raise MigrationPlanError(f"无法取列名：{col_def[:60]}")
    return m.group(1)


def _mysql_quotes(sql: str) -> str:
    """
    把双引号**标识符**换成 MySQL 的反引号，不碰字符串字面量。

    早先用 `re.sub(r'"(\\w+)"', ...)` 一把梭，会把 `COMMENT '如 "foo" 这类'`
    里的 `"foo"` 也换成反引号——注释内容被改坏，且可能把合法字符串改成语法错误。

    做法：先切出单引号字符串（含转义），只对**字符串之外**的片段做替换。
    """
    import re

    parts = re.split(r"('(?:[^'\\]|\\.)*')", sql)
    out = []
    for i, part in enumerate(parts):
        if i % 2 == 1:      # 奇数位是单引号字符串，原样保留
            out.append(part)
        else:
            out.append(re.sub(r'"(\w+)"', r"`\1`", part))
    return "".join(out)


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
        new_tables, new_columns, unsupported = plan(
            rendered, existing, existing_definitions(root, dialect))
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
