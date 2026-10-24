#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
在真实方言（MySQL 8 / PostgreSQL 16）上验证时区契约。

对应 ``docs/timezone.md`` 的三条约定：

1. 存储为 UTC aware；
2. 输出带偏移的 ISO 8601；
3. naive 输入按 UTC 解释，带偏移的换算成 UTC。

用法::

    python scripts/check_timezone_dialects.py mysql    "mysql://root:root@127.0.0.1:3306/tzcheck"
    python scripts/check_timezone_dialects.py postgres "postgres://postgres:root@127.0.0.1:5432/tzcheck"
    python scripts/check_timezone_dialects.py sqlite   "sqlite://:memory:"   # 本地自查用

退出码：
    0  全部通过
    1  契约不符
    2  用法/连接错误

**为什么单独一个脚本**：SQLite 上 Tortoise 会自己把值归一成 UTC aware，所以本地
测试跑绿不代表 MySQL 也对——MySQL 的 ``DATETIME`` **本身不带时区**，依赖 ORM
在写入前转好。这里用**真实 Tortoise 连接**（不是裸 SQL）打到各方言上验证，
因为要测的正是 ORM 的转换行为。

实现方式：不定义 ORM 模型（``__main__`` 里的局部模型类 Tortoise 不认），
而是用 ``conn.execute_script`` 建表 + ``conn.execute_query_dict`` 读写，
再手工按 ORM 的语义把值送进 ``Tortoise`` 的字段转换路径。
"""
from __future__ import annotations

import asyncio
import datetime
import sys

#: 用于断言的样例值
TZ_SHANGHAI = datetime.timezone(datetime.timedelta(hours=8))
TZ_TOKYO = datetime.timezone(datetime.timedelta(hours=9))

#: (原始输入文本, 期望的 UTC 时刻, 说明)
CASES = [
    ("2026-12-01T10:00:00",
     datetime.datetime(2026, 12, 1, 10, 0, tzinfo=datetime.timezone.utc),
     "naive 输入按 UTC 解释"),
    ("2026-12-01T10:00:00+08:00",
     datetime.datetime(2026, 12, 1, 2, 0, tzinfo=datetime.timezone.utc),
     "+08:00 输入换算成 UTC"),
    ("2026-12-01T10:00:00Z",
     datetime.datetime(2026, 12, 1, 10, 0, tzinfo=datetime.timezone.utc),
     "Z 后缀等同 +00:00"),
]


def _to_aware_utc(text: str) -> datetime.datetime:
    """按 API 契约把输入文本转成 UTC aware（naive 视为 UTC）。"""
    dt = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


async def _run(dialect: str, url: str) -> int:
    from tortoise import Tortoise
    from tortoise.backends.base.client import BaseDBAsyncClient

    # 用连接字典 + 空 app 的形式：本脚本只要连接，不需要 ORM 模型
    await Tortoise.init(
        config={
            "connections": {"default": url},
            "apps": {"models": {"models": [], "default_connection": "default"}},
        },
        use_tz=True,
        timezone="UTC",
    )
    conn: BaseDBAsyncClient = Tortoise.get_connection("default")
    failures: list[str] = []

    # 表结构按方言区分：MySQL 的 DATETIME 不带时区（这正是要验证的点），
    # PG 用 TIMESTAMPTZ，SQLite 用 TEXT。
    ddl_map = {
        "mysql": "CREATE TABLE tz_probe (id INT PRIMARY KEY AUTO_INCREMENT, "
                 "ts DATETIME(6) NULL)",
        "postgres": "CREATE TABLE tz_probe (id SERIAL PRIMARY KEY, "
                    "ts TIMESTAMPTZ NULL)",
        "sqlite": "CREATE TABLE tz_probe (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                  "ts TEXT NULL)",
    }
    try:
        await conn.execute_script("DROP TABLE IF EXISTS tz_probe")
        await conn.execute_script(ddl_map[dialect])

        for raw, expected, label in CASES:
            sent = _to_aware_utc(raw)
            # 走 Tortoise 的字段转换（与 ORM 写入同一条路径）
            from tortoise.fields import DatetimeField
            field = DatetimeField(null=True)
            to_db = field.to_db_value(sent, conn)
            await conn.execute_script(
                f"INSERT INTO tz_probe (ts) VALUES ('{to_db}')"
            )
            rows = await conn.execute_query_dict(
                "SELECT ts FROM tz_probe ORDER BY id DESC LIMIT 1"
            )
            back = field.to_python_value(rows[0]["ts"])
            if back is None:
                failures.append(f"{label}: 读回为 None")
                continue
            if back.tzinfo is None:
                failures.append(
                    f"{label}: 读回是 naive（{back!r}）——{dialect} 上没有归一到 aware"
                )
                continue
            if back != expected:
                failures.append(
                    f"{label}: 期望 {expected.isoformat()}，实际 {back.isoformat()}"
                )
                continue
            text = back.isoformat()
            if "T" not in text:
                failures.append(f"{label}: 输出 {text!r} 缺少 T 分隔符")
            elif not (text.endswith("+00:00") or text.endswith("Z")):
                failures.append(f"{label}: 输出 {text!r} 缺少 UTC 偏移")
            else:
                print(f"  OK  {dialect:9s} {label:28s} -> {text}")
                print(f"              (写入库中的原始值: {to_db!r})")

        # 跨时区一致性：同一绝对时刻用不同偏移写入，读回必须相同
        from tortoise.fields import DatetimeField
        field = DatetimeField(null=True)
        a_val = datetime.datetime(2026, 12, 1, 10, 0, tzinfo=TZ_SHANGHAI)
        b_val = datetime.datetime(2026, 12, 1, 11, 0, tzinfo=TZ_TOKYO)
        for v in (a_val, b_val):
            await conn.execute_script(
                f"INSERT INTO tz_probe (ts) VALUES ('{field.to_db_value(v, conn)}')"
            )
        rows = await conn.execute_query_dict(
            "SELECT ts FROM tz_probe ORDER BY id DESC LIMIT 2"
        )
        ra = field.to_python_value(rows[1]["ts"])
        rb = field.to_python_value(rows[0]["ts"])
        if ra != rb:
            failures.append(
                f"跨时区一致性失败：+08:00 的 10:00 读回 {ra.isoformat()}，"
                f"+09:00 的 11:00 读回 {rb.isoformat()}——本应相同"
            )
        else:
            print(f"  OK  {dialect:9s} 跨时区一致                    -> {ra.isoformat()}")
    finally:
        try:
            await conn.execute_script("DROP TABLE IF EXISTS tz_probe")
        except Exception:
            pass
        await Tortoise.close_connections()

    if failures:
        print(f"\n!! {dialect} 时区契约不符（{len(failures)} 项）：", file=sys.stderr)
        for f in failures:
            print(f"   - {f}", file=sys.stderr)
        return 1
    print(f"\n{dialect}: 时区契约全部通过")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    dialect, url = args
    if dialect not in ("mysql", "postgres", "sqlite"):
        print(f"!! 不支持的方言：{dialect}", file=sys.stderr)
        return 2
    try:
        return asyncio.run(_run(dialect, url))
    except Exception as exc:
        print(f"!! 连接或执行失败（{dialect}）：{exc!r}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
