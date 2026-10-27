#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
在真实方言（MySQL 8 / PostgreSQL 16 / SQLite）上验证时区契约。

对应 ``docs/timezone.md`` 的三条约定：

1. 存储为 UTC aware；
2. 输出带偏移的 ISO 8601；
3. naive 输入按 UTC 解释，带偏移的换算成 UTC。

用法::

    python scripts/check_timezone_dialects.py mysql    "mysql://root:root@127.0.0.1:3306/tzcheck"
    python scripts/check_timezone_dialects.py postgres "postgres://postgres:root@127.0.0.1:5432/tzcheck"
    python scripts/check_timezone_dialects.py sqlite   "sqlite://:memory:"   # 本地自查

退出码：
    0  全部通过
    1  契约不符
    2  用法/连接错误

## 为什么走 ORM 模型而不是裸 SQL

第一版用「脚本自己写的 `_to_aware_utc()` 解析 + 字面量拼 INSERT」——那是**自己证明
自己**：断言的输入和实现都在这一个文件里，测不出应用的转换路径是否有问题。

现在改为：把**原始文本**直接交给 Tortoise 的 `DatetimeField`，让 ORM 自己解析
（这正是 `Customer.create(onboarded_at="2026-12-01T10:00:00+08:00")` 走的路径），
写库、读回、再断言。这样测的是**应用真正依赖的那条链路**。

## 为什么必须在真方言上跑

SQLite 上 Tortoise 会自己把值归一成 UTC aware，本地绿不代表 MySQL 也对——
MySQL 的 ``DATETIME`` **本身不带时区**，全靠 ORM 在写入前转好。
"""
from __future__ import annotations

import asyncio
import datetime
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

#: (原始输入文本, 期望的 UTC 时刻, 说明)
#: **输入保持为字符串**——由 ORM 解析，不由本脚本解析。
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

TZ_SHANGHAI = datetime.timezone(datetime.timedelta(hours=8))
TZ_TOKYO = datetime.timezone(datetime.timedelta(hours=9))


async def _run(dialect: str, url: str) -> int:
    from tortoise import Tortoise

    from tz_probe_model import TzProbe

    await Tortoise.init(
        config={
            "connections": {"default": url},
            "apps": {"models": {
                "models": ["tz_probe_model"],
                "default_connection": "default",
            }},
        },
        use_tz=False,  # [负向验证临时改动]
        timezone="UTC",
    )
    conn = Tortoise.get_connection("default")
    failures: list[str] = []

    # 表结构按方言区分：MySQL 的 DATETIME 不带时区（这正是要验证的点），
    # PG 用 TIMESTAMPTZ，SQLite 用 TEXT。**只在这里用 DDL**，数据读写全走 ORM。
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
            # **关键**：把原始字符串交给 ORM，由 DatetimeField 自己解析与转换。
            # 不做任何本脚本侧的预处理——那会变成自己证明自己。
            obj = await TzProbe.create(ts=raw)
            got = await TzProbe.get(id=obj.id)

            if got.ts is None:
                failures.append(f"{label}: 读回为 None")
                continue
            if got.ts.tzinfo is None:
                failures.append(
                    f"{label}: 读回是 naive（{got.ts!r}）——{dialect} 上没有归一到 aware"
                )
                continue
            if got.ts != expected:
                failures.append(
                    f"{label}: 期望 {expected.isoformat()}，实际 {got.ts.isoformat()}"
                )
                continue
            text = got.ts.isoformat()
            if "T" not in text:
                failures.append(f"{label}: 输出 {text!r} 缺少 T 分隔符")
            elif not (text.endswith("+00:00") or text.endswith("Z")):
                failures.append(f"{label}: 输出 {text!r} 缺少 UTC 偏移")
            else:
                print(f"  OK  {dialect:9s} {label:28s} -> {text}")

        # 跨时区一致性：同一绝对时刻用不同偏移写入，读回必须相同
        a = await TzProbe.create(ts=datetime.datetime(2026, 12, 1, 10, 0, tzinfo=TZ_SHANGHAI))
        b = await TzProbe.create(ts=datetime.datetime(2026, 12, 1, 11, 0, tzinfo=TZ_TOKYO))
        ra = await TzProbe.get(id=a.id)
        rb = await TzProbe.get(id=b.id)
        if ra.ts != rb.ts:
            failures.append(
                f"跨时区一致性失败：+08:00 的 10:00 读回 {ra.ts.isoformat()}，"
                f"+09:00 的 11:00 读回 {rb.ts.isoformat()}——本应相同"
            )
        else:
            print(f"  OK  {dialect:9s} 跨时区一致                    -> {ra.ts.isoformat()}")
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
