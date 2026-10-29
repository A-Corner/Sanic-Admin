#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""SPEC-005 迁移的**非空 orders 表**回归测试（`EVT-20261029-035` / `037`）。

## 为什么必须有这组测试

迁移的 CI 检查（`check_dialect_ddl.py` / `check_migrations.py`）都跑在**空库**上。
空库时 `CASE` 的每个分支一行都不会被命中 —— 两个高严重度缺陷因此全绿通过：

1. **finding 1**：幂等守卫查了 `information_schema` 的 `'orders'`（RENAME 后该名字
   已被**新表**占用），恒命中 → 换算分支成死代码 → 浮点值原样写进 INT 列被静默
   截断，**金额缩水 100 倍**。
2. **finding 2**：断言右侧用 `CAST`（向零截断）。`1.14 * 100 = 113.99999999999999`
   被截成 113，产生 **1.0 的假残差** → 合法金额被判「不精确」→ `ELSE NULL`
   → 迁移中止。

## 判别力自检（改完必须跑，否则不知道测试有没有用）

- 把断言改回 `CAST` → `test_every_seed_value_converts_exactly` 必须红
- 把幂等守卫改回查 `'orders'` → 宿主机是 SQLite，该分支是方言专属 SQL，**本地测不到**，
  只能靠 CI 的 `migrations-dialects` 真容器 + 人工核对 SQL（如实记录此局限）

## 值集（公司 CPL 2026-10-29 指定的种子表）

`12.34` 常规 / `1.14` **关键回归值**（CAST 判死、ROUND 通过）/ `0.01` 最小非零分位 /
`0` 零值边界 / `21474836.47` 32 位 INT 上界 / 负数（业务未禁止，故必须覆盖）。

**负数是否允许的核实**（2026-10-29）：`specs/order.yaml` 无 `min`/`max` 约束；
`tools/specgen/render_py.py:108` 的 `_INT_RULE` 只校验 `type(v) is int`，无范围校验；
`app/generated/models/order.py:17` 的 `IntField` 无约束。**⇒ 业务接受负数，必须覆盖。**

## 「精确等于」与「容差」是两件事（CPL 明确区分）

- **容差 1e-3**：迁移内部用于判断「原值能否精确换算」
- **精确等于**：测试断言换算结果 —— `assert got == round(original * 100)`，
  **不是** `abs(a - b) < eps`。迁移语义就是「精确换算，否则中止」；
  结果还要容差等于承认它可能不准。
"""

import asyncio
import importlib.util
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

MIG = REPO / "migrations" / "models" / "3_20261029063723_spec005_amount_cents.py"
BASELINE = REPO / "migrations" / "dialects" / "sqlite" / "1_20261024153549_specgen.py"

#: CPL 指定的种子表 + 补充的 tricky 值（`*100` 后是 `xxx.999…`，CAST/ROUND 的唯一区分点）
SEEDS = [
    (12.34, 1234),           # 常规值
    (1.14, 114),             # **关键回归值**：1.14*100 = 113.99999999999999
    (2.28, 228),             # 同类：227.99999999999997
    (0.29, 29),              # 同类：28.999999999999996
    (0.57, 57),              # 同类：56.99999999999999
    (19.99, 1999),           # 同类：1998.9999999999998
    (0.01, 1),               # 最小非零分位
    (0, 0),                  # 零值边界
    (21474836.47, 2147483647),  # 32 位 INT 上界
    (-12.34, -1234),         # 负数（业务未禁止，见模块 docstring 的核实）
    (0.1 + 0.2, 30),         # 0.30000000000000004 —— 必须精确为 30
    (100.00, 10000),         # 整数值的浮点金额：值判定会误判成「已换算」
]

#: 无法精确换算（半分尾数）
INEXACT = 12.345


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(coro):
    return asyncio.run(coro)


async def _db_with_seeds(rows):
    """**先**建旧表（amount REAL）+ 插入种子 —— 时序不能反，插在迁移之后测试无意义。"""
    from tortoise import Tortoise

    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": []})
    conn = Tortoise.get_connection("default")
    await conn.execute_script(await _load(BASELINE, "sp005_base").upgrade(conn))
    await conn.execute_script(
        'INSERT OR IGNORE INTO "customer" ("id","name","email","status") '
        "VALUES (1,'c','c@c','active');"
    )
    for i, (yuan, _) in enumerate(rows, 1):
        await conn.execute_script(
            f'INSERT INTO "orders" ("title","amount","quantity","status","customer_id") '
            f"VALUES ('o{i}', {yuan!r}, 1, 'pending', 1);"
        )
    return conn


def _rowcount(conn):
    async def inner():
        old = await conn.execute_query_dict('SELECT COUNT(*) AS c FROM "orders_old"')
        new = await conn.execute_query_dict('SELECT COUNT(*) AS c FROM "orders"')
        return old[0]["c"], new[0]["c"]

    return inner()


def test_every_seed_value_converts_exactly():
    """全部种子值必须**精确等于** `round(原值 × 100)`，且行数不变。

    一次跑完再用 `assert got == round(orig*100)` 精确比较（不是容差比较）。
    把迁移断言改回 `CAST` 时，`1.14/2.28/0.29/0.57/19.99` 会因迁移中止而红。
    """
    os.environ.setdefault("INITIAL_ADMIN_PASSWORD", "Spec005-Test-Pass-1")

    async def inner():
        from tortoise import Tortoise

        conn = await _db_with_seeds(SEEDS)
        try:
            await conn.execute_script(await _load(MIG, "sp005_mig").upgrade(conn))
            got = await conn.execute_query_dict(
                'SELECT "amount" FROM "orders" '
                'ORDER BY CAST(SUBSTR("title", 2) AS INTEGER)'
            )
            assert len(got) == len(SEEDS), (
                f"迁移后行数 {len(got)} != 种子 {len(SEEDS)}——有行被丢"
            )
            wrong = []
            for (orig, exp), row in zip(SEEDS, got):
                want = round(orig * 100)          # 独立算一次，不复用迁移的逻辑
                assert want == exp, f"测试自身数据错误：{orig} 期望 {exp} 实算 {want}"
                if row["amount"] != want:         # **精确等于**，不是容差
                    wrong.append(f"{orig!r} → 实际 {row['amount']}，期望 {want}")
            assert not wrong, "以下金额未精确换算：\n" + "\n".join(wrong)
        finally:
            await Tortoise.close_connections()

    _run(inner())


def test_inexact_value_aborts_and_writes_nothing():
    """无法精确换算的值（12.345）必须中止迁移 —— 断言**三件事**，不是只有「报错了」。

    「迁移报错了」不等于「数据安全了」。必须证明：
    ① 抛异常 ② `orders_old` 仍在且行数不变（数据未丢）③ `orders` 表为空（一行未写）。
    """
    os.environ.setdefault("INITIAL_ADMIN_PASSWORD", "Spec005-Test-Pass-1")

    async def inner():
        from tortoise import Tortoise

        conn = await _db_with_seeds([(INEXACT, 0)])
        try:
            with pytest.raises(Exception) as exc:
                await conn.execute_script(await _load(MIG, "sp005_mig").upgrade(conn))
            # ① 中止原因必须是「不精确行置 NULL 违反约束」
            assert "NOT NULL" in str(exc.value) or "null" in str(exc.value).lower(), (
                f"中止原因应是不精确行置 NULL 违反 NOT NULL，实际：{exc.value!r}"
            )
            # ② ③ 数据安全：旧表数据完整、新表零行
            old_n, new_n = await _rowcount(conn)
            assert old_n == 1, f"orders_old 行数应保持 1，实际 {old_n}——数据丢了"
            assert new_n == 0, f"orders 应 0 行（语句原子回滚），实际 {new_n}——写入了残缺数据"
        finally:
            await Tortoise.close_connections()

    _run(inner())


def test_mixed_batch_with_one_inexact_row_aborts_whole_migration():
    """一条不精确 + 多条精确 ⇒ **整批中止**，精确行也不许写。

    验证的是语句级原子性：不能「能换的换了、不能换的跳过」——那正是静默改值的变体。
    """
    os.environ.setdefault("INITIAL_ADMIN_PASSWORD", "Spec005-Test-Pass-1")

    async def inner():
        from tortoise import Tortoise

        rows = [(12.34, 1234), (INEXACT, 0), (1.14, 114)]
        conn = await _db_with_seeds(rows)
        try:
            with pytest.raises(Exception):
                await conn.execute_script(await _load(MIG, "sp005_mig").upgrade(conn))
            old_n, new_n = await _rowcount(conn)
            assert old_n == 3, f"orders_old 应保留全部 3 行，实际 {old_n}"
            assert new_n == 0, f"orders 应 0 行，实际 {new_n}——精确行被单独写入了"
        finally:
            await Tortoise.close_connections()

    _run(inner())


def test_idempotent_on_already_converted_table():
    """库已是新形态（amount 为 INT、值已是分）时，必须等值搬运，不能再 ×100。

    SQLite 用 `typeof()` 判源表列类型（已实测可区分 real/integer）。
    **注意**：MySQL/PG 的等价判定是 `information_schema` 查 `orders_old`——
    那是方言专属 SQL，本地 SQLite 测不到，由 CI 的 `migrations-dialects` 覆盖。
    此处如实标注该局限，不冒充已覆盖。
    """
    os.environ.setdefault("INITIAL_ADMIN_PASSWORD", "Spec005-Test-Pass-1")

    async def inner():
        from tortoise import Tortoise

        await Tortoise.init(db_url="sqlite://:memory:", modules={"models": []})
        conn = Tortoise.get_connection("default")
        await conn.execute_script(await _load(BASELINE, "sp005_base").upgrade(conn))
        await conn.execute_script('DROP TABLE "orders";')
        await conn.execute_script(
            '''CREATE TABLE "orders" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "created_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    "deleted" INT NOT NULL  DEFAULT 0,
    "title" VARCHAR(128) NOT NULL,
    "amount" INT NOT NULL,
    "quantity" INT NOT NULL  DEFAULT 1,
    "status" VARCHAR(16) NOT NULL  DEFAULT 'pending',
    "customer_id" INT NOT NULL REFERENCES "customer" ("id") ON DELETE RESTRICT
);'''
        )
        await conn.execute_script(
            'INSERT OR IGNORE INTO "customer" ("id","name","email","status") '
            "VALUES (1,'c','c@c','active');"
        )
        await conn.execute_script(
            'INSERT INTO "orders" ("title","amount","quantity","status","customer_id") '
            "VALUES ('o1', 1000, 1, 'pending', 1), ('o2', 0, 1, 'pending', 1);"
        )
        try:
            await conn.execute_script(await _load(MIG, "sp005_mig").upgrade(conn))
            got = await conn.execute_query_dict(
                'SELECT "amount" FROM "orders" ORDER BY "id"'
            )
            assert [r["amount"] for r in got] == [1000, 0], (
                f"源表已是整数（1000 分 / 0 分）应等值搬运，实际 {[r['amount'] for r in got]}"
                "——若为 100000 说明守卫失效、又乘了一次 100"
            )
        finally:
            await Tortoise.close_connections()

    _run(inner())
