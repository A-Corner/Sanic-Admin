#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
``use_tz`` 的可观测性测试（v0.4.2）。

## 为什么需要这个文件

v0.4.1 的负向验证（把 ``use_tz`` 改成 ``False``）在真实 MySQL 8 / PostgreSQL 16
上**没有变红**，当时的结论是「验证路径不覆盖 ``use_tz``」。本文件补上能真正观测
到它的断言，并把「为什么原路径测不到」固化成测试。

## 测不到的两个原因（缺一不可）

1. **写入路径**：``check_timezone_dialects.py`` 走 ``Model.create()`` →
   ``to_python_value()``，那里**无条件** ``make_aware(value, get_timezone())``
   （``tortoise/fields/data.py:363-365``），根本不读 ``get_use_tz()``。
   真正读它的是后端 executor 的 ``auto_now`` / ``auto_now_add`` 分支
   （SQLite：``tortoise/backends/sqlite/executor.py:44-52``）。
2. **时区配置**：``use_tz`` 的差异**只在 ``timezone`` 非 UTC 时出现**。本项目
   配置是 ``use_tz=True, timezone="UTC"``——若沿用该 timezone 做对照，
   ``True`` 与 ``False`` 行为完全相同，测一万次也是绿的。

## 因此断言必须

- 用 ``auto_now_add``（走 executor 分支，不经过 ``to_python_value``）；
- 对照时把 ``timezone`` 设为 ``Asia/Shanghai``；
- **直读 DB 原始字符串**，不走 ORM 读回（读回会被 ``to_python_value`` 归一化，
  差异被抹平）。

第 3 点最容易写错：本文件的 ``_raw_created_values`` 用 sqlite3 直连，绕过 Tortoise。

## 模型必须在模块级

Tortoise 的 ``apps[...]["models"]`` 按模块名导入后再扫描该模块的 ``Model`` 子类，
**函数内定义的模型识别不到**（实测报 ``Module ... has no models``）。
"""
from __future__ import annotations

import asyncio
import os
import sqlite3
import tempfile

import pytest
from tortoise import Tortoise, fields, models

_APP = "use_tz_probe_app"
_TZ_TABLE = "use_tz_probe"


class Probe(models.Model):
    """探针模型：只有一个 ``auto_now_add`` 字段。"""

    id = fields.IntField(pk=True)
    created = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = _TZ_TABLE
        app = _APP


def _raw_created_values(db_path: str) -> list:
    """直读 SQLite 原始字符串，绕过 ORM（关键：不能走 to_python_value）。"""
    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(f"SELECT created FROM {_TZ_TABLE} ORDER BY id").fetchall()
    finally:
        con.close()
    return [r[0] for r in rows]


async def _probe(use_tz: bool, timezone: str):
    """建一行，分别返回「原始值」与「ORM 读回的 utcoffset」。"""
    db_dir = tempfile.mkdtemp(prefix="sa-use-tz-")
    db_path = os.path.join(db_dir, "probe.sqlite3")

    await Tortoise.init(
        config={
            "connections": {"default": f"sqlite://{db_path}"},
            "apps": {_APP: {"models": [__name__], "default_connection": "default"}},
        },
        use_tz=use_tz,
        timezone=timezone,
    )
    try:
        await Tortoise.generate_schemas()
        obj = await Probe.create()
        readback = await Probe.get(id=obj.id)
        offset = readback.created.utcoffset()
    finally:
        await Tortoise.close_connections()

    raw = _raw_created_values(db_path)
    return raw, offset


def _run(use_tz: bool, timezone: str):
    """同步包装：Tortoise 的 use_tz/timezone 落在进程环境变量上，必须串行。"""
    return asyncio.run(_probe(use_tz, timezone))


# ---------------------------------------------------------------------------
# A1 + A2：auto_now_add 在 use_tz=False + 非 UTC 时区下写本地偏移
# ---------------------------------------------------------------------------


def test_auto_now_add_writes_local_offset_when_use_tz_off():
    """A1：``use_tz=False`` + ``timezone=Asia/Shanghai`` → 原始值含 ``+08:00``。

    这是唯一能区分 ``use_tz`` 两值的组合。用 UTC 做对照永远绿（见第 3 个用例）。
    """
    raw, _ = _run(use_tz=False, timezone="Asia/Shanghai")
    assert len(raw) == 1, raw
    assert "+08:00" in raw[0], f"use_tz=False 应写本地偏移，实际 {raw[0]!r}"


def test_auto_now_add_normalizes_to_utc_when_use_tz_on():
    """A2：同一配置下 ``use_tz=True`` → 原始值含 ``+00:00``。

    与 A1 构成双向对照：证明不是「两种配置都写 +08:00」这种假差异。
    """
    raw, _ = _run(use_tz=True, timezone="Asia/Shanghai")
    assert len(raw) == 1, raw
    assert "+00:00" in raw[0], f"use_tz=True 应归一为 UTC，实际 {raw[0]!r}"


def test_use_tz_pair_differs_only_when_timezone_is_not_utc():
    """A1/A2 的合并陈述：差异只在 timezone 非 UTC 时出现。

    这条同时解释了 v0.4.1 负向验证为什么没变红——它用的是 ``timezone="UTC"``。
    """
    utc_off = _run(use_tz=False, timezone="UTC")[0][0]
    utc_on = _run(use_tz=True, timezone="UTC")[0][0]
    assert ("+08:00" in utc_off) == ("+08:00" in utc_on) is False, (
        f"timezone=UTC 时两者都应是 +00:00，实际 off={utc_off!r} on={utc_on!r}"
    )

    sh_off = _run(use_tz=False, timezone="Asia/Shanghai")[0][0]
    sh_on = _run(use_tz=True, timezone="Asia/Shanghai")[0][0]
    assert ("+08:00" in sh_off) != ("+08:00" in sh_on), (
        f"timezone=Asia/Shanghai 时两者必须不同，实际 off={sh_off!r} on={sh_on!r}"
    )


# ---------------------------------------------------------------------------
# A3：ORM 读回会把差异归一化——这正是原脚本测不到的原因
# ---------------------------------------------------------------------------


def test_orm_readback_normalizes_and_hides_the_difference():
    """A3：同样的写入，**ORM 读回**在两个 ``use_tz`` 值下偏移一致。

    这条不是测 ``use_tz``，而是把「为什么必须直读原始值」钉住：
    若将来有人把本文件的断言改成 ORM 读回比较，这条会说明那样做无效。
    """
    _, off_offset = _run(use_tz=False, timezone="Asia/Shanghai")
    _, on_offset = _run(use_tz=True, timezone="Asia/Shanghai")

    assert off_offset == on_offset, (
        "ORM 读回经 to_python_value 的 localtime() 归一，两个 use_tz 值应得到相同偏移；"
        f"实际 off={off_offset} on={on_offset}"
    )
