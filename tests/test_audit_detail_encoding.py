#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
审计 ``detail`` 的字段名编码（v0.4.3 / 缺陷池 BL-01）。

背景
====
``detail`` 里记录「这次改了哪些字段名」，格式是 ``id=42 fields=<字段名列表>``。
此前的实现用 ``",".join(fields)``，当字段名本身含逗号时无法无损还原：

```
fields = ["a,b", "c"]  →  "fields=a,b,c"  →  读回会以为是 3 个字段
```

规格层允许字段名包含逗号（``tools/specgen`` 的字段名校验只限制字符集与
保留字，未禁止逗号），所以这是真实的编码歧义。

修法：字段名列表用 JSON 数组编码（``json.dumps``），自定界、可无损往返。

本文件只测编码这一层（不启动服务、不碰数据库），
端到端行为由 ``tests/generated/test_gen_*.py`` 的审计用例覆盖。
"""

import json

import pytest

from app.services.audit import record_resource_event


class _FakeRequest:
    """``record_resource_event`` 只用到 headers 与 remote_addr。"""

    def __init__(self) -> None:
        self.headers = {"User-Agent": "detail-encoding-test/1.0"}
        self.remote_addr = "127.0.0.1"


def _parse_fields(detail: str):
    """从 detail 里取出字段名列表——**按 JSON 数组解析**，这正是被修的行为。"""
    marker = "fields="
    idx = detail.find(marker)
    assert idx >= 0, f"detail 里没有 {marker}：{detail!r}"
    return json.loads(detail[idx + len(marker):])


@pytest.mark.parametrize(
    "fields",
    [
        ["status"],
        ["status", "assignee_id"],
        # 关键用例：字段名本身含逗号。逗号拼接的实现会在这里塌陷。
        ["a,b", "c"],
        ["x,y,z"],
        ["含,中文,逗号", "normal"],
    ],
    ids=["single", "two", "comma-in-name", "all-comma", "cjk-with-comma"],
)
def test_detail_field_list_roundtrips_losslessly(fields):
    """任意字段名都能无损往返——这是逗号拼接做不到的。"""
    detail = _make_detail(fields)
    assert _parse_fields(detail) == fields, (
        f"字段名解码后与输入不一致：输入 {fields!r}，detail={detail!r}"
    )


def test_comma_joined_encoding_would_be_ambiguous():
    """
    正向对照：证明「逗号拼接」确实会歧义，所以本测试不是空转。

    直接构造两种不同的字段名列表，逗号拼接后得到同一个字符串——这就是被修的缺陷。
    """
    a = ["a,b", "c"]
    b = ["a", "b", "c"]
    assert ",".join(a) == ",".join(b) == "a,b,c", "前提校验：两种输入逗号拼接后相同"
    assert a != b, "前提校验：两种输入本身不同"

    # 而 JSON 编码能区分它们
    assert json.dumps(a) != json.dumps(b)


def test_detail_omits_fields_when_empty():
    """没有字段名时不应出现 ``fields=`` 段（删除动作就没有字段名）。"""
    detail = _make_detail([])
    assert "fields=" not in detail, f"空字段名不应输出 fields 段：{detail!r}"
    assert detail.startswith("id="), f"id 段必须保留：{detail!r}"


def _make_detail(fields) -> str:
    """
    直接调 ``record_resource_event`` 取它拼出的 detail。

    用 monkeypatch 把 ``OperationLog.create`` 换成捕获器，不落库——
    这样测的是真实实现路径，而不是复制一份拼接逻辑（后者会自己证明自己）。
    """
    from app.models import OperationLog

    captured = {}

    async def _capture(**kwargs):
        captured.update(kwargs)

    original = OperationLog.create
    OperationLog.create = staticmethod(_capture)
    try:
        import asyncio

        asyncio.run(
            record_resource_event(
                _FakeRequest(),
                resource="ticket",
                action="update",
                object_id=42,
                account=None,
                fields=fields or None,
            )
        )
    finally:
        OperationLog.create = original

    assert captured, "审计没有走到 OperationLog.create"
    return captured.get("detail") or ""
