#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
时区契约测试（v0.4.1）。

契约（见 docs/ 里的说明与 v0.4.1 发布说明）：

1. 所有时间字段**以 UTC aware 存储**；
2. API 输出带偏移的 ISO 8601（例如 ``2026-12-01T10:00:00+00:00``）；
3. API 输入只接受带偏移或 naive 的值——**naive 一律按 UTC 解释**；
4. 进程 ``TZ`` 环境变量如何设置，都不影响存储与输出的绝对时刻。

"今天"为什么要专门测这个：模型层的 ``.json`` 属性此前用 ``str(datetime)``，
输出是 ``2026-10-24 12:55:31+00:00``——**空格分隔，不是合法 ISO 8601**，
``datetime.fromisoformat`` 在旧版 Python 上会拒绝。改为 ``.isoformat()`` 后
才是标准形式。这条契约靠 ``test_all_api_datetime_fields_are_iso8601`` 守。
"""
from __future__ import annotations

import datetime
import os
import time

import pytest

ISO_T_SEPARATOR = "T"


def _reparse(value):
    """把任意时间字符串解析成 aware datetime（naive 视为 UTC）。"""
    dt = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# 一、不同进程 TZ 下的往返一致
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("process_tz", ["UTC", "Asia/Shanghai", "America/New_York"])
async def test_roundtrip_stable_across_process_tz(
    client, auth_headers, process_tz, monkeypatch,
):
    """
    改变进程 TZ 后，同一绝对时刻写入再读出必须等价。

    `time.tzset()` 让 ``TZ`` 立即生效（仅 POSIX）。这是唯一能真正模拟
    「另一台机器/另一个部署环境」的办法——只 monkeypatch 环境变量而不调
    tzset，Python 缓存的本地时区不会变，测试就是空转。
    """
    sent = "2026-12-01T10:00:00+08:00"
    expected = datetime.datetime(
        2026, 12, 1, 2, 0, tzinfo=datetime.timezone.utc
    )

    old_tz = os.environ.get("TZ")
    monkeypatch.setenv("TZ", process_tz)
    try:
        time.tzset()
    except AttributeError:  # Windows 没有 tzset
        pytest.skip("平台不支持 time.tzset，无法模拟不同进程 TZ")

    try:
        payload = {
            "name": f"tz-{process_tz.replace('/', '-')}",
            "email": f"tz-{abs(hash(process_tz))}@example.com",
            "onboarded_at": sent,
        }
        resp = await client.post("/api/v1/customers", headers=auth_headers, json=payload)
        assert resp.status_code == 201, resp.text[:300]
        data = resp.json()["data"]

        got = _reparse(data["onboarded_at"])
        # 关键断言：绝对时刻相同，与进程 TZ 无关
        assert got == expected, (
            f"TZ={process_tz} 下写入 {sent} 应等价于 {expected.isoformat()}，"
            f"实际 {data['onboarded_at']}"
        )
    finally:
        if old_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old_tz
        try:
            time.tzset()
        except AttributeError:
            pass


async def test_naive_input_is_interpreted_as_utc(client, auth_headers):
    """不带偏移的输入按 UTC 解释——这是契约里最容易搞错的一条。"""
    naive = "2026-12-01T10:00:00"
    payload = {
        "name": "tz-naive-check",
        "email": "tz-naive@example.com",
        "onboarded_at": naive,
    }
    resp = await client.post("/api/v1/customers", headers=auth_headers, json=payload)
    assert resp.status_code == 201, resp.text[:300]
    got = _reparse(resp.json()["data"]["onboarded_at"])
    expected = datetime.datetime(2026, 12, 1, 10, 0, tzinfo=datetime.timezone.utc)
    assert got == expected, f"naive 输入应视为 UTC，实际 {resp.json()['data']['onboarded_at']}"


async def test_offset_input_converts_correctly(client, auth_headers):
    """+08:00 的输入必须换算成 UTC 存储，输出仍表示同一绝对时刻。"""
    payload = {
        "name": "tz-offset-check",
        "email": "tz-offset@example.com",
        "onboarded_at": "2026-12-01T10:00:00+08:00",
    }
    resp = await client.post("/api/v1/customers", headers=auth_headers, json=payload)
    assert resp.status_code == 201, resp.text[:300]
    raw = resp.json()["data"]["onboarded_at"]
    got = _reparse(raw)
    assert got.utcoffset() == datetime.timedelta(0), f"输出应带 UTC 偏移，实际 {raw}"
    assert got == datetime.datetime(2026, 12, 1, 2, 0, tzinfo=datetime.timezone.utc)


async def test_z_suffix_input_accepted(client, auth_headers):
    """
    `Z` 后缀的输入必须被接受，且等价于 `+00:00`。

    Python 3.10 及更早的 `datetime.fromisoformat` **不接受** `Z`，
    所以应用里凡是解析时间的路径都做了 `.replace("Z", "+00:00")` 处理
    （`app/api/validators.py:269`、`app/api/resources/log.py:50`）。
    这条用例保证该处理在真实请求里生效——CI 的 3.10 上必须通过。
    """
    payload = {
        "name": "tz-z-suffix",
        "email": "tz-z@example.com",
        "onboarded_at": "2026-12-01T10:00:00Z",
    }
    resp = await client.post("/api/v1/customers", headers=auth_headers, json=payload)
    assert resp.status_code == 201, (
        f"Z 后缀输入被拒绝（HTTP {resp.status_code}）：{resp.text[:300]}"
    )
    got = _reparse(resp.json()["data"]["onboarded_at"])
    assert got == datetime.datetime(2026, 12, 1, 10, 0, tzinfo=datetime.timezone.utc)


# ---------------------------------------------------------------------------
# 二、全仓守卫：所有 API 响应里的时间字段必须是 ISO 8601
# ---------------------------------------------------------------------------

#: 各资源列表端点 -> 需要检查的时间字段名
_DATETIME_FIELDS = ("created_at", "updated_at", "onboarded_at", "expires")

_ENDPOINTS = [
    "/api/v1/customers",
    "/api/v1/orders",
    "/api/v1/tickets",
    "/api/v1/accounts",
    "/api/v1/roles",
    "/api/v1/settings",
    "/api/v1/logs",
]


async def _seed_all(client, auth_headers) -> None:
    """为每个被扫描的资源建一条最小记录，确保列表非空。"""
    import uuid

    tag = uuid.uuid4().hex[:8]
    seeds = [
        ("/api/v1/customers", {"name": f"seed-{tag}", "email": f"seed-{tag}@example.com"}),
        ("/api/v1/orders", None),   # 下面单独处理（需要 customer）
        ("/api/v1/tickets", None),
        # settings 有键白名单（ALLOWED_SETTING_KEYS），只能用已注册的键
        ("/api/v1/settings", {"key": "site_name", "value": "seed", "value_type": "string"}),
    ]
    customer_id = None
    for url, payload in seeds:
        if payload is None:
            continue
        resp = await client.post(url, headers=auth_headers, json=payload)
        # seed 失败必须报出来：否则后续「端点为空」的断言会写成误导性的原因
        assert resp.status_code in (200, 201), (
            f"造数据失败 {url}：HTTP {resp.status_code} {resp.text[:200]}"
        )
        if url == "/api/v1/customers":
            customer_id = (resp.json().get("data") or {}).get("id")
    if customer_id:
        await client.post("/api/v1/orders", headers=auth_headers, json={
            "customer_id": customer_id, "title": f"seed-order-{tag}",
            "amount": 10.0, "status": "pending",
        })
        await client.post("/api/v1/tickets", headers=auth_headers, json={
            "title": f"seed-{tag}", "status": "open", "priority": "normal",
            "customer_id": customer_id,
        })


async def test_all_api_datetime_fields_are_iso8601(client, auth_headers):
    """
    全仓守卫：扫描所有列表端点返回的时间字段，必须
    ①包含 ``T`` 分隔符 ②能被 ``datetime.fromisoformat`` 解析。

    这条是**回归守卫**：只要有人再写回 ``str(dt)``，输出就会变回空格分隔，
    测试立刻红。它不针对某个具体端点，而是对新旧所有资源都生效。
    """
    # 先造数据：空端点等于没覆盖。逐个资源建一条最小记录，
    # 否则某个端点为 [] 时，它对应模型的 .json 根本不会被走到。
    await _seed_all(client, auth_headers)

    checked = 0
    problems = []
    empty = []
    for url in _ENDPOINTS:
        resp = await client.get(url, headers=auth_headers)
        if resp.status_code != 200:
            empty.append(f"{url}(HTTP {resp.status_code})")
            continue
        body = resp.json()
        items = (body.get("data") or {}).get("items") or []
        if not items:
            empty.append(url)
            continue
        for item in items:
            for field in _DATETIME_FIELDS:
                value = item.get(field)
                if not value or not isinstance(value, str):
                    continue
                checked += 1
                if ISO_T_SEPARATOR not in value:
                    problems.append(f"{url} 的 {field}={value!r} 缺少 T 分隔符")
                    continue
                try:
                    datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError as exc:
                    problems.append(f"{url} 的 {field}={value!r} 无法解析: {exc}")

    assert not problems, "时间字段不是合法 ISO 8601：\n" + "\n".join(problems)

    # **另一条路径必须单独覆盖**：模型的 `.json` 属性（Account.json 等）走的是
    # 自己拼字典的路径，不经过 APIResponse.serialize。上面扫的列表端点用的是
    # 序列化器（传 datetime 对象），**根本走不到 .json**——实测：把
    # Account.json 改回 str(datetime)，上面的扫描照样绿。
    # 认证响应里带 session.bearer.json，正好覆盖这条路径。
    # 口令从 conftest 设置的环境变量取真实值（conftest.py:82 写入）。
    login_ok = await client.post("/auth/login", json={
        "email": os.environ.get("INITIAL_ADMIN_EMAIL", "SAdmin@Sanic.com"),
        "password": os.environ["INITIAL_ADMIN_PASSWORD"],
    })
    # **不能写 `if status in (200, 403)`**：401 时会静默跳过，而这条断言是
    # `.json` 路径唯一的覆盖——跳过就等于没测。复核指出过这一点。
    assert login_ok.status_code == 200, (
        f"登录失败（HTTP {login_ok.status_code}），无法验证 .json 路径："
        f"{login_ok.text[:200]}"
    )
    body = login_ok.json()
    payload = body.get("data") or {}
    checked_json_path = 0
    for field in ("created_at", "updated_at"):
        value = payload.get(field)
        assert isinstance(value, str) and value, (
            f"认证响应的 {field} 缺失或不是字符串：{value!r}"
        )
        checked_json_path += 1
        assert ISO_T_SEPARATOR in value, (
            f"认证响应 .json 路径的 {field}={value!r} 缺少 T 分隔符"
            "（模型 .json 属性可能又用回了 str()）"
        )
    assert checked_json_path == 2, f"只检查了 {checked_json_path} 个字段"
    # 正向对照：这条测试必须真的检查到东西，否则「0 个问题」毫无意义
    assert checked > 0, (
        f"没有检查到任何时间字段（端点 {_ENDPOINTS} 都为空或字段名不匹配）——"
        "这条守卫形同虚设"
    )
    # **逐端点覆盖断言**：只要求「总数 > 0」不够——某个端点返回空列表时，
    # 它对应模型的 `.json` 序列化根本没被走到，破坏那个模型这条测试也不会红。
    # （实测踩到：把 Account.json 改回 str() 后本条仍然通过，因为 accounts
    #   端点在那个 fixture 下是空的。）
    assert not empty, (
        "以下端点没有返回任何数据行，对应的时间字段未被覆盖：" + ", ".join(empty)
    )


def test_all_api_datetime_fields_are_iso8601_source_guard():
    """
    源码守卫：模型层的 ``.json`` 属性不得再用 ``str(<时间字段>)``。

    上面的行为测试依赖「数据库里至少有一条记录」；这条静态检查不依赖数据，
    只要有人把某个模型改回 ``str(self.created_at)`` 就会红。
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parent.parent
    bad: list[str] = []

    # 模式 1：`str(<任意表达式>.<时间字段>)` —— 从 `str(self.x)` 放宽到接收者任意，
    # 因为实测漏掉的几处接收者不是 self/setting/item/obj 这几个固定名。
    # 时间字段名清单（用于字符串匹配）
    _DT_FIELDS = (
        "created_at", "updated_at", "date_created", "date_updated",
        "expires", "onboarded_at", "birthday",
    )
    # 匹配 `str(<接收者>.<时间字段>)`。接收者不限定为 self/setting/obj——
    # 实测漏掉的那几处接收者各不相同。
    p_str_dt = re.compile(
        r"\bstr\(\s*[\w\.\[\]'\"]+\.(" + "|".join(_DT_FIELDS) + r")\s*\)"
    )
    # 匹配不带时区参数的 datetime.now()
    p_naive_now = re.compile(r"datetime\.now\(\)")

    #: 例外：`datetime.now()` 在这里的用途是拼**迁移文件名**（版本号形如
    #: `20261024184457`），不是放进 API 响应。时区契约只管响应里的时间字段。
    _NAIVE_NOW_ALLOWLIST = {
        "tools/specgen/migrations.py",
    }

    for sub in ("app", "tools"):
        for path in (root / sub).rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            rel = path.relative_to(root)
            for m in p_str_dt.finditer(text):
                bad.append(f"{rel}: {m.group(0)}")
            if str(rel) in _NAIVE_NOW_ALLOWLIST:
                continue
            # datetime.now() 只在不带 timezone 参数时才违反契约
            for m in p_naive_now.finditer(text):
                bad.append(f"{rel}: {m.group(0)} —— 应为 datetime.now(datetime.timezone.utc)")

    assert not bad, (
        "以下位置的时间处理违反契约（str() 序列化 datetime，或无时区的 now()）：\n"
        + "\n".join(bad)
    )
