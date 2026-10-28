#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
缓存清理的 ``type`` 参数与审计（EVT-20261028-041）。

问题
====
``DELETE /api/v1/cache`` 此前 ``type`` 默认 ``"all"`` —— **不带参数的 DELETE
直接清空整个缓存**，且**不写审计**。

三个分支里，``all`` 是唯一不可逆的，却是唯一有默认值的。

改动
====
1. ``type`` 改为必填：不传 / 传非法值 → 400 + ``VALIDATION_ERROR``
2. **三个分支都写**审计（含 ``except`` 失败路径），detail 记录删除范围
3. ``pattern`` 拒绝破坏审计结构的字符（空格 / \r \n \t / ``fields=`` / 空串）

本文件的三层目的
================
1. **默认值真的取消了** —— 不传 / 非法值都 400，不是「静默按 all 处理」
2. **只有 all 写审计** —— 这是**正向对照**：只测「all 写了」不够，
   还要证明「别的分支没写」，否则「每条都写」也能通过
3. **三个合法分支都还能正常清** —— 收紧入口不能把功能改坏
"""

import contextlib

import pytest

from app.cache import get_cache
from app.models import OperationLog


@contextlib.asynccontextmanager
async def _isolated_cache(*keys):
    """
    隔离缓存键空间：set 若干探针键，退出时**无论如何都恢复**。

    为什么用 ``try/finally``（复审 SF-3）：早先的测试在断言失败时不会执行
    清理代码，会留下 ``rbac09c-*`` 键 —— 后续若有测试用同名键或按 ``*``
    扫描，会看到脏数据。**清理不能依赖断言成功。**

    为什么全清用例也要用它：``type=all`` 会真的 ``cache.clear()``，
    ``type=route`` 会真的 ``clear_route_cache("*")``。虽然每个测试的 teardown
    都会清单例缓存（见 ``test_benign_patterns_are_not_rejected`` 的说明），
    但**那个结论依赖 teardown 一定跑到**。这里显式恢复，把依赖去掉。
    """
    cache = get_cache()
    before = {k: cache.get(k) for k in keys}
    try:
        for k in keys:
            cache.set(k, "v", timeout=300)
        yield cache
    finally:
        for k, prev in before.items():
            cache.delete(k)
            if prev is not None:
                cache.set(k, prev, timeout=300)


@contextlib.asynccontextmanager
async def _audit_scope():
    """
    审计行作用域：进入时清空、退出时**无论如何都清空**（复审 SF-3）。

    早先每个用例开头调 ``_clear_audit_rows()``、结尾再调一次 —— 断言失败时
    结尾那次不执行，DB 里残留的 cache 审计行会让**后续用例**的 ``count == 1``
    断言失败，产生与本次改动无关的红。**这是最难查的一类偶发失败：它只在
    特定执行顺序下出现。**
    """
    await OperationLog.filter(operation_type="cache").delete()
    try:
        yield
    finally:
        await OperationLog.filter(operation_type="cache").delete()


async def _audit_count() -> int:
    return await OperationLog.filter(operation_type="cache").count()


# ----------------------------------------------------------------------
# 1. type 必填
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "query,case",
    [
        ("", "完全不传 type"),
        ("?type=", "传了但为空"),
        ("?type=garbage", "传了非法值"),
        ("?type=ALL", "大小写不匹配（值是大小写敏感的）"),
        ("?type=allx", "近似但不等于 all"),
    ],
)
async def test_delete_without_valid_type_returns_400(client, auth_headers, query, case):
    """
    不传 ``type`` 或传非法值必须是 **400 + VALIDATION_ERROR**，不能静默按 all 处理。

    **为什么必须精确到 400**：这个测试的核心是「默认全清取消了」。如果断言写成
    ``>= 400``，一个 500（代码写崩了）也能通过 —— 那测的不是「入口被收紧」，
    是「服务出错了」。
    """
    cache = get_cache()
    cache.set("rbac09c-guard", "v", timeout=300)
    try:
        resp = await client.delete(f"/api/v1/cache{query}", headers=auth_headers)
        assert resp.status_code == 400, (
            f"{case} 应 400，实际 {resp.status_code}: {resp.text}"
        )
        body = resp.json()
        assert body.get("error") == "VALIDATION_ERROR", (
            f"{case} 的错误码应为 VALIDATION_ERROR，实际 {body.get('error')!r}"
        )
        # 关键：缓存没被清 —— 这才是「默认全清已取消」的实质证据
        assert cache.exists("rbac09c-guard"), (
            f"{case} 被拒绝后缓存不应被清空（这正是本项要防的误操作）"
        )
    finally:
        cache.delete("rbac09c-guard")


# ----------------------------------------------------------------------
# 2. 审计：三个分支都写 + except 失败路径也写
# ----------------------------------------------------------------------

async def test_type_all_writes_audit(client, auth_headers):
    """``type=all`` 必须写一条审计，且带操作者。"""
    async with _audit_scope():
        resp = await client.delete("/api/v1/cache?type=all", headers=auth_headers)
        assert resp.status_code == 200, resp.text

        # 断言必须在 scope 内 —— _audit_scope 退出时会清空审计行，
        # 写在 outside 会读到空列表（本测试第一版就是这样错的）。
        rows = await OperationLog.filter(operation_type="cache").all()
        assert len(rows) == 1, (
            f"type=all 应写 1 条审计，实际 {len(rows)} 条"
        )
        row = rows[0]
        assert row.operation == "delete", (
            f"operation 应为 delete，实际 {row.operation!r}"
        )
        assert (row.detail or "") == "id=all", (
            f"type=all 的 detail 应为 'id=all'，实际 {row.detail!r}"
        )
        assert row.account_id is not None, (
            "审计必须带操作者 account（谁清的空缓存是可追溯性的核心）"
        )


@pytest.mark.parametrize(
    "query,expected_id",
    [
        ("?type=route", "route:*"),
        ("?type=route&pattern=api:", "route:api:"),
        ("?type=pattern&pattern=rbac09c-*", "pattern:rbac09c-*"),
    ],
)
async def test_route_and_pattern_also_write_audit(
    client, auth_headers, query, expected_id
):
    """
    **三个分支都写审计** —— 这是 ``pattern=*`` 绕过点的修复。

    历史：最初只有 ``type=all`` 写审计，于是 ``?type=pattern&pattern=*``
    能达成与 ``type=all`` 完全相同的效果却不留任何记录 —— 一条**不留痕的全清路径**。

    修复方式不是「判断 pattern 是否等效全清再决定是否审计」（那个集合无法穷举：
    ``*`` / ``**`` / ``*?`` / ``[a-w]*`` …），而是「**凡删除必审计**」。

    审计内容按分支填，让 detail 能读出删除范围：
    ``id=route:<pattern>`` / ``id=pattern:<pattern>``。
    """
    async with _audit_scope():
        resp = await client.delete(f"/api/v1/cache{query}", headers=auth_headers)
        assert resp.status_code == 200, resp.text

        rows = await OperationLog.filter(operation_type="cache").all()
        assert len(rows) == 1, (
            f"{query} 应写 1 条审计（三个分支都写），实际 {len(rows)} 条"
        )
        assert (rows[0].detail or "") == f"id={expected_id}", (
            f"{query} 的 detail 应为 'id={expected_id}'，实际 {rows[0].detail!r}"
        )


async def test_pattern_star_cannot_bypass_audit(client, auth_headers):
    """
    **回归测试**：``?type=pattern&pattern=*`` 不能成为「不留痕的全清」。

    这条是本项最重要的回归 —— 它测的正是审核席指出的绕过点。
    ``pattern=*`` 与 ``type=all`` 效果相同（都清空全部键），
    修复后两者**都必须留审计**。
    """
    async with _isolated_cache("rbac09c-bypass-a", "rbac09c-bypass-b") as cache:
        async with _audit_scope():
            resp = await client.delete(
                "/api/v1/cache?type=pattern&pattern=*", headers=auth_headers
            )
            assert resp.status_code == 200, resp.text
            assert not cache.exists("rbac09c-bypass-a"), "pattern=* 确实删除了全部键"
            assert not cache.exists("rbac09c-bypass-b"), "pattern=* 确实删除了全部键"

            count = await _audit_count()
            assert count == 1, (
                f"pattern=* 等效全清，必须留审计；实际写了 {count} 条"
            )
            row = (await OperationLog.filter(operation_type="cache").all())[0]
            assert (row.detail or "") == "id=pattern:*", (
                f"detail 应记录删除范围 'id=pattern:*'，实际 {row.detail!r}"
            )


# ----------------------------------------------------------------------
# 2b. 审计注入防护：pattern 不能破坏 detail 结构
# ----------------------------------------------------------------------
#
# ``pattern`` 会被拼进 ``detail``（``id=pattern:<pattern>``），而 detail 是
# **空格分隔的 key=value 格式**，官方解析器（docs/audit-log-format.md）按
# ``detail[3:].split(" ", 1)[0]`` 取 id、按 ``detail.find("fields=")`` 取字段名。
#
# 两类字符能让操作者**伪造审计内容**：
#   1. 空格      → id 被截断
#   2. "fields=" → 解析器把 pattern 里的 ``fields=`` 当成真的字段段
#
# 第 2 条更隐蔽：id 段没被截断，整条记录看起来格式合法，但 fields 是伪造的。


@pytest.mark.parametrize(
    "pattern,case",
    [
        ("a b", "含空格 → id 会被截断"),
        ("fields=y", "含 fields= → 伪造 fields 段（无空格，id 不被截断，更隐蔽）"),
        ('x fields=["fake"]', "组合注入：空格 + JSON 数组形态的 fields"),
        ("myfields=z", "fields= 出现在中间"),
    ],
)
@pytest.mark.parametrize("type_value", ["pattern", "route"])
async def test_pattern_injection_is_rejected(
    client, auth_headers, pattern, case, type_value
):
    """
    ``pattern`` 含空格或 ``fields=`` 必须 400 —— 否则可以伪造审计记录。

    **两个分支都测**（``pattern`` 与 ``route``）：两条路径都把 pattern 拼进
    审计 detail，所以都受同一类注入影响。

    **为什么这些输入真的危险**（实测，不是推测）：
    ```
    pattern='a b'             → detail='id=pattern:a b'          → 解析 id='pattern:a'
    pattern='fields=y'        → detail='id=pattern:fields=y'     → 解析 fields=['y']
    pattern='x fields=["fake"]' → detail='id=pattern:x fields=["fake"]'
                                                              → 解析 fields=['fake']
    ```
    **最后一条尤其危险**：伪造的 ``fields=["fake"]`` 是 JSON 数组形态，
    正是 v0.4.2 起生成资源审计的格式，**看起来完全合法**。
    """
    cache = get_cache()
    cache.set("rbac09c-inj", "v", timeout=300)
    try:
        resp = await client.delete(
            "/api/v1/cache",
            params={"type": type_value, "pattern": pattern},
            headers=auth_headers,
        )
        assert resp.status_code == 400, (
            f"{type_value} 分支：{case}，应 400，实际 {resp.status_code}: {resp.text}"
        )
        assert resp.json().get("error") == "VALIDATION_ERROR", (
            f"错误码应为 VALIDATION_ERROR，实际 {resp.json().get('error')!r}"
        )
        assert cache.exists("rbac09c-inj"), (
            f"{case}：被拒绝后缓存不应被删（说明校验在删除之前生效）"
        )
    finally:
        cache.delete("rbac09c-inj")


@pytest.mark.parametrize(
    "pattern",
    [
        "user_rl:*",
        "login_rl_acct:123",
        "a:b",
        "a,b",
        "a=b",
        "a*b",
    ],
)
async def test_benign_patterns_are_not_rejected(client, auth_headers, pattern):
    """
    **反向对照**：合法 pattern 不能被误拒。

    这条和上面那条是一对 —— 只测「危险输入被拒」不够，还要证明
    「安全输入没被误伤」，否则「拒绝一切」也能通过。

    **不在列表里的输入及原因**：
    - ``a\\tb`` / ``a\\nb`` → 现在该拒（复审 SF-2：破坏下游按行收集的日志系统），
      见 ``test_control_chars_are_rejected``
    - ``""`` 空串 → 现在该 400，见 ``test_empty_pattern_behaviour``
    """
    resp = await client.delete(
        "/api/v1/cache",
        params={"type": "pattern", "pattern": pattern},
        headers=auth_headers,
    )
    assert resp.status_code == 200, (
        f"合法 pattern {pattern!r} 不应被拒，实际 {resp.status_code}: {resp.text}"
    )


# ----------------------------------------------------------------------
# 3. 三个合法分支仍然可用（收紧入口不能改坏功能）
# ----------------------------------------------------------------------

async def test_type_route_clears_route_cache(client, auth_headers):
    """``type=route`` 返回 200 并给出清理数量。"""
    resp = await client.delete("/api/v1/cache?type=route", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    assert "路由缓存键" in resp.json().get("message", ""), (
        f"message 应说明清理的是路由缓存，实际 {resp.text}"
    )


async def test_type_pattern_deletes_matching_keys(client, auth_headers):
    """``type=pattern`` 只删匹配的键，不碰其他键。"""
    cache = get_cache()
    cache.set("rbac09c-match-a", "v", timeout=300)
    cache.set("rbac09c-match-b", "v", timeout=300)
    cache.set("rbac09c-keep", "v", timeout=300)
    try:
        resp = await client.delete(
            "/api/v1/cache?type=pattern&pattern=rbac09c-match-*", headers=auth_headers
        )
        assert resp.status_code == 200, resp.text
        assert not cache.exists("rbac09c-match-a"), "匹配的键应被删除"
        assert not cache.exists("rbac09c-match-b"), "匹配的键应被删除"
        assert cache.exists("rbac09c-keep"), "不匹配的键不应被删除"
    finally:
        for k in ("rbac09c-match-a", "rbac09c-match-b", "rbac09c-keep"):
            cache.delete(k)


async def test_type_all_clears_everything(client, auth_headers):
    """
    ``type=all`` 清空所有键。

    **用 ``_isolated_cache`` 包裹**：本用例会真的 ``cache.clear()``，
    清掉全局单例缓存里的全部键。虽然每测试的 teardown 也会清，但显式恢复
    去掉了「teardown 必须跑到」这个隐式依赖（复审 SF-3）。
    """
    async with _isolated_cache("rbac09c-a", "rbac09c-b") as cache:
        async with _audit_scope():
            resp = await client.delete("/api/v1/cache?type=all", headers=auth_headers)
            assert resp.status_code == 200, resp.text
            assert not cache.exists("rbac09c-a"), "all 应清空所有键"
            assert not cache.exists("rbac09c-b"), "all 应清空所有键"


# ----------------------------------------------------------------------
# 4. 非 admin 对三个分支都 403（权限未因改动松动）
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "query",
    ["?type=route", "?type=pattern&pattern=*", "?type=all"],
)
async def test_non_admin_403_for_all_types(client, normal_auth_headers, query):
    """
    非 admin 对**每个** ``type`` 都 403，包括 ``all``。

    ``type`` 变成必填后，容易出的错是「新加的参数校验走在权限检查之前」——
    那样非 admin 会拿到 400（因参数不对）而不是 403（因权限不足），
    **把「没权限」伪装成「参数错误」**。这条钉住顺序：权限在前。
    """
    resp = await client.delete(f"/api/v1/cache{query}", headers=normal_auth_headers)
    assert resp.status_code == 403, (
        f"非 admin 带 {query} 应 403（权限检查先于参数校验），"
        f"实际 {resp.status_code}: {resp.text}"
    )


# ----------------------------------------------------------------------
# 5. except 路径也写审计（复审 SF-1）
# ----------------------------------------------------------------------

async def test_failed_cleanup_writes_failure_audit(
    client, auth_headers, monkeypatch
):
    """
    **失败路径也必须留审计** —— 这是「凡删除必审计」的最后一环。

    为什么必须有这条（复审 SF-1）：三个分支的成功路径都写了，但
    ``except Exception → _server_error`` 那条零记录。而删除可能
    **部分完成后**才抛错（例如 ``delete_many`` 删到一半缓存后端断了）——
    此时缓存已经变了，但没有记录。

    ``record_resource_event`` 的签名本身支持 ``status="failure"``，
    补这一条成本≈0，却封死了「删除已发生/部分发生却无痕」的口子。

    **怎么制造失败**：让 ``cache.delete_many`` 抛异常。
    """
    cache = get_cache()

    def _boom(*args, **kwargs):
        raise RuntimeError("模拟缓存后端故障")

    monkeypatch.setattr(cache, "delete_many", _boom)

    async with _audit_scope():
        resp = await client.delete(
            "/api/v1/cache?type=pattern&pattern=rbac09c-x", headers=auth_headers
        )
        assert resp.status_code == 500, (
            f"缓存后端抛错应 500，实际 {resp.status_code}: {resp.text}"
        )

        rows = await OperationLog.filter(operation_type="cache").all()
        assert len(rows) == 1, (
            f"失败路径应写 1 条审计，实际 {len(rows)} 条"
        )
        row = rows[0]
        assert row.status == "failure", (
            f"失败审计的 status 应为 'failure'（让消费方区分「删了」与「试了但失败」），"
            f"实际 {row.status!r}"
        )
        assert row.operation == "delete"
        assert (row.detail or "") == "id=pattern:rbac09c-x", (
            f"失败审计也应记录删除范围，实际 {row.detail!r}"
        )
        assert row.account_id is not None


# ----------------------------------------------------------------------
# 6. 「空 pattern」的真实形态（复审 SF-5 / AC-GLM N-3，前提需修正）
# ----------------------------------------------------------------------

async def test_empty_query_value_falls_back_to_default(client, auth_headers):
    """
    ``?pattern=``（空值）**不会**产生空串 —— Sanic 把空值 query 当不存在，
    于是 ``request.args.get("pattern", "*")`` 返回默认 ``"*"``。

    **这是对复审 SF-5「空 pattern → 400」的前提修正**：那条要求基于
    「空串 pattern 无意义」，但实测 **空串根本到不了业务层** ——
    Sanic 的 query 解析用 ``keep_blank_values=False``（urllib 默认），
    ``?pattern=`` 与不传 pattern 完全等价。

    所以「空 pattern」不是需要拒绝的输入，**它根本不存在**。
    业务层的 ``if not pattern`` 是防御性死代码，保留无害（若将来换 WSGI
    或改解析配置，它能兜住），但不该被当成「已修复的缺陷」写进 PR。

    **真正需要测的是「不影响行为」**：``?pattern=`` 与不传应表现一致（都 200）。
    """
    cache = get_cache()
    cache.set("rbac09c-empty-probe", "v", timeout=300)
    try:
        r_empty = await client.delete(
            "/api/v1/cache", params={"type": "pattern", "pattern": ""},
            headers=auth_headers,
        )
        r_absent = await client.delete(
            "/api/v1/cache", params={"type": "pattern"}, headers=auth_headers,
        )
        assert r_empty.status_code == r_absent.status_code == 200, (
            f"?pattern= 与不传应行为一致（都回落到默认 '*'），"
            f"实际 {r_empty.status_code} vs {r_absent.status_code}"
        )
    finally:
        cache.delete("rbac09c-empty-probe")


async def test_nul_pattern_matches_nothing(client, auth_headers):
    """
    ``?pattern=%00`` 到达业务层是 ``"\\x00"``（非空串），匹配不到任何键。

    这条钉住「转义后的空值」实际行为：它不是空 pattern，而是一个
    匹配不到任何键的单字符模式 —— 删 0 个键，写一条 ``id=pattern:\\x00`` 审计。

    **为什么测它**：它是「空 pattern」唯一能真正到达业务层的形态
    （``%20`` 会变成空格被拒，``%00`` 变成 NUL 不在拒绝列表）。
    """
    cache = get_cache()
    cache.set("rbac09c-nul-probe", "v", timeout=300)
    try:
        async with _audit_scope():
            resp = await client.delete(
                "/api/v1/cache", params={"type": "pattern", "pattern": "\x00"},
                headers=auth_headers,
            )
            assert resp.status_code == 200, resp.text
            assert cache.exists("rbac09c-nul-probe"), (
                "NUL pattern 匹配不到任何键，不应删掉探针键"
            )
            rows = await OperationLog.filter(operation_type="cache").all()
            assert len(rows) == 1, "仍应写一条审计（凡删除必审计）"
            assert rows[0].detail == "id=pattern:\x00", (
                f"detail 应含原始 NUL 字符，实际 {rows[0].detail!r}"
            )
    finally:
        cache.delete("rbac09c-nul-probe")


# ----------------------------------------------------------------------
# 7. 制表符/换行/回车也拒绝（复审 SF-2，CPL 裁定）
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "char,name",
    [("\r", "回车"), ("\n", "换行"), ("\t", "制表符")],
)
@pytest.mark.parametrize("type_value", ["pattern", "route"])
async def test_control_chars_are_rejected(
    client, auth_headers, char, name, type_value
):
    """
    ``\\r`` / ``\\n`` / ``\\t`` 也要拒绝（复审 SF-2）。

    **它们不破坏 detail 解析**（``split(" ", 1)`` 只认 ASCII 空格），
    **但破坏下游日志系统**：
    - Syslog / Loki / ELK 按行收集 → ``\\n`` 把一条审计拆成两行（**日志伪造**）
    - 消费方若用无参 ``detail.split()``（按任意空白切）→ ``\\t`` 同样截断

    **误拒面≈0**：现实缓存键不含这些字符。

    **两席在此有张力**：AC-GLM 认为「不拒绝也算忠实映射解析器缺陷」，
    CPL 裁定拒绝（现实风险优先）。这条测试钉住该裁定。
    """
    cache = get_cache()
    cache.set("rbac09c-ctrl", "v", timeout=300)
    try:
        resp = await client.delete(
            "/api/v1/cache",
            params={"type": type_value, "pattern": f"a{char}b"},
            headers=auth_headers,
        )
        assert resp.status_code == 400, (
            f"{type_value} 分支：pattern 含{name}应 400，"
            f"实际 {resp.status_code}: {resp.text}"
        )
        assert cache.exists("rbac09c-ctrl"), "被拒绝后缓存不应被删"
    finally:
        cache.delete("rbac09c-ctrl")
