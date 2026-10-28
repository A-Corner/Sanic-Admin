#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
审计 ``object_id`` 的格式约束（EVT-20261028-043）。

问题
====
``record_resource_event`` 把 ``object_id`` 裸拼进 detail：

```python
parts = [f"id={object_id}"]
detail = " ".join(parts)
```

而 detail 是**空格分隔的 key=value 格式**，官方解析器
（``docs/audit-log-format.md``）按两处取内容：

```python
object_id = detail[3:].split(" ", 1)[0]      # 按空格截断
idx = detail.find("fields=")                 # 按子串定位
```

**所以 object_id 含空格会截断 id 段，含 ``fields=`` 会伪造 fields 段。**
后者更隐蔽 —— id 段看起来正常，整条记录格式合法。

为什么约束放在调用方，不放在审计函数
====================================
``record_resource_event`` 的契约是「**永不抛出**」（审计是旁路，不能影响
主请求）。在它内部校验会破坏这个契约；而「环境分叉」（只在非生产校验）
同样不可靠 —— 见 ``test_validate_object_id_*`` 的说明。

**所以 ``validate_audit_object_id`` 是给调用方主动调用的**，
调用方把它转成 400（客户端传了非法参数），而不是让它冒成 500。

本文件测三层
============
1. ``validate_audit_object_id`` 本身的判定（含正向对照）
2. ``cache.py`` 的调用方已正确接入（非法 pattern 仍被 400 拦住）
3. **生产环境不炸** —— ``record_resource_event`` 对非法 object_id 不抛异常
"""

import pytest

from app.services.audit import validate_audit_object_id


# ----------------------------------------------------------------------
# 1. 校验函数的判定
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "value,reason",
    [
        ("a b", "含空格 → split(' ', 1)[0] 截断 id"),
        (" x", "前导空格"),
        ("x ", "尾随空格"),
        ("a  b", "连续空格"),
        ("fields=y", "含 fields= → find() 命中伪造段"),
        ("myfields=z", "fields= 出现在中间"),
        ('x fields=["fake"]', "组合注入"),
    ],
)
def test_validate_object_id_rejects_unsafe(value, reason):
    """含空格或 ``fields=`` 的值必须抛 ``ValueError``。"""
    with pytest.raises(ValueError) as exc_info:
        validate_audit_object_id(value)
    message = str(exc_info.value)
    # 错误信息要能定位到问题所在，否则调用方拿到 500 也不知道改哪儿
    assert ("空格" in message) or ("fields=" in message), (
        f"错误信息应指明是哪类问题，实际 {message!r}"
    )


@pytest.mark.parametrize(
    "value",
    [
        "user_rl:*",
        "login_rl_acct:123",
        "a:b",
        "a,b",
        "a=b",
        "a*b",
        "all",
        "route:*",
        "pattern:user:1",
        # 制表符/换行**不破坏 detail 解析**（split(" ", 1) 只认 ASCII 空格），
        # 所以这个通用校验不该拒绝它们。拒绝是调用方各自的额外要求
        # （如 cache.py 因下游日志系统而拒绝）。
        "a\tb",
        "a\nb",
        "a\rb",
    ],
)
def test_validate_object_id_accepts_safe(value):
    """
    **正向对照**：安全的值不能误拒。

    这条和上面那条是一对 —— 只测「危险值被拒」不够，还要证明
    「安全值没被误伤」，否则「全部拒绝」也能通过上面那组测试。

    **特别注意 ``a\\tb`` / ``a\\nb`` / ``a\\rb``**：它们是「形态最接近
    空格、但实际安全」的难例 —— 如果只放 ``user_rl:*`` 这种明显安全的值，
    测不出校验是否过严。
    """
    validate_audit_object_id(value)  # 不抛即通过


def test_validate_object_id_accepts_non_string():
    """整数等非字符串值应被接受（``obj.id`` 是最常见的用法）。"""
    for value in (1, 0, 999999, None):
        validate_audit_object_id(value)  # 不抛即通过


def test_validate_object_id_field_name_in_message():
    """``field_name`` 参数要出现在错误信息里，便于调用方定位。"""
    with pytest.raises(ValueError) as exc_info:
        validate_audit_object_id("a b", field_name="cache.pattern")
    assert "cache.pattern" in str(exc_info.value), (
        f"错误信息应含 field_name，实际 {exc_info.value}"
    )


# ----------------------------------------------------------------------
# 2. 调用方已接入
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "pattern",
    [
        "a b",
        "fields=y",
        'x fields=["fake"]',
    ],
)
async def test_cache_rejects_invalid_pattern(client, auth_headers, pattern):
    """
    ``cache.py`` 的入口仍挡住非法 pattern —— 它现在通过共享校验实现。

    这条是**接入验证**：改成本 PR 的写法后，原有防护不能丢。
    如果 ``validate_audit_object_id`` 的调用写错了位置（比如放在 ``try`` 之后、
    或在删除之后），这里会红。
    """
    from app.cache import get_cache

    cache = get_cache()
    cache.set("w043-guard", "v", timeout=300)
    try:
        resp = await client.delete(
            "/api/v1/cache",
            params={"type": "pattern", "pattern": pattern},
            headers=auth_headers,
        )
        assert resp.status_code == 400, (
            f"非法 pattern {pattern!r} 应 400，实际 {resp.status_code}: {resp.text}"
        )
        assert resp.json().get("error") == "VALIDATION_ERROR"
        assert cache.exists("w043-guard"), "被拒绝后缓存不应被删"
    finally:
        cache.delete("w043-guard")


@pytest.mark.parametrize("char,name", [("\r", "回车"), ("\n", "换行"), ("\t", "制表符")])
async def test_cache_still_rejects_control_chars(client, auth_headers, char, name):
    """
    ``cache.py`` 仍拒绝控制字符 —— 这是**调用方的额外约束**，不属于共享校验。

    **这条测的是分层是否清晰**：如果将来有人「简化」掉了 cache.py 里的
    控制字符循环（以为 `validate_audit_object_id` 已经管了），这条会红。
    """
    resp = await client.delete(
        "/api/v1/cache",
        params={"type": "pattern", "pattern": f"a{char}b"},
        headers=auth_headers,
    )
    assert resp.status_code == 400, (
        f"pattern 含{name}应 400（下游日志保护），实际 {resp.status_code}"
    )


# ----------------------------------------------------------------------
# 3. 生产环境不炸（契约钉住）
# ----------------------------------------------------------------------

async def test_record_resource_event_never_raises_on_bad_object_id(app):
    """
    **``record_resource_event`` 对非法 object_id 不抛异常** —— 钉住「永不抛出」契约。

    为什么这条重要：本 PR 的诱因之一就是「给它加断言」这个想法。
    而断言在哪个环境下生效都不对：
    - 生产生效 → 违反永不抛出，非法 object_id 会让主请求 500
    - 非生产生效 → 依赖「环境判断正确」，而 ``__debug__``（取决于 ``-O``）
      和模块级 ``config``（与应用实例可能不一致）都不可靠

    **所以设计上选择「不加断言，靠调用方校验」**。这条测试防止将来有人
    「顺手把断言加回来」。
    """
    from app.services.audit import record_resource_event

    class _FakeRequest:
        headers = {}
        client_ip = "127.0.0.1"
        remote_addr = "127.0.0.1"

        class ctx:
            authentication_session = None

    class _FakeAccount:
        username = "tester"

    # 含空格与 fields= 的 object_id —— 明知非法，但函数必须不抛
    for bad in ("a b", "fields=y", "x fields=[1]"):
        await record_resource_event(
            _FakeRequest(),
            resource="probe",
            action="delete",
            object_id=bad,
            account=_FakeAccount(),
        )  # 不抛即通过
