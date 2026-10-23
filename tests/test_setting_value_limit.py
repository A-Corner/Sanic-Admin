#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
settings 资源对 value 落库长度的校验（v0.3 P1 任务 A）。

背景：``SystemSetting.value`` 是 TextField，数据库层没有长度限制；此前四条
写路径（POST /api/v1/settings、PUT /settings/<id>、PUT /settings/key/<key>、
PUT /settings/bulk）对 value 只有类型校验，没有业务长度上限 —— 单条配置可以
膨胀到请求体上限（16MB），读接口会把整行原样回传。

钳制对象是 ``_store_value`` 的**落库产物**，而不是请求体里 value 的原始形态：
json 类型的 dict/list 以 ``json.dumps(ensure_ascii=False)`` 字符串落库，
int/float/bool 会被字符串化，落库长度与请求体形态可能不同。以落库产物为准，
才能保证"库里不会出现超过上限的 value"。

边界：恰好 8192 个字符必须通过；8193 必须返回 400 VALIDATION_ERROR。
"""
import json


def _message(response) -> str:
    """取统一响应体里的 message（响应体把中文转义成 unicode escape，不能用原文匹配 text）。"""
    return response.json()["message"]


#: 白名单内的 key，用于真正走到字段校验分支
WHITELIST_KEY = "site_name"
#: 与实现中的 VALUE_MAX_LENGTH 一致（超限报错文案里会出现这个数字）
VALUE_MAX_LENGTH = 8192


def _json_value_with_stored_length(target: int) -> dict:
    """构造 ``json.dumps`` 后恰好 target 个字符的 dict（带自检）。"""
    # json.dumps({"a": "x" * n}, ensure_ascii=False) 的长度 = n + 9
    n = target - 9
    assert n >= 0, f"target {target} 过小，无法构造"
    value = {"a": "x" * n}
    stored = json.dumps(value, ensure_ascii=False)
    assert len(stored) == target, f"构造自检失败：落库长度 {len(stored)} != {target}"
    return value


async def _create_setting(client, auth_headers, key: str = WHITELIST_KEY, value: str = "init"):
    """前置：创建一个 string 类型的设置，返回 (response, id)。"""
    response = await client.post(
        "/api/v1/settings",
        json={"key": key, "value": value, "value_type": "string"},
        headers=auth_headers,
    )
    assert response.status_code == 201, f"前置创建失败：{response.status_code} {response.text}"
    return response, response.json()["data"]["id"]


# ---------------------------------------------------------------------------
# POST /api/v1/settings（collection）—— 恰好边界的正反两例
# ---------------------------------------------------------------------------

async def test_post_exact_boundary_8192_passes(client, auth_headers):
    """恰好 8192 个字符必须通过，且落库的就是这 8192 个字符。"""
    value = "x" * VALUE_MAX_LENGTH
    response = await client.post(
        "/api/v1/settings",
        json={"key": WHITELIST_KEY, "value": value, "value_type": "string"},
        headers=auth_headers,
    )
    assert response.status_code == 201, (
        f"恰好 {VALUE_MAX_LENGTH} 字符返回 {response.status_code}，应为 201：{response.text}"
    )
    assert len(response.json()["data"]["raw_value"]) == VALUE_MAX_LENGTH


async def test_post_over_boundary_8193_is_400(client, auth_headers):
    """8193 个字符必须 400，且不能落库。"""
    response = await client.post(
        "/api/v1/settings",
        json={"key": WHITELIST_KEY, "value": "x" * (VALUE_MAX_LENGTH + 1),
              "value_type": "string"},
        headers=auth_headers,
    )
    assert response.status_code == 400, (
        f"超限 value 返回 {response.status_code}，应为 400"
    )
    assert "长度不能超过" in _message(response), "报错文案应说明上限"
    assert str(VALUE_MAX_LENGTH) in _message(response), "报错文案应包含上限数字"

    # 拒绝后不得落库
    detail = await client.get(f"/api/v1/settings/key/{WHITELIST_KEY}", headers=auth_headers)
    assert detail.status_code == 404, "被拒的超限 value 不应出现在库里"


# ---------------------------------------------------------------------------
# PUT /settings/<id>
# ---------------------------------------------------------------------------

async def test_put_item_exact_boundary_8192_passes(client, auth_headers):
    """PUT 单项：恰好 8192 通过并落库。"""
    _, setting_id = await _create_setting(client, auth_headers)

    response = await client.put(
        f"/api/v1/settings/{setting_id}",
        json={"value": "x" * VALUE_MAX_LENGTH},
        headers=auth_headers,
    )
    assert response.status_code == 200, (
        f"PUT 恰好 {VALUE_MAX_LENGTH} 字符返回 {response.status_code}，应为 200"
    )
    assert len(response.json()["data"]["raw_value"]) == VALUE_MAX_LENGTH


async def test_put_item_over_boundary_8193_is_400_and_keeps_old_value(client, auth_headers):
    """PUT 单项：8193 返回 400，且旧值不被覆盖。"""
    _, setting_id = await _create_setting(client, auth_headers, value="old-value")

    response = await client.put(
        f"/api/v1/settings/{setting_id}",
        json={"value": "x" * (VALUE_MAX_LENGTH + 1)},
        headers=auth_headers,
    )
    assert response.status_code == 400, f"PUT 超限 value 返回 {response.status_code}，应为 400"

    detail = await client.get(f"/api/v1/settings/{setting_id}", headers=auth_headers)
    assert detail.status_code == 200
    assert detail.json()["data"]["raw_value"] == "old-value", "被拒后旧值不应被覆盖"


# ---------------------------------------------------------------------------
# PUT /settings/key/<key>
# ---------------------------------------------------------------------------

async def test_put_by_key_exact_boundary_8192_passes(client, auth_headers):
    """PUT by key：恰好 8192 通过并落库。"""
    await _create_setting(client, auth_headers)

    response = await client.put(
        f"/api/v1/settings/key/{WHITELIST_KEY}",
        json={"value": "x" * VALUE_MAX_LENGTH},
        headers=auth_headers,
    )
    assert response.status_code == 200, (
        f"PUT by key 恰好 {VALUE_MAX_LENGTH} 字符返回 {response.status_code}，应为 200"
    )
    assert len(response.json()["data"]["raw_value"]) == VALUE_MAX_LENGTH


async def test_put_by_key_over_boundary_8193_is_400(client, auth_headers):
    """PUT by key：8193 返回 400。"""
    await _create_setting(client, auth_headers)

    response = await client.put(
        f"/api/v1/settings/key/{WHITELIST_KEY}",
        json={"value": "x" * (VALUE_MAX_LENGTH + 1)},
        headers=auth_headers,
    )
    assert response.status_code == 400, f"PUT by key 超限返回 {response.status_code}，应为 400"
    assert "长度不能超过" in _message(response)


# ---------------------------------------------------------------------------
# PUT /settings/bulk
# ---------------------------------------------------------------------------

async def test_bulk_exact_boundary_8192_passes(client, auth_headers):
    """bulk：恰好 8192 的成员正常更新（200）。"""
    await _create_setting(client, auth_headers, key="site_name")
    await _create_setting(client, auth_headers, key="site_footer")

    response = await client.put(
        "/api/v1/settings/bulk",
        json={"settings": {"site_name": "x" * VALUE_MAX_LENGTH, "site_footer": "ok"}},
        headers=auth_headers,
    )
    assert response.status_code == 200, (
        f"bulk 恰好 {VALUE_MAX_LENGTH} 字符返回 {response.status_code}，应为 200：{response.text}"
    )
    assert response.json()["data"]["errors"] == []
    assert len(response.json()["data"]["updated"][0]["raw_value"]) == VALUE_MAX_LENGTH


async def test_bulk_over_boundary_is_400_and_atomic(client, auth_headers):
    """bulk：任一成员超限必须 400，且整批不落库（合法成员也不被更新）。"""
    await _create_setting(client, auth_headers, key="site_name", value="init-name")
    await _create_setting(client, auth_headers, key="site_footer", value="init-footer")

    response = await client.put(
        "/api/v1/settings/bulk",
        json={"settings": {"site_name": "new-name",
                           "site_footer": "x" * (VALUE_MAX_LENGTH + 1)}},
        headers=auth_headers,
    )
    assert response.status_code == 400, (
        f"bulk 含超限成员返回 {response.status_code}，应为 400：{response.text}"
    )
    assert "site_footer" in _message(response), "报错应指明超限的 key"

    # 原子性：合法成员也不应被更新
    name = await client.get("/api/v1/settings/key/site_name", headers=auth_headers)
    assert name.json()["data"]["raw_value"] == "init-name", "整批拒绝后合法成员不应被更新"
    footer = await client.get("/api/v1/settings/key/site_footer", headers=auth_headers)
    assert footer.json()["data"]["raw_value"] == "init-footer"


# ---------------------------------------------------------------------------
# 各 value_type 至少各 1 例
# ---------------------------------------------------------------------------

async def test_int_type_large_value_stays_within_boundary(client, auth_headers):
    """int：大整数正常通过；int 实际上永远到不了 8192 上限。

    原因：Python 3.12 对 int 与字符串的互转有 4300 位的硬限制 —— 超过 4300 位的
    JSON 数字在请求体解析阶段就会被拒（进不了业务校验），而能被 ``int()`` 解析的
    值其 ``str()`` 落库产物也必然不超过 4300 位 < 8192。这里用 4000 位整数验证
    上限内的正常写路径。
    """
    value = int("9" * 4000)
    response = await client.post(
        "/api/v1/settings",
        json={"key": WHITELIST_KEY, "value": value, "value_type": "int"},
        headers=auth_headers,
    )
    assert response.status_code == 201, (
        f"4000 位 int 返回 {response.status_code}，应为 201：{response.text[:200]}"
    )
    assert len(response.json()["data"]["raw_value"]) == 4000


async def test_float_type_clamps_on_stored_string_not_numeric_value(client, auth_headers):
    """float：钳制对象是落库字符串。

    value 以字符串形式传 8193 位数字：``float()`` 能把它解析成 inf（数值形态
    只有 3 个字符 "inf"），但落库产物是原始的 8193 字符串 —— 必须被拒。
    """
    response = await client.post(
        "/api/v1/settings",
        json={"key": WHITELIST_KEY, "value": "9" * (VALUE_MAX_LENGTH + 1),
              "value_type": "float"},
        headers=auth_headers,
    )
    assert response.status_code == 400, (
        f"float 超限返回 {response.status_code}，应为 400：{response.text[:200]}"
    )
    assert "长度不能超过" in _message(response)


async def test_bool_type_stays_within_boundary(client, auth_headers):
    """bool：落库产物只有 "true"/"false"，永远在上限内，应正常通过。"""
    response = await client.post(
        "/api/v1/settings",
        json={"key": WHITELIST_KEY, "value": True, "value_type": "bool"},
        headers=auth_headers,
    )
    assert response.status_code == 201, f"bool 正常值返回 {response.status_code}，应为 201"
    assert response.json()["data"]["raw_value"] == "true"


async def test_json_type_exact_boundary_dict_passes(client, auth_headers):
    """json：dict 以 json.dumps 产物落库，产物恰好 8192 必须通过。"""
    value = _json_value_with_stored_length(VALUE_MAX_LENGTH)
    response = await client.post(
        "/api/v1/settings",
        json={"key": WHITELIST_KEY, "value": value, "value_type": "json"},
        headers=auth_headers,
    )
    assert response.status_code == 201, (
        f"json 恰好 {VALUE_MAX_LENGTH} 字符返回 {response.status_code}，应为 201：{response.text[:200]}"
    )
    assert len(response.json()["data"]["raw_value"]) == VALUE_MAX_LENGTH


async def test_json_type_over_boundary_dict_is_400(client, auth_headers):
    """json：dumps 产物 8193 必须被拒 —— 钳制的是落库产物，不是请求体形态。"""
    value = _json_value_with_stored_length(VALUE_MAX_LENGTH + 1)
    response = await client.post(
        "/api/v1/settings",
        json={"key": WHITELIST_KEY, "value": value, "value_type": "json"},
        headers=auth_headers,
    )
    assert response.status_code == 400, (
        f"json 超限返回 {response.status_code}，应为 400：{response.text[:200]}"
    )
    assert "长度不能超过" in _message(response)
