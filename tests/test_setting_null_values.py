#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
settings 资源对 null 值的处理（Editor B 的 F-1）。

背景：``_validate_text_fields`` 原本把 ``None`` 当作"未提供该字段"直接跳过，
于是 ``category=None`` 落进模型 —— 而 ``SystemSetting.category`` 的模型字段
不允许 null（``default="general"``，无 ``null=True``）—— Tortoise 在落库时抛
``ValidationError``，变成 **500**。

同时 ``validate_value_type`` 原本没有 string 分支，``value_type="string"`` 时
``value=None`` 穿过校验，被 ``str(None)`` 落库成字面量字符串 ``"None"`` ——
配置里出现字符串 "None" 是数据污染。

本文件用**白名单内的 key**（如 site_name）触发这些路径 —— 非白名单 key 会先被
key 校验挡掉（400），测不到后面的分支。
"""
import pytest


#: 白名单内的 key，用于真正走到字段校验分支
WHITELIST_KEY = "site_name"


async def test_create_with_null_category_is_400_not_500(client, auth_headers):
    """category=null 必须 400，不能是 500。"""
    response = await client.post(
        "/api/v1/settings",
        json={"key": WHITELIST_KEY, "value": "x", "value_type": "string",
              "category": None},
        headers=auth_headers,
    )
    assert response.status_code == 400, (
        f"category=null 返回 {response.status_code}，应为 400（曾为 500）"
    )
    assert "INTERNAL_ERROR" not in response.text, "不应是内部错误"


async def test_update_with_null_category_is_400_not_500(client, auth_headers):
    """PUT 路径的 category=null 同样必须 400。"""
    created = await client.post(
        "/api/v1/settings",
        json={"key": WHITELIST_KEY, "value": "x", "value_type": "string"},
        headers=auth_headers,
    )
    assert created.status_code == 201, f"前置创建失败：{created.status_code}"
    setting_id = created.json()["data"]["id"]

    response = await client.put(
        f"/api/v1/settings/{setting_id}",
        json={"value": "y", "category": None},
        headers=auth_headers,
    )
    assert response.status_code == 400, (
        f"PUT category=null 返回 {response.status_code}，应为 400（曾为 500）"
    )
    assert "INTERNAL_ERROR" not in response.text, "不应是内部错误"


async def test_create_with_null_description_is_400(client, auth_headers):
    """description=null 同样按非法值拒绝（模型允许 null，但语义上应与 category 一致）。"""
    response = await client.post(
        "/api/v1/settings",
        json={"key": WHITELIST_KEY, "value": "x", "value_type": "string",
              "description": None},
        headers=auth_headers,
    )
    assert response.status_code == 400, (
        f"description=null 返回 {response.status_code}，应为 400"
    )


@pytest.mark.parametrize("value_type", ["string", "int", "float", "bool", "json"])
async def test_create_with_null_value_is_400(client, auth_headers, value_type):
    """value=null 在**所有** value_type 下都必须 400，不得落库成字面量 "None"。"""
    response = await client.post(
        "/api/v1/settings",
        json={"key": WHITELIST_KEY, "value": None, "value_type": value_type},
        headers=auth_headers,
    )
    assert response.status_code == 400, (
        f"value=null (type={value_type}) 返回 {response.status_code}，应为 400"
    )


async def test_null_value_is_not_stored_as_literal_none(client, auth_headers):
    """核心断言：库里不能出现字符串 "None"。

    即使前面的请求被别的校验挡下，也要确认没有把 null 存成字面量 "None"。
    """
    response = await client.post(
        "/api/v1/settings",
        json={"key": WHITELIST_KEY, "value": None, "value_type": "string"},
        headers=auth_headers,
    )
    assert response.status_code == 400

    listing = await client.get("/api/v1/settings", headers=auth_headers)
    assert listing.status_code == 200
    body = listing.text
    assert '"raw_value":"None"' not in body, (
        "库中出现了字面量 \"None\" —— null 被 str() 落库了"
    )


async def test_string_value_type_rejects_non_string(client, auth_headers):
    """value_type=string 时，非字符串值应被拒（string 分支此前缺失）。"""
    response = await client.post(
        "/api/v1/settings",
        json={"key": WHITELIST_KEY, "value": {"a": 1}, "value_type": "string"},
        headers=auth_headers,
    )
    assert response.status_code == 400, (
        f"value_type=string 传 dict 返回 {response.status_code}，应为 400"
    )
