#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
个人资料与操作日志端点测试（v0.3 P6 覆盖率）。

覆盖 ``app/api/resources/profile.py``（列表 / 详情 / 更新 / me）与
``log.py``（列表 / 详情 / 统计）的读路径与代表性写路径。
"""

async def test_my_profile_get_and_put(client, auth_headers):
    """GET /api/v1/me/profile → 200；PUT 修改后读回一致。"""
    got = await client.get("/api/v1/me/profile", headers=auth_headers)
    assert got.status_code == 200, got.text[:200]
    body = got.json()
    assert body.get("success") is True

    put = await client.put(
        "/api/v1/me/profile",
        headers=auth_headers,
        json={"nickname": "p6-coverage", "gender": "other",
              "address": "测试地址", "mobile_phone": "13800000000"},
    )
    assert put.status_code == 200, put.text[:200]
    reread = await client.get("/api/v1/me/profile", headers=auth_headers)
    data = reread.json().get("data") or {}
    assert data.get("nickname") == "p6-coverage", "PUT 后应能读回修改"


async def test_profile_list_is_paginated(client, auth_headers):
    """GET /api/v1/profiles → 200，信封含分页结构。"""
    response = await client.get("/api/v1/profiles", headers=auth_headers)
    assert response.status_code == 200, response.text[:200]
    body = response.json()
    assert body.get("success") is True
    data = body.get("data") or {}
    assert ("items" in data) or ("list" in data), f"缺少列表字段: {list(data)}"


async def test_profile_detail_and_update(client, auth_headers):
    """/profiles/<id>：GET 已存在资料 → 200；PUT 更新 → 200；GET 不存在 → 404。"""
    # 每个测试拿到的是全新内存库，Profile 行要等 me/profile 首次访问才创建
    seeding = await client.get("/api/v1/me/profile", headers=auth_headers)
    assert seeding.status_code == 200, seeding.text[:200]

    listing = await client.get("/api/v1/profiles", headers=auth_headers)
    data = listing.json().get("data") or {}
    items = data.get("items") or []
    assert items, f"列表里应至少有初始管理员的资料，响应字段: {list(data)}"
    pid = items[0]["id"]

    got = await client.get(f"/api/v1/profiles/{pid}", headers=auth_headers)
    assert got.status_code == 200, got.text[:200]

    put = await client.put(
        f"/api/v1/profiles/{pid}",
        headers=auth_headers,
        json={"nickname": "renamed-by-id"},
    )
    assert put.status_code == 200, put.text[:200]

    missing = await client.get("/api/v1/profiles/999999", headers=auth_headers)
    assert missing.status_code == 404, f"不存在的资料应 404，实际 {missing.status_code}"


async def test_log_list_and_statistics(client, auth_headers):
    """GET /api/v1/logs 与 /logs/statistics → 200，空库也返回信封。"""
    listing = await client.get("/api/v1/logs", headers=auth_headers)
    assert listing.status_code == 200, listing.text[:200]
    assert listing.json().get("success") is True

    stats = await client.get("/api/v1/logs/statistics", headers=auth_headers)
    assert stats.status_code == 200, stats.text[:200]
    assert stats.json().get("success") is True


async def test_log_detail_missing_is_404(client, auth_headers):
    """GET /api/v1/logs/<不存在的 id> → 404。"""
    response = await client.get("/api/v1/logs/999999", headers=auth_headers)
    assert response.status_code == 404, f"应 404，实际 {response.status_code}"


async def test_log_endpoints_require_auth(client):
    """未登录访问日志端点必须 401。"""
    for path in ("/api/v1/logs", "/api/v1/logs/statistics"):
        response = await client.get(path)
        assert response.status_code == 401, f"未登录 GET {path} 应 401"
