#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""客户 CRUD 契约测试（由 SA-v04-S0 spike 生成器产出）。"""

import pytest


async def test_customer_requires_auth(client):
    """未登录访问必须 401。"""
    response = await client.get("/api/v1/customers")
    assert response.status_code == 401


async def test_customer_create_requires_permission(client, normal_auth_headers):
    """低权账户无 `customer:create` 权限 → 403（RBAC 生效）。"""
    response = await client.post(
        "/api/v1/customers", headers=normal_auth_headers,
        json={"name": "x", "email": "x@example.com"})
    assert response.status_code == 403, f"应 403，实际 {response.status_code}"


async def test_customer_crud_roundtrip(client, auth_headers):
    """管理员：创建 → 列表 → 详情 → 更新 → 删除 全链路。"""
    created = await client.post(
        "/api/v1/customers", headers=auth_headers,
        json={"name": "客户A", "email": "a@example.com", "status": "active"})
    assert created.status_code == 201, created.text[:200]
    body = created.json()
    assert body["data"]["name"] == "客户A"
    assert body["data"]["status"] == "active"

    listing = await client.get("/api/v1/customers", headers=auth_headers)
    assert listing.status_code == 200
    items = listing.json()["data"]["items"]
    assert any(i["email"] == "a@example.com" for i in items)

    obj_id = body["data"]["id"]
    updated = await client.put(
        f"/api/v1/customers/{obj_id}", headers=auth_headers,
        json={"status": "archived"})
    assert updated.status_code == 200
    assert updated.json()["data"]["status"] == "archived"

    detail = await client.get(f"/api/v1/customers/{obj_id}", headers=auth_headers)
    assert detail.status_code == 200, "更新后取详情应 200"

    missing = await client.get(f"/api/v1/customers/999999", headers=auth_headers)
    assert missing.status_code == 404

    deleted = await client.delete(f"/api/v1/customers/{obj_id}", headers=auth_headers)
    assert deleted.status_code == 200

    refetch = await client.get(f"/api/v1/customers/{obj_id}", headers=auth_headers)
    assert refetch.status_code == 404, "删除后复查应 404"


async def test_customer_create_requires_fields(client, auth_headers):
    """缺必填字段 → 400。"""
    response = await client.post("/api/v1/customers", headers=auth_headers, json={})
    assert response.status_code == 400
