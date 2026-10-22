#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
账户 CRUD 主要路径测试。

覆盖 CPL 验收口径第 5 项：创建 → 列表 → 详情 → 更新 → 删除。
"""

import pytest

from app.models import Account

#: 每次测试用不同的邮箱/用户名，避免唯一约束互相干扰
_SUFFIX = 0


def _unique(prefix: str = "acct") -> tuple:
    """生成一组唯一标识（邮箱、用户名）。"""
    global _SUFFIX
    _SUFFIX += 1
    marker = f"{_SUFFIX:04d}"
    return f"{prefix}.{marker}@example.com", f"{prefix}{marker}"


async def test_account_create_returns_201(client, auth_headers):
    """创建账户 → 201，返回新账户信息，且不回显口令。"""
    email, username = _unique("create")
    response = await client.post(
        "/api/v1/accounts",
        headers=auth_headers,
        json={
            "username": username,
            "email": email,
            "password": "CreatePass123!",
        },
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["success"] is True
    data = body["data"]
    assert data["email"] == email
    assert data["username"] == username
    # 口令绝不能回显
    assert "password" not in data
    assert "TestAdminPass123!" not in response.text


async def test_account_create_rejects_duplicate_email(client, auth_headers):
    """重复邮箱 → 400。"""
    email, username = _unique("dupe")
    payload = {"username": username, "email": email, "password": "CreatePass123!"}

    first = await client.post("/api/v1/accounts", headers=auth_headers, json=payload)
    assert first.status_code == 201, first.text

    second = await client.post(
        "/api/v1/accounts",
        headers=auth_headers,
        json={"username": username + "b", "email": email, "password": "CreatePass123!"},
    )
    assert second.status_code == 400, second.text


async def test_account_create_requires_password(client, auth_headers):
    """缺少口令 → 400。"""
    email, username = _unique("nopw")
    response = await client.post(
        "/api/v1/accounts",
        headers=auth_headers,
        json={"username": username, "email": email},
    )
    assert response.status_code == 400, response.text


async def test_account_create_rejects_invalid_email(client, auth_headers):
    """非法邮箱 → 400。"""
    _, username = _unique("bademail")
    response = await client.post(
        "/api/v1/accounts",
        headers=auth_headers,
        json={
            "username": username,
            "email": "not-an-email",
            "password": "CreatePass123!",
        },
    )
    assert response.status_code == 400, response.text


async def test_account_list_contains_created_account(client, auth_headers):
    """账户列表 → 200，且包含刚创建的账户。"""
    email, username = _unique("listed")
    created = await client.post(
        "/api/v1/accounts",
        headers=auth_headers,
        json={"username": username, "email": email, "password": "CreatePass123!"},
    )
    assert created.status_code == 201, created.text

    response = await client.get("/api/v1/accounts", headers=auth_headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["success"] is True

    items = body["data"]["items"]
    assert any(item["email"] == email for item in items), (
        f"账户列表里找不到刚创建的 {email}：{[i.get('email') for i in items]}"
    )


async def test_account_detail_by_id(client, auth_headers):
    """账户详情 → 200，返回指定账户。"""
    email, username = _unique("detail")
    created = await client.post(
        "/api/v1/accounts",
        headers=auth_headers,
        json={"username": username, "email": email, "password": "CreatePass123!"},
    )
    assert created.status_code == 201, created.text
    account_id = created.json()["data"]["id"]

    response = await client.get(f"/api/v1/accounts/{account_id}", headers=auth_headers)
    assert response.status_code == 200, response.text
    assert response.json()["data"]["email"] == email


async def test_account_detail_not_found(client, auth_headers):
    """不存在的账户 → 404。"""
    response = await client.get("/api/v1/accounts/999999", headers=auth_headers)
    assert response.status_code == 404, response.text


async def test_account_update(client, auth_headers):
    """更新账户 → 200，字段被更新。"""
    email, username = _unique("update")
    created = await client.post(
        "/api/v1/accounts",
        headers=auth_headers,
        json={"username": username, "email": email, "password": "CreatePass123!"},
    )
    assert created.status_code == 201, created.text
    account_id = created.json()["data"]["id"]

    new_email, _ = _unique("updated")
    response = await client.put(
        f"/api/v1/accounts/{account_id}",
        headers=auth_headers,
        json={"email": new_email},
    )
    assert response.status_code == 200, response.text
    assert response.json()["data"]["email"] == new_email

    # 落库验证
    stored = await Account.get(id=account_id)
    assert stored.email == new_email


async def test_account_update_cannot_escalate_to_admin(client, auth_headers):
    """
    创建账户时传入 ``is_admin`` 不得生效（白名单拒绝提权）。

    这是 mass-assignment 的关键防线：客户端即使显式传 ``is_admin: true``，
    新账户也必须是普通账户。
    """
    email, username = _unique("escalate")
    response = await client.post(
        "/api/v1/accounts",
        headers=auth_headers,
        json={
            "username": username,
            "email": email,
            "password": "CreatePass123!",
            "is_admin": True,
        },
    )

    assert response.status_code == 201, response.text
    assert response.json()["data"].get("is_admin") is not True

    stored = await Account.get(email=email)
    assert stored.is_admin is False


async def test_account_delete(client, auth_headers):
    """删除账户 → 200，随后详情查询 → 404。"""
    email, username = _unique("delete")
    created = await client.post(
        "/api/v1/accounts",
        headers=auth_headers,
        json={"username": username, "email": email, "password": "CreatePass123!"},
    )
    assert created.status_code == 201, created.text
    account_id = created.json()["data"]["id"]

    deleted = await client.delete(f"/api/v1/accounts/{account_id}", headers=auth_headers)
    assert deleted.status_code == 200, deleted.text

    after = await client.get(f"/api/v1/accounts/{account_id}", headers=auth_headers)
    assert after.status_code == 404, after.text


async def test_account_delete_admin_forbidden(client, auth_headers):
    """不允许删除管理员账户 → 403。"""
    admin = await Account.get(email="SAdmin@Sanic.com")
    response = await client.delete(f"/api/v1/accounts/{admin.id}", headers=auth_headers)
    assert response.status_code == 403, response.text


async def test_account_me_returns_current_account(client, auth_headers):
    """``/api/v1/accounts/me`` 返回当前登录账户及其角色。"""
    response = await client.get("/api/v1/accounts/me", headers=auth_headers)
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["email"] == "SAdmin@Sanic.com"
    assert "roles" in data
    assert "permissions" in data


async def test_account_password_update(client, auth_headers):
    """修改账户口令 → 200。"""
    email, username = _unique("pw")
    created = await client.post(
        "/api/v1/accounts",
        headers=auth_headers,
        json={"username": username, "email": email, "password": "CreatePass123!"},
    )
    assert created.status_code == 201, created.text
    account_id = created.json()["data"]["id"]

    response = await client.put(
        f"/api/v1/accounts/{account_id}/password",
        headers=auth_headers,
        json={"current_password": "CreatePass123!", "new_password": "NewPass12345!"},
    )
    assert response.status_code == 200, response.text


async def test_account_password_update_wrong_current_password(client, auth_headers):
    """当前口令错误 → 400。"""
    email, username = _unique("pwbad")
    created = await client.post(
        "/api/v1/accounts",
        headers=auth_headers,
        json={"username": username, "email": email, "password": "CreatePass123!"},
    )
    account_id = created.json()["data"]["id"]

    response = await client.put(
        f"/api/v1/accounts/{account_id}/password",
        headers=auth_headers,
        json={"current_password": "TotallyWrong123!", "new_password": "NewPass12345!"},
    )
    assert response.status_code == 400, response.text
