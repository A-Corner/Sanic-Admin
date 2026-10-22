#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
角色 CRUD 主要路径测试。

覆盖 CPL 验收口径第 6 项：创建 → 列表 → 详情 → 更新 → 删除。

权限模型说明（重要）
====================
M1 的权限**不落独立的 Permission 表**，而是由 ``Role.permissions``（JSONField，
格式 ``{资源: [动作, ...]}``）承载，资源/动作的合法取值由
``app/auth/permissions.py`` 的注册表约束。所以本文件里"给账户授权"的方式是
**给角色授予 permissions 字典**，而不是往一张权限表里插记录。
"""

import pytest

from app.models import Role

_SUFFIX = 0


def _unique_role_name(prefix: str = "role") -> str:
    global _SUFFIX
    _SUFFIX += 1
    return f"{prefix}-{_SUFFIX:04d}"


async def test_role_create_returns_201(client, auth_headers):
    """创建角色 → 201，permissions 正确落库。"""
    name = _unique_role_name("created")
    response = await client.post(
        "/api/v1/roles",
        headers=auth_headers,
        json={
            "name": name,
            "description": "Lane E 创建测试",
            "permissions": {"account": ["read"]},
        },
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["success"] is True
    data = body["data"]
    assert data["name"] == name
    assert data["permissions"] == {"account": ["read"]}


async def test_role_create_rejects_duplicate_name(client, auth_headers):
    """角色名重复 → 400。"""
    name = _unique_role_name("dupe")
    payload = {"name": name, "permissions": {}}

    first = await client.post("/api/v1/roles", headers=auth_headers, json=payload)
    assert first.status_code == 201, first.text

    second = await client.post("/api/v1/roles", headers=auth_headers, json=payload)
    assert second.status_code == 400, second.text


async def test_role_create_rejects_unregistered_permission_resource(client, auth_headers):
    """
    权限资源必须已注册 → 400。

    防止写入永远无法生效的权限（例如拼错的资源名）。
    """
    response = await client.post(
        "/api/v1/roles",
        headers=auth_headers,
        json={
            "name": _unique_role_name("badperm"),
            "permissions": {"no-such-resource": ["read"]},
        },
    )
    assert response.status_code == 400, response.text


async def test_role_create_requires_permissions_field(client, auth_headers):
    """缺少 permissions → 400。"""
    response = await client.post(
        "/api/v1/roles",
        headers=auth_headers,
        json={"name": _unique_role_name("noperm")},
    )
    assert response.status_code == 400, response.text


async def test_role_list_contains_created_role(client, auth_headers):
    """角色列表 → 200，且包含刚创建的角色。"""
    name = _unique_role_name("listed")
    created = await client.post(
        "/api/v1/roles",
        headers=auth_headers,
        json={"name": name, "permissions": {}},
    )
    assert created.status_code == 201, created.text

    response = await client.get("/api/v1/roles", headers=auth_headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["success"] is True

    items = body["data"]["items"]
    assert any(item["name"] == name for item in items), (
        f"角色列表里找不到刚创建的 {name}：{[i.get('name') for i in items]}"
    )


async def test_role_detail_by_id(client, auth_headers):
    """角色详情 → 200。"""
    name = _unique_role_name("detail")
    created = await client.post(
        "/api/v1/roles",
        headers=auth_headers,
        json={"name": name, "permissions": {"role": ["read"]}},
    )
    assert created.status_code == 201, created.text
    role_id = created.json()["data"]["id"]

    response = await client.get(f"/api/v1/roles/{role_id}", headers=auth_headers)
    assert response.status_code == 200, response.text
    assert response.json()["data"]["name"] == name


async def test_role_detail_not_found(client, auth_headers):
    """不存在的角色 → 404。"""
    response = await client.get("/api/v1/roles/999999", headers=auth_headers)
    assert response.status_code == 404, response.text


async def test_role_update(client, auth_headers):
    """更新角色 → 200，permissions 被更新。"""
    name = _unique_role_name("updated")
    created = await client.post(
        "/api/v1/roles",
        headers=auth_headers,
        json={"name": name, "permissions": {"account": ["read"]}},
    )
    assert created.status_code == 201, created.text
    role_id = created.json()["data"]["id"]

    response = await client.put(
        f"/api/v1/roles/{role_id}",
        headers=auth_headers,
        json={"description": "Lane E 更新测试", "permissions": {"account": ["read", "create"]}},
    )
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["description"] == "Lane E 更新测试"
    assert set(data["permissions"]["account"]) == {"read", "create"}

    stored = await Role.get(id=role_id)
    assert set(stored.permissions["account"]) == {"read", "create"}


async def test_role_delete(client, auth_headers):
    """删除角色 → 200，随后详情查询 → 404。"""
    name = _unique_role_name("deleted")
    created = await client.post(
        "/api/v1/roles",
        headers=auth_headers,
        json={"name": name, "permissions": {}},
    )
    assert created.status_code == 201, created.text
    role_id = created.json()["data"]["id"]

    deleted = await client.delete(f"/api/v1/roles/{role_id}", headers=auth_headers)
    assert deleted.status_code == 200, deleted.text

    after = await client.get(f"/api/v1/roles/{role_id}", headers=auth_headers)
    assert after.status_code == 404, after.text


async def test_builtin_role_cannot_be_deleted(client, auth_headers):
    """内置角色（admin/user）不可删除 → 403。"""
    admin_role = await Role.filter(name="admin").first()
    if admin_role is None:
        pytest.skip("测试库里没有内置 admin 角色")

    response = await client.delete(f"/api/v1/roles/{admin_role.id}", headers=auth_headers)
    assert response.status_code == 403, response.text


async def test_role_members_endpoint(client, auth_headers):
    """角色成员列表 → 200。"""
    name = _unique_role_name("members")
    created = await client.post(
        "/api/v1/roles",
        headers=auth_headers,
        json={"name": name, "permissions": {}},
    )
    assert created.status_code == 201, created.text
    role_id = created.json()["data"]["id"]

    response = await client.get(f"/api/v1/roles/{role_id}/members", headers=auth_headers)
    assert response.status_code == 200, response.text
    assert response.json()["success"] is True


async def test_role_permissions_drive_account_access(client, auth_headers):
    """
    权限模型闭环：给角色授予 ``account:read`` 后，拥有该角色的普通账户能读账户列表。

    这是"权限由 Role.permissions 的 permissions 字典承载"的直接验证——
    不依赖任何独立的 Permission 表。
    """
    from app.models import Account

    role_name = _unique_role_name("granted")
    created = await client.post(
        "/api/v1/roles",
        headers=auth_headers,
        json={"name": role_name, "permissions": {"account": ["read"]}},
    )
    assert created.status_code == 201, created.text
    role = await Role.get(name=role_name)

    # 建一个只拥有该角色的普通账户
    email = f"granted.{role_name}@example.com"
    account = Account(
        username=f"granted{role_name.replace('-', '')}",
        email=email,
        verified=True,
        disabled=False,
        is_admin=False,
    )
    account.set_password("GrantedPass123!")
    await account.save()
    await account.roles.add(role)

    login = await client.post(
        "/auth/login", json={"email": email, "password": "GrantedPass123!"}
    )
    assert login.status_code == 200, login.text
    token = login.headers["authorization"]

    response = await client.get("/api/v1/accounts", headers={"Authorization": token})
    assert response.status_code == 200, (
        f"拥有 account:read 角色的账户访问账户列表返回 {response.status_code}，"
        f"应为 200：{response.text}"
    )
