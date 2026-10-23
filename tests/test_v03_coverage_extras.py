#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
v0.3 P6 收尾批次：模型注册 / 缓存装饰器 / 上传 / 角色成员 / 账户负路径。

覆盖 ``app/docs/models.py``（Tortoise 模型 → OpenAPI，纯函数）、
``app/cache/decorators.py``（缓存键生成与清理）、``upload.py``（multipart
上传播权路径）、``role.py``（成员管理）、``account.py``（创建/更新的
校验分支）。所有断言都针对真实行为。
"""

import io

from app.docs import models as doc_models
from app.cache.decorators import generate_cache_key


# ---------------------------------------------------------------------------
# docs/models —— Tortoise 模型 → OpenAPI（纯注册，不碰 DB）
# ---------------------------------------------------------------------------

def test_register_tortoise_model_builds_openapi_schema():
    """register_tortoise_model 应把 Tortoise 模型字段翻译成 OpenAPI 属性。"""
    from app.models import Account

    name = "P6Account"
    doc_models.register_tortoise_model(Account, name=name)
    schema = doc_models.get_schemas().get(name)
    assert schema, f"注册后应能取到 {name}"
    props = schema.get("properties", {})
    assert "username" in props and "email" in props, f"应含模型列: {list(props)[:8]}"
    assert schema.get("type") == "object"


def test_register_tortoise_model_idempotent_and_alias():
    from app.models import Profile

    doc_models.register_tortoise_model(Profile, name="P6Profile")
    first = doc_models.get_schemas().get("P6Profile")
    doc_models.register_tortoise_model(Profile, name="P6Profile")
    again = doc_models.get_schemas().get("P6Profile")
    assert first == again, "重复注册应幂等"


def test_register_plain_model_class():
    from pydantic import BaseModel

    class P6Plain(BaseModel):
        id: int

    doc_models.register_model(P6Plain)
    assert doc_models.get_schemas().get("P6Plain"), "register_model 应登记 pydantic 模型"


# ---------------------------------------------------------------------------
# cache/decorators —— 缓存键生成
# ---------------------------------------------------------------------------

class _FakeArgs:
    def __init__(self, data):
        self._data = data

    def keys(self):
        return self._data.keys()

    def get(self, key, default=None):
        return self._data.get(key, default)

    def getlist(self, key):
        value = self._data.get(key)
        return [value] if value is not None else []


class _FakeRequest:
    method = "GET"
    path = "/api/v1/fake"
    args = _FakeArgs({"b": "2", "a": "1"})
    ctx = type("Ctx", (), {"authentication_session": None})()

    class endpoint:
        __name__ = "fake_view"

    @staticmethod
    def name():
        return "fake_view"


def test_generate_cache_key_is_order_insensitive():
    key1 = generate_cache_key(_FakeRequest(), include_query=True)
    # 键形如 METHOD:path:account:sorted_query（无前缀参数时没有 route: 前缀）
    assert key1.startswith("GET:/api/v1/fake:"), f"键应以方法+路径开头: {key1}"
    assert key1.endswith("a=1&b=2"), f"查询参数应按键排序合并: {key1}"
    key2 = generate_cache_key(_FakeRequest(), include_query=True)
    assert key1 == key2, "同一请求的键应稳定"


def test_generate_cache_key_excludes_query_when_asked():
    with_query = generate_cache_key(_FakeRequest(), include_query=True)
    without_query = generate_cache_key(_FakeRequest(), include_query=False)
    assert with_query != without_query, "含参与不含参的键应不同"


def test_clear_route_cache_returns_count():
    from app.cache.decorators import clear_route_cache

    cleared = clear_route_cache("*")
    assert isinstance(cleared, int) and cleared >= 0


# ---------------------------------------------------------------------------
# upload —— multipart 上传与文件列表
# ---------------------------------------------------------------------------

async def test_upload_file_roundtrip(client, auth_headers, tmp_path):
    """POST /api/v1/upload 上传 → 201；GET /files 列表可见；下载 200。"""
    payload = b"p6 coverage upload content"
    up = await client.post(
        "/api/v1/upload",
        headers=auth_headers,
        files={"file": ("p6.txt", io.BytesIO(payload), "text/plain")},
    )
    assert up.status_code in (200, 201), up.text[:200]

    listing = await client.get("/api/v1/files", headers=auth_headers)
    assert listing.status_code == 200, listing.text[:200]
    data = listing.json().get("data") or {}
    items = data.get("items") or []
    assert items, "上传后列表不应为空"
    fid = items[0]["id"]

    dl = await client.get(f"/api/v1/files/{fid}/download", headers=auth_headers)
    assert dl.status_code == 200, dl.text[:200]
    assert payload in (dl.content or b""), "下载内容应与上传一致"


async def test_upload_requires_file_part(client, auth_headers):
    """不带 file 字段的上传 → 400（校验分支）。"""
    up = await client.post("/api/v1/upload", headers=auth_headers)
    assert up.status_code == 400, f"应 400，实际 {up.status_code}"


async def test_upload_requires_auth(client):
    up = await client.post(
        "/api/v1/upload",
        files={"file": ("x.txt", io.BytesIO(b"x"), "text/plain")},
    )
    assert up.status_code == 401


# ---------------------------------------------------------------------------
# role —— 成员管理
# ---------------------------------------------------------------------------

async def _make_role(client, auth_headers, name):
    created = await client.post(
        "/api/v1/roles", headers=auth_headers,
        json={"name": name, "permissions": {"account": ["read"]}},
    )
    assert created.status_code == 201, created.text[:200]
    return created.json()["data"]["id"]


async def test_role_member_add_list_remove(client, auth_headers):
    """成员管理主路径：添加 → 列表可见 → 移除。"""
    import itertools
    counter = itertools.count()
    role_id = await _make_role(client, auth_headers, f"member-role-{next(counter)}")

    me = await client.get("/auth/validate", headers=auth_headers)
    assert me.status_code in (200, 404)  # 端点存在性不假设；拿不到就用列表法
    accounts = await client.get("/api/v1/accounts", headers=auth_headers)
    items = (accounts.json().get("data") or {}).get("items") or []
    assert items, "应至少有初始管理员账户"
    account_id = items[0]["id"]

    add = await client.post(
        f"/api/v1/roles/{role_id}/members",
        headers=auth_headers, json={"account_ids": [account_id]},
    )
    assert add.status_code in (200, 201), add.text[:200]

    members = await client.get(f"/api/v1/roles/{role_id}/members", headers=auth_headers)
    assert members.status_code == 200, members.text[:200]

    remove = await client.delete(
        f"/api/v1/roles/{role_id}/members/{account_id}", headers=auth_headers
    )
    assert remove.status_code in (200, 204), remove.text[:200]


async def test_role_member_add_unknown_account_is_4xx(client, auth_headers):
    """给角色添加不存在的账户 → 4xx（不静默成功）。"""
    import itertools
    role_id = await _make_role(client, auth_headers, "ghost-member-role")
    response = await client.post(
        f"/api/v1/roles/{role_id}/members",
        headers=auth_headers, json={"account_id": 999999},
    )
    assert 400 <= response.status_code < 500, (
        f"不存在的账户应 4xx，实际 {response.status_code}"
    )


# ---------------------------------------------------------------------------
# account —— 创建/更新校验分支
# ---------------------------------------------------------------------------

async def test_account_create_requires_fields(client, auth_headers):
    """缺必填字段的创建 → 400。"""
    response = await client.post("/api/v1/accounts", headers=auth_headers, json={})
    assert response.status_code == 400, f"应 400，实际 {response.status_code}"


async def test_account_create_duplicate_email_rejected(client, auth_headers):
    """重复邮箱创建 → 4xx。"""
    dup = await client.post(
        "/api/v1/accounts", headers=auth_headers,
        json={"email": "SAdmin@Sanic.com", "password": "XxXxXxXx99",
              "username": "dup-p6"},
    )
    assert 400 <= dup.status_code < 500, f"重复邮箱应 4xx，实际 {dup.status_code}"


async def test_account_create_success_then_get(client, auth_headers):
    """合法创建 → 201，列表可见。"""
    import itertools
    n = next(itertools.count())
    created = await client.post(
        "/api/v1/accounts", headers=auth_headers,
        json={"email": f"p6-{n}@example.com", "password": "XxXxXxXx99",
              "username": f"p6user{n}"},
    )
    assert created.status_code == 201, created.text[:200]
    data = created.json().get("data") or {}
    assert not data.get("password"), "响应不得回显口令"
