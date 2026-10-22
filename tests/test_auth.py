#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
认证相关测试：登录成功 / 登录失败 / 未认证访问 / 会话失效。

覆盖 CPL 验收口径第 1 项（登录成功与失败）。
"""

import pytest


async def test_login_success_returns_token(client):
    """登录成功 → 200，拿到 Authorization 头里的 token 与会话 Cookie。"""
    response = await client.post(
        "/auth/login",
        json={"email": "SAdmin@Sanic.com", "password": "TestAdminPass123!"},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == 0
    assert body["msg"]

    # 令牌通过响应头下发（Session.encode）
    token = response.headers.get("authorization")
    assert token and token.startswith("Bearer ")
    # 会话 Cookie 同时下发，前端可凭它保持登录态
    assert "session" in response.cookies


async def test_login_with_username_success(client):
    """也允许用用户名登录（ALLOW_LOGIN_WITH_USERNAME）。"""
    response = await client.post(
        "/auth/login",
        json={"username": "SAdmin", "password": "TestAdminPass123!"},
    )
    assert response.status_code == 200, response.text
    assert response.headers.get("authorization", "").startswith("Bearer ")


async def test_login_wrong_password_returns_401(client):
    """登录失败（口令错误）→ 401，且不泄露账户是否存在。"""
    response = await client.post(
        "/auth/login",
        json={"email": "SAdmin@Sanic.com", "password": "WrongPassword123!"},
    )

    assert response.status_code == 401, response.text
    body = response.json()
    assert body["success"] is False
    assert body["error"] == "CREDENTIALS_ERROR"
    # 账户不存在与口令错误必须返回同样的文案，避免账户枚举
    assert body["message"] == "用户名或密码错误"


async def test_login_unknown_account_returns_401(client):
    """登录失败（账户不存在）→ 401，文案与口令错误一致。"""
    response = await client.post(
        "/auth/login",
        json={"email": "no.such.person@example.com", "password": "TestAdminPass123!"},
    )

    assert response.status_code == 401, response.text
    body = response.json()
    assert body["success"] is False
    assert body["error"] == "CREDENTIALS_ERROR"
    assert body["message"] == "用户名或密码错误"


async def test_login_missing_credentials_returns_400(client):
    """既没有用户名也没有邮箱 → 400（参数校验失败，不是 401）。"""
    response = await client.post("/auth/login", json={"password": "TestAdminPass123!"})
    assert response.status_code == 400, response.text


async def test_login_short_password_rejected(client):
    """口令短于最小长度 → 400。"""
    response = await client.post(
        "/auth/login", json={"email": "SAdmin@Sanic.com", "password": "short"}
    )
    assert response.status_code == 400, response.text


async def test_protected_endpoint_without_token_returns_401(client):
    """未认证访问受保护接口 → 401（不是 500，也不是 404）。"""
    response = await client.get("/api/v1/accounts")
    assert response.status_code == 401, response.text


async def test_protected_endpoint_with_bogus_token_returns_401(client):
    """伪造 token → 401。"""
    response = await client.get(
        "/api/v1/accounts", headers={"Authorization": "Bearer not-a-real-token"}
    )
    assert response.status_code == 401, response.text


async def test_logout_invalidates_session(client, admin_token):
    """登出后同一 token 不再可用 → 401。"""
    logout = await client.post("/auth/logout", headers={"Authorization": admin_token})
    assert logout.status_code == 200, logout.text

    after = await client.get("/api/v1/accounts", headers={"Authorization": admin_token})
    assert after.status_code == 401, after.text


async def test_authenticated_request_succeeds(client, admin_token):
    """带真实 token 的请求成功（管理员可读账户列表）。"""
    response = await client.get(
        "/api/v1/accounts", headers={"Authorization": admin_token}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["success"] is True
    assert isinstance(body["data"]["items"], list)


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/api/v1/accounts"),
        ("PUT", "/api/v1/accounts/1"),
        ("DELETE", "/api/v1/accounts/1"),
        ("POST", "/api/v1/roles"),
    ],
)
async def test_unauthenticated_write_requests_return_401(client, method, path):
    """未认证的写操作一律 401。"""
    response = await client.request(method, path, json={})
    assert response.status_code == 401, response.text


async def test_options_preflight_is_not_blocked(client):
    """OPTIONS 预检不被 401 拦截（否则浏览器同源/跨域调用都会失败）。"""
    response = await client.request("OPTIONS", "/api/v1/accounts")
    assert response.status_code == 204, response.text


async def test_unknown_route_returns_404(client):
    """不存在的路由 → 404（不是 401，也不是 500）。"""
    response = await client.get("/api/v1/definitely-not-a-route")
    assert response.status_code == 404, response.text
