#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
CSRF 双提交 cookie 保护测试。

方案（v0.3 P2）：登录成功时下发非 HttpOnly 的 ``csrf_token`` cookie 并在
``X-CSRF-Token`` 响应头返回同值；此后凭会话 cookie 的写请求（非 GET/HEAD/OPTIONS）
必须让 ``X-CSRF-Token`` 请求头与 cookie 一致，否则 403 CSRF_TOKEN_INVALID。

适用范围按威胁模型收窄：
* GET/HEAD/OPTIONS 不校验；
* 只约束携带会话 cookie 的请求（无 cookie 的匿名请求交给认证层返回 401）；
* 显式 ``Authorization`` 头的请求豁免（跨站攻击者无法让浏览器携带自定义请求头）；
* 登录前端点（/auth/login、/auth/register）豁免（此时还没有 token）。
"""

import pytest

from app.middleware.security_middleware import SESSION_COOKIE_NAME
from app.models import AuthenticationSession

ADMIN_EMAIL = "SAdmin@Sanic.com"
ADMIN_PASSWORD = "TestAdminPass123!"


async def _login(client, email: str = ADMIN_EMAIL, password: str = ADMIN_PASSWORD):
    """登录并返回响应（cookie 已存入 client 的 cookie jar）。"""
    return await client.post("/auth/login", json={"email": email, "password": password})


def _csrf_header(client) -> dict:
    """从 cookie jar 里取 csrf_token 组装请求头。"""
    token = client.cookies.get("csrf_token")
    assert token, "登录后 cookie jar 里应存在 csrf_token"
    return {"X-CSRF-Token": token}


async def test_login_issues_csrf_cookie_and_header(client):
    """登录成功 → 下发 csrf_token cookie（非 HttpOnly、SameSite=Lax）与同值响应头。"""
    response = await _login(client)

    assert response.status_code == 200, response.text
    cookie_token = client.cookies.get("csrf_token")
    header_token = response.headers.get("x-csrf-token")
    assert cookie_token, "登录响应必须下发 csrf_token cookie"
    assert header_token == cookie_token, "响应头与 cookie 必须是同值（双提交）"

    # cookie 属性：前端 JS 要能读（非 HttpOnly），SameSite=Lax 与会话 cookie 一致
    set_cookies = response.headers.get_list("set-cookie")
    csrf_set_cookie = [c for c in set_cookies if c.startswith("csrf_token=")]
    assert csrf_set_cookie, f"Set-Cookie 里缺少 csrf_token: {set_cookies}"
    raw = csrf_set_cookie[0].lower()
    assert "httponly" not in raw, "csrf_token cookie 不能是 HttpOnly（前端需读取回填请求头）"
    assert "samesite=lax" in raw


async def test_write_with_session_cookie_and_no_csrf_header_forbidden(client):
    """凭会话 cookie 的写请求缺 X-CSRF-Token 头 → 403 CSRF_TOKEN_INVALID。"""
    await _login(client)

    response = await client.post("/auth/associated")

    assert response.status_code == 403, response.text
    body = response.json()
    assert body["success"] is False
    assert body["error"] == "CSRF_TOKEN_INVALID"


async def test_write_with_matching_csrf_header_succeeds(client):
    """头与 cookie 一致 → 写请求正常通过（200）。"""
    await _login(client)

    response = await client.post("/auth/associated", headers=_csrf_header(client))

    assert response.status_code == 200, response.text


async def test_write_with_wrong_csrf_header_forbidden(client):
    """头与 cookie 不一致 → 403。"""
    await _login(client)

    response = await client.post(
        "/auth/associated", headers={"X-CSRF-Token": "forged-token-value"}
    )

    assert response.status_code == 403, response.text
    assert response.json()["error"] == "CSRF_TOKEN_INVALID"


async def test_get_requests_do_not_require_csrf(client):
    """GET 请求不要求 CSRF 头：健康检查与带会话 cookie 的 GET API 均正常。"""
    await _login(client)

    health = await client.get("/health")
    assert health.status_code == 200, health.text

    # 带会话 cookie（无 Authorization 头、无 CSRF 头）的 GET API 照常工作
    listing = await client.get("/api/v1/accounts?page=1&page_size=1")
    assert listing.status_code == 200, listing.text


async def test_login_and_register_are_exempt(client, app):
    """登录前端点豁免：没有 csrf token 也能正常提交（401 是凭据问题，不是 403）。

    AUTH-02② 起自助注册默认关闭，``/auth/register`` 默认返回 403
    ``REGISTRATION_DISABLED``。那个 403 与「CSRF 校验失败 403」在状态码上
    无法区分，会让本条失去判别力 —— 所以这里显式开启开关，让端点真正走到
    处理函数。断言不变：**没有 csrf token 也能 200**，这仍然证明豁免成立
    （CSRF 校验发生在路由之前，开关关闭时同样豁免，只是结果也是 403）。
    """
    app.config["ALLOW_SELF_REGISTRATION"] = True

    wrong_password = await client.post(
        "/auth/login", json={"email": ADMIN_EMAIL, "password": "WrongPassword123!"}
    )
    assert wrong_password.status_code == 401, wrong_password.text

    register = await client.post(
        "/auth/register",
        json={
            "username": "csrf_probe_user",
            "email": "csrf-probe@example.com",
            "password": "ProbePass123!",
        },
    )
    assert register.status_code == 200, register.text


async def test_authorization_header_requests_exempt(client, admin_token):
    """显式 Authorization 头的请求豁免 CSRF（跨站无法伪造自定义头）。"""
    response = await client.post(
        "/auth/associated", headers={"Authorization": admin_token}
    )
    assert response.status_code == 200, response.text


async def test_anonymous_write_hits_auth_layer_not_csrf(client):
    """无会话 cookie 的匿名写请求不触发 CSRF（403），交由认证层返回 401。"""
    response = await client.post("/api/v1/accounts", json={"username": "x"})
    assert response.status_code == 401, response.text


async def test_amis_pages_still_served(client):
    """AMIS 页面是 GET 静态资源，不受 CSRF 影响。"""
    for path in ("/amis/", "/amis/login.html", "/amis/index.html"):
        response = await client.get(path)
        assert response.status_code == 200, f"{path} -> {response.status_code}"


def test_session_cookie_name_stays_in_sync():
    """CSRF 触发条件锚定在会话 cookie 名上，模型改名时两处必须同步。"""
    assert SESSION_COOKIE_NAME == AuthenticationSession.cookie_name


@pytest.mark.parametrize("method", ["put", "delete"])
async def test_other_write_methods_enforced(client, method):
    """PUT/DELETE 同样受 CSRF 约束（以 role 资源为例）。

    同一请求两次对比：无 CSRF 头 → 403 CSRF_TOKEN_INVALID（被 CSRF 层拦下）；
    带正确 CSRF 头 → 穿过 CSRF 层，到达业务/授权层（403 FORBIDDEN，
    admin 不能改/删自己拥有的角色——错误码不同证明走了不同的层）。
    """
    await _login(client)

    blocked = await getattr(client, method)("/api/v1/roles/1")
    assert blocked.status_code == 403, blocked.text
    assert blocked.json()["error"] == "CSRF_TOKEN_INVALID"

    allowed = await getattr(client, method)(
        "/api/v1/roles/1", headers=_csrf_header(client)
    )
    assert allowed.json()["error"] != "CSRF_TOKEN_INVALID", (
        "带正确 CSRF 头的请求不应再被 CSRF 层拦截"
    )
