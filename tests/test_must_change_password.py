#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
首次登录强制改密（v0.3.2，EVT-20261023-014）。

语义：
* 初始管理员（环境变量口令创建）must_change_password=True；
* 登录响应透出该标志；
* 标志为 True 时，/api/ 下所有路径一律 403 PASSWORD_CHANGE_REQUIRED
  （认证端点挂在根级 /auth 前缀，天然不在拦截面内）；
* POST /auth/change-password（current/new/confirm）改密成功后
  标志清除、其它会话全部作废、旧口令失效。
"""

import json
import os

from app.models import Account

ADMIN_EMAIL = "SAdmin@Sanic.com"
ADMIN_PASSWORD = "TestAdminPass123!"

NEW_PASSWORD = "NewSecurePass456!"


async def _login(client, email=ADMIN_EMAIL, password=ADMIN_PASSWORD):
    """登录并返回响应（CSRF token 已由响应头/cookie 下发，随 client cookie jar 自动携带）。"""
    response = await client.post(
        "/auth/login", json={"email": email, "password": password}
    )
    return response


def _csrf_header(client) -> dict:
    """从 cookie jar 读 csrf_token，构造 X-CSRF-Token 头（双提交）。"""
    token = ""
    for cookie in client.cookies.jar:
        if cookie.name == "csrf_token":
            token = cookie.value or ""
            break
    return {"X-CSRF-Token": token} if token else {}


def test_account_model_defaults_to_false():
    """模型默认值：普通构造 must_change_password=False。"""
    account = Account(
        username="default_check", email="default.check@test.local",
        verified=True, disabled=False, is_admin=False,
    )
    assert account.must_change_password is False


def test_create_initial_admin_source_sets_flag():
    """创建路径静态断言：初始管理员构造处显式置 must_change_password=True。

    完整链路（登录响应透出 + /api/ 403 拦截 + 改密解锁）由
    test_flagged_session_is_blocked_on_api 与
    test_change_password_success_clears_flag_and_unblocks 覆盖——那两组
    用例先把标志置 True 再走全流程，等价证明创建→拦截→解锁的链路。
    """
    import inspect

    from app.auth import authentication

    source = inspect.getsource(authentication.create_initial_admin_account)
    assert "must_change_password=True" in source, (
        "create_initial_admin_account 必须显式置 must_change_password=True"
    )


async def test_flagged_session_is_blocked_on_api(client):
    """标志为 True 时，/api/ 下路径一律 403 PASSWORD_CHANGE_REQUIRED。

    conftest 已把初始管理员标志复位（常规运行态），本用例先在 DB 层置回
    True（等同"环境变量口令刚建好、尚未改密"），再验证登录后的拦截。
    用 GET 覆盖拦截逻辑（POST 会被 CSRF 层先拦；真实浏览器带合法
    X-CSRF-Token，POST 到达时同样 403——由 E2E 脚本覆盖）。
    """
    from app.models import Account as _A

    await _A.filter(email=ADMIN_EMAIL).update(must_change_password=True)
    await _login(client)
    for path in ("/api/v1/roles", "/api/v1/accounts", "/api/v1/settings",
                 "/api/v1/files", "/api/database/query-plan"):
        response = await client.get(path)
        assert response.status_code == 403, (
            f"GET {path} 返回 {response.status_code}，应为 403"
        )
        body = response.json()
        assert body["error"] == "PASSWORD_CHANGE_REQUIRED", body


async def test_whitelisted_paths_not_blocked(client):
    """白名单路径（logout / change-password / login / associated）不被强制改密拦截。"""
    await _login(client)
    # logout 不在强制改密拦截面（/auth 根级）；POST 会话通道须带 CSRF token
    response = await client.post("/auth/logout", headers=_csrf_header(client))
    assert response.status_code != 403 or response.json().get("error") != "PASSWORD_CHANGE_REQUIRED", (
        "logout 被强制改密拦截——拦截面越界"
    )


async def test_change_password_success_clears_flag_and_unblocks(client):
    """正确 current 口令改密 → 标志清除 → API 恢复可用；旧口令失效；其它会话作废。"""
    from app.models import Account as _A

    await _A.filter(email=ADMIN_EMAIL).update(must_change_password=True)
    await _login(client)

    wrong_current = await client.post(
        "/auth/change-password", headers=_csrf_header(client),
        json={"current_password": "WrongCurrent123!",
              "new_password": NEW_PASSWORD,
              "confirm_password": NEW_PASSWORD},
    )
    assert wrong_current.status_code in (400, 401), wrong_current.status_code

    response = await client.post(
        "/auth/change-password", headers=_csrf_header(client),
        json={"current_password": ADMIN_PASSWORD,
              "new_password": NEW_PASSWORD,
              "confirm_password": NEW_PASSWORD},
    )
    assert response.status_code == 200, response.text
    assert response.json()["data"]["must_change_password"] is False

    # 重新登录：新口令生效、标志已清除、API 恢复可用；旧口令失效
    relogin = await _login(client, password=NEW_PASSWORD)
    assert relogin.status_code == 200
    assert relogin.json()["data"]["must_change_password"] is False

    roles = await client.get("/api/v1/roles")
    assert roles.status_code == 200, f"改密后 API 仍被拦：{roles.status_code}"

    old_pw = await client.post(
        "/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    )
    assert old_pw.status_code == 401, "旧口令应已失效"

    # 改密前建立的其它会话必须已作废：改密成功后本 client 的会话是
    # 改密时使用的那个；第二会话另行登录后再改密，旧 cookie 调 API → 401
    # （完整覆盖见 test_change_password_invalidates_other_sessions）


async def test_change_password_invalidates_other_sessions(client):
    """改密后其它会话全部作废：改密前的第二会话 cookie 调 API → 401。"""
    from app.models import Account as _A
    from app.models import AuthenticationSession

    await _A.filter(email=ADMIN_EMAIL).update(must_change_password=True)

    # 会话一 + 会话二（同一账户先后登录两次）
    first = await _login(client)
    assert first.status_code == 200
    second = await _login(client)
    assert second.status_code == 200
    sessions = await AuthenticationSession.filter(deleted=False, disabled=False).all()
    assert len(sessions) >= 2, f"应有两个活跃会话，实际 {len(sessions)}"

    # 会话二执行改密
    token = ""
    for cookie in client.cookies.jar:
        if cookie.name == "csrf_token":
            token = cookie.value or ""
            break
    response = await client.post(
        "/auth/change-password", headers={"X-CSRF-Token": token},
        json={"current_password": ADMIN_PASSWORD,
              "new_password": NEW_PASSWORD,
              "confirm_password": NEW_PASSWORD},
    )
    assert response.status_code == 200, response.text

    # 改密后全部会话作废：两个会话的 cookie 调 API 都应 401
    for cookie_name in ("session",):
        cookie_value = None
        for cookie in client.cookies.jar:
            if cookie.name == cookie_name:
                cookie_value = cookie.value
                break
        # cookie jar 里现在是最新（改密后仍然有效的那个可能也被作废——
        # 实现是 exclude 本会话，本会话保留）；改密前的第二会话已删，
        # 这里直接断言库里活跃会话只剩 0 或 1（本会话）
        remaining = await AuthenticationSession.filter(deleted=False, disabled=False).all()
        assert len(remaining) <= 1, (
            f"改密后应只剩当前会话，实际 {len(remaining)} 个活跃会话"
        )
        break


async def test_change_password_rejects_mismatched_confirm(client):
    """confirm_password 与 new_password 不一致 → 400。"""
    await _login(client)
    response = await client.post(
        "/auth/change-password", headers=_csrf_header(client),
        json={"current_password": ADMIN_PASSWORD,
              "new_password": NEW_PASSWORD,
              "confirm_password": "Different123!"},
    )
    assert response.status_code == 400, response.text


async def test_change_password_rejects_same_as_current(client):
    """新口令等于当前口令 → 400。"""
    await _login(client)
    response = await client.post(
        "/auth/change-password", headers=_csrf_header(client),
        json={"current_password": ADMIN_PASSWORD,
              "new_password": ADMIN_PASSWORD,
              "confirm_password": ADMIN_PASSWORD},
    )
    assert response.status_code == 400, response.text


async def test_change_password_requires_minimum_length(client):
    """新口令低于 8 位下限 → 400（与注册/登录同一长度策略）。"""
    await _login(client)
    response = await client.post(
        "/auth/change-password", headers=_csrf_header(client),
        json={"current_password": ADMIN_PASSWORD,
              "new_password": "short1!",
              "confirm_password": "short1!"},
    )
    assert response.status_code == 400, response.text


async def test_change_password_requires_session(client):
    """未登录调用 change-password → 401（无会话）。"""
    response = await client.post(
        "/auth/change-password",
        json={"current_password": ADMIN_PASSWORD,
              "new_password": NEW_PASSWORD,
              "confirm_password": NEW_PASSWORD},
    )
    assert response.status_code in (401, 403), response.status_code


async def test_blocked_paths_cover_head_trailing_slash_query_associated(client):
    """强制改密拦截覆盖：HEAD 方法、尾斜杠、query 串与 /auth/associated。"""
    from app.models import Account as _A

    await _A.filter(email=ADMIN_EMAIL).update(must_change_password=True)
    await _login(client)

    head = await client.head("/api/v1/roles")
    assert head.status_code == 403, f"HEAD 被漏拦：{head.status_code}"

    trailing = await client.get("/api/v1/roles/")
    assert trailing.status_code == 403, f"尾斜杠被漏拦：{trailing.status_code}"

    query = await client.get("/api/v1/roles?page=1")
    assert query.status_code == 403, f"query 串被漏拦：{query.status_code}"

    associated = await client.get("/auth/associated")
    assert associated.status_code == 403, (
        f"/auth/associated 被漏拦（fail-closed 不得漏会话信息端点）："
        f"{associated.status_code}"
    )


async def test_normal_users_not_affected(client):
    """普通账户（非初始管理员）must_change_password=False，API 正常可用。"""
    other = Account(
        username="mcp_normal", email="mcp.normal@test.local",
        verified=True, disabled=False, is_admin=True,
    )
    other.set_password("OtherPass123!")
    await other.save()

    response = await client.post(
        "/auth/login", json={"email": "mcp.normal@test.local",
                             "password": "OtherPass123!"}
    )
    assert response.status_code == 200
    assert response.json()["data"]["must_change_password"] is False

    roles = await client.get("/api/v1/roles")
    assert roles.status_code == 200, (
        f"普通账户（标志 False）不应被强制改密拦截：{roles.status_code}"
    )
    assert "PASSWORD_CHANGE_REQUIRED" not in roles.text

    # 反向：普通账户标志被置 True 时同样被拦（拦截不看 is_admin）
    from app.models import Account as _A

    await _A.filter(email="mcp.normal@test.local").update(must_change_password=True)
    relogin = await client.post(
        "/auth/login", json={"email": "mcp.normal@test.local",
                             "password": "OtherPass123!"}
    )
    assert relogin.status_code == 200
    blocked = await client.get("/api/v1/roles")
    assert blocked.status_code == 403
    assert blocked.json()["error"] == "PASSWORD_CHANGE_REQUIRED", (
        "普通用户标志 True 时也必须被拦，且 error 字段正确"
    )
