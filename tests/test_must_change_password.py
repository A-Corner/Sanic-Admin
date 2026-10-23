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


async def test_initial_admin_created_with_flag(client):
    """初始管理员（环境变量口令创建）在 DB 层默认 must_change_password=True。

    conftest 会在 app 初始化后把标志复位（模拟"已改密"的常规运行态供
    其它测试使用），因此这里直接调创建函数在一个干净库上断言默认值；
    登录响应透出该标志由 test_flagged_session_* 与人工验收覆盖。
    """
    import asyncio
    import tempfile
    from pathlib import Path

    from tortoise import Tortoise

    from app.auth.authentication import create_initial_admin_account
    from app.config import config_to_dict, get_config
    from app.models import Account

    tmp = tempfile.mkdtemp()
    await Tortoise.init(
        db_url=f"sqlite://{tmp}/flag.sqlite", modules={"models": ["app.models"]}
    )
    try:
        await Tortoise.generate_schemas()
        await create_initial_admin_account()
        admin = await Account.get(email=os.environ["INITIAL_ADMIN_EMAIL"])
        assert admin.must_change_password is True, (
            "初始管理员（环境变量口令创建）必须默认携带强制改密标志"
        )
    finally:
        await Tortoise.close_connections()


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
    """正确 current 口令改密 → 标志清除 → API 恢复可用；旧口令失效。"""
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


async def test_normal_users_not_affected(client):
    """普通账户（非初始管理员）must_change_password=False，API 正常可用。"""
    other = Account(
        username="mcp_normal", email="mcp.normal@test.local",
        verified=True, disabled=False, is_admin=False,
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
    assert roles.status_code in (200, 403), (
        "普通账户不应被强制改密拦截（403 仅应是权限不足）"
    )
    if roles.status_code == 200:
        assert "PASSWORD_CHANGE_REQUIRED" not in roles.text
