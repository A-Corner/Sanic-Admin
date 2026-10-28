#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
自助注册开关（AUTH-02②）。

语义（Owner 裁定选项 C）：

* ``ALLOW_SELF_REGISTRATION`` 默认 False，``POST /auth/register`` 直接
  403 ``REGISTRATION_DISABLED``；
* 账户只由管理员通过 ``POST /api/v1/accounts`` 创建，建号时可直接设
  ``verified=true``，该类账户立即可登录；
* 非管理员建号**可以**（沿用 ``account:create`` 权限），但**不能**把
  ``verified`` 置 True —— 那等于自己给自己发放可登录账户。

开关通过 ``app.config`` 读写（``create_app`` 把配置字典写进实例配置），
所以这些用例改的是**当前 app 实例**的配置，不触碰全局 ``settings``，
不会影响其它测试文件。
"""

import pytest

from app.models import Account, Role

#: 与 conftest 中的测试夹具一致的固定值（仅测试环境使用）
NEW_ACCOUNT_PASSWORD = "SelfRegPass123!"

_SUFFIX = 0


def _unique(prefix: str = "selfreg") -> tuple:
    """生成一组唯一标识（邮箱、用户名），避免跨用例唯一约束冲突。"""
    global _SUFFIX
    _SUFFIX += 1
    marker = f"{_SUFFIX:04d}"
    return f"{prefix}.{marker}@example.com", f"{prefix}{marker}"


@pytest.fixture()
def registration_enabled(app):
    """在当前 app 实例上临时开启自助注册；用例结束后复位为关闭。"""
    app.config["ALLOW_SELF_REGISTRATION"] = True
    try:
        yield app
    finally:
        app.config["ALLOW_SELF_REGISTRATION"] = False


async def _grant_account_create_only(account: Account) -> None:
    """给账户一个只含 ``account:create`` 的角色（能建号，但不是管理员）。"""
    role, _ = await Role.get_or_create(
        name="account-creator",
        defaults={"description": "只能创建账户", "permissions": {"account": ["create"]}},
    )
    await account.roles.add(role)


async def _login(client, email: str, password: str) -> str:
    """真实登录，返回 Authorization 头的 token。"""
    response = await client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    token = response.headers.get("authorization")
    assert token, "登录响应缺少 Authorization 头"
    return token


# ---------------------------------------------------------------------------
# 1 / 2：开关本身 —— 必须成对，单条没有判别力
# ---------------------------------------------------------------------------


async def test_register_disabled_returns_403(client):
    """默认关闭：注册端点 403，且错误码精确为 REGISTRATION_DISABLED。"""
    email, username = _unique("disabled")

    response = await client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": NEW_ACCOUNT_PASSWORD},
    )

    assert response.status_code == 403, response.text
    assert response.json()["error"] == "REGISTRATION_DISABLED", response.json()
    # 请求被拒时不得留下账户
    assert not await Account.filter(email=email).exists()


async def test_register_allowed_creates_account(client, registration_enabled):
    """开关开启：注册端点 200，账户真实落库。

    本条与 ``test_register_disabled_returns_403`` 成对：
    关闭时 403、开启时 200 —— 证明「开关这个变量真的改变了结果」。
    单看本条的 200 没有判别力（改动前也是 200）。

    **注意这不代表该账户可用**：它 `verified=False`，按 README「Known
    limitations」第 3 条，无人能投递验证码时该账户无法登录。
    本条只证明「开关生效」，不证明「自助注册产出的账户可用」。
    """
    email, username = _unique("allowed")

    response = await client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": NEW_ACCOUNT_PASSWORD},
    )

    assert response.status_code == 200, response.text

    account = await Account.filter(email=email).first()
    assert account is not None, "开关开启时账户应被创建"
    assert account.verified is False, "自助注册的账户仍应为未验证（README 已知限制第 3 条）"


# ---------------------------------------------------------------------------
# 3：管理员建号可直接设为已验证 → 能登录
# ---------------------------------------------------------------------------


async def test_admin_can_create_verified_account(client, auth_headers):
    """管理员建号带 verified=true → 201，账户 verified=True，且能登录。"""
    email, username = _unique("adminmade")

    response = await client.post(
        "/api/v1/accounts",
        headers=auth_headers,
        json={
            "username": username,
            "email": email,
            "password": NEW_ACCOUNT_PASSWORD,
            "verified": True,
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["data"]["verified"] is True

    account = await Account.filter(email=email).first()
    assert account is not None
    assert account.verified is True

    # 建号即可登录（不需要任何验证步骤）
    login = await client.post(
        "/auth/login", json={"email": email, "password": NEW_ACCOUNT_PASSWORD}
    )
    assert login.status_code == 200, login.text
    assert login.headers.get("authorization"), "登录应返回 Authorization 头"


# ---------------------------------------------------------------------------
# 4：非管理员不能把 verified 置 True
# ---------------------------------------------------------------------------


async def test_non_admin_cannot_set_verified(client):
    """非管理员建号带 verified=true → 403，且账户**没有被创建**。

    该账户被显式授予 ``account:create``，因此 403 **不是**来自
    ``@check_permissions`` 的前置拦截，而是来自 ``verified=True`` 的
    管理员判定 —— 否则这条用例会因为「没权限建号」而通过，失去判别力。
    """
    email, username = _unique("nonadmin")

    non_admin_email = f"creator.{_SUFFIX:04d}@example.com"
    creator = Account(
        username=f"creator{_SUFFIX:04d}",
        email=non_admin_email,
        verified=True,
        disabled=False,
        is_admin=False,
    )
    creator.set_password("CreatorPass123!")
    await creator.save()
    await _grant_account_create_only(creator)

    # 正向对照：同一账户建一个**不带 verified** 的号必须成功（证明它确实有
    # account:create 权限，403 只可能来自 verified 判定）。
    ok_email, ok_username = _unique("nonadmin_ok")
    allowed = await client.post(
        "/api/v1/accounts",
        headers={"Authorization": await _login(client, non_admin_email, "CreatorPass123!")},
        json={"username": ok_username, "email": ok_email, "password": NEW_ACCOUNT_PASSWORD},
    )
    assert allowed.status_code == 201, allowed.text

    response = await client.post(
        "/api/v1/accounts",
        headers={"Authorization": await _login(client, non_admin_email, "CreatorPass123!")},
        json={
            "username": username,
            "email": email,
            "password": NEW_ACCOUNT_PASSWORD,
            "verified": True,
        },
    )

    assert response.status_code == 403, response.text
    assert response.json()["error"] == "INSUFFICIENT_PERMISSIONS", response.json()
    # 关键：权限判定发生在创建之前 —— 不能留下「已建号再报错」的脏数据
    assert not await Account.filter(email=email).exists()


# ---------------------------------------------------------------------------
# 补充：verified 必须是布尔值，不接受字符串（bool("false") 为 True 的坑）
# ---------------------------------------------------------------------------


async def test_verified_must_be_boolean(client, auth_headers):
    """``verified: "true"``（字符串）→ 400，不可被当作 True 接受。"""
    email, username = _unique("strbool")

    response = await client.post(
        "/api/v1/accounts",
        headers=auth_headers,
        json={
            "username": username,
            "email": email,
            "password": NEW_ACCOUNT_PASSWORD,
            "verified": "true",
        },
    )

    assert response.status_code == 400, response.text
    assert response.json()["error"] == "VALIDATION_ERROR", response.json()
    assert not await Account.filter(email=email).exists()
