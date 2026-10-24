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
    response = await client.post("/auth/login", json={"email": email, "password": password})
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
        username="default_check",
        email="default.check@test.local",
        verified=True,
        disabled=False,
        is_admin=False,
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
    assert "must_change_password=True" in source, "create_initial_admin_account 必须显式置 must_change_password=True"


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
    for path in ("/api/v1/roles", "/api/v1/accounts", "/api/v1/settings", "/api/v1/files", "/api/database/query-plan"):
        response = await client.get(path)
        assert response.status_code == 403, f"GET {path} 返回 {response.status_code}，应为 403"
        body = response.json()
        assert body["error"] == "PASSWORD_CHANGE_REQUIRED", body


async def test_whitelisted_paths_not_blocked(client):
    """标志为 True 时，白名单路径（change-password / logout）不被强制改密拦截。

    先在 DB 层把标志置 True（否则 conftest 复位后的 False 态下本用例恒过，
    证明不了白名单）；正向对照：同一会话访问 /api/v1/roles 必须 403。
    """
    from app.models import Account as _A

    await _A.filter(email=ADMIN_EMAIL).update(must_change_password=True)
    login = await _login(client)
    assert login.status_code == 200, login.text

    # 正向对照：拦截确实生效
    blocked = await client.get("/api/v1/roles")
    assert blocked.status_code == 403, blocked.status_code
    assert blocked.json()["error"] == "PASSWORD_CHANGE_REQUIRED"

    # change-password 白名单：参数校验失败（缺 new_password）→ 400，而非 403
    change = await client.post(
        "/auth/change-password",
        headers=_csrf_header(client),
        json={"current_password": ADMIN_PASSWORD},
    )
    assert change.status_code == 400, (change.status_code, change.text)

    # logout 白名单：正常注销 → 200
    response = await client.post("/auth/logout", headers=_csrf_header(client))
    assert response.status_code == 200, (response.status_code, response.text)


async def test_change_password_success_clears_flag_and_unblocks(client):
    """正确 current 口令改密 → 标志清除 → API 恢复可用；旧口令失效；其它会话作废。"""
    from app.models import Account as _A

    await _A.filter(email=ADMIN_EMAIL).update(must_change_password=True)
    await _login(client)

    wrong_current = await client.post(
        "/auth/change-password",
        headers=_csrf_header(client),
        json={"current_password": "WrongCurrent123!", "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD},
    )
    assert wrong_current.status_code in (400, 401), wrong_current.status_code

    response = await client.post(
        "/auth/change-password",
        headers=_csrf_header(client),
        json={"current_password": ADMIN_PASSWORD, "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD},
    )
    assert response.status_code == 200, response.text
    assert response.json()["data"]["must_change_password"] is False

    # 重新登录：新口令生效、标志已清除、API 恢复可用；旧口令失效
    relogin = await _login(client, password=NEW_PASSWORD)
    assert relogin.status_code == 200
    assert relogin.json()["data"]["must_change_password"] is False

    roles = await client.get("/api/v1/roles")
    assert roles.status_code == 200, f"改密后 API 仍被拦：{roles.status_code}"

    old_pw = await client.post("/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert old_pw.status_code == 401, "旧口令应已失效"

    # 改密前建立的其它会话必须已作废：改密成功后本 client 的会话是
    # 改密时使用的那个；第二会话另行登录后再改密，旧 cookie 调 API → 401
    # （完整覆盖见 test_change_password_invalidates_other_sessions）


async def test_change_password_rotates_all_sessions(client):
    """改密后**全部**旧会话作废，并轮换出一个新会话（SA-v034-L1 第 4 项）。

    与 v0.3.2 的差别：旧行为保留「发起改密的那个会话」，新行为把它也作废并
    签发新 token —— 这样即使当前 token 曾泄露，改密后立即失效。
    """
    from app.models import Account as _A
    from app.models import AuthenticationSession

    await _A.filter(email=ADMIN_EMAIL).update(must_change_password=True)

    # 会话一 + 会话二（同一账户先后登录两次）；记下会话二的令牌
    first = await _login(client)
    assert first.status_code == 200
    first_token = first.headers.get("authorization")
    assert first_token, "登录响应缺少 Authorization 头"
    second = await _login(client)
    assert second.status_code == 200
    second_token = second.headers.get("authorization")
    assert second_token and second_token != first_token
    sessions = await AuthenticationSession.filter(deleted=False, disabled=False).all()
    assert len(sessions) == 2, f"应有两个活跃会话，实际 {len(sessions)}"

    # 会话二（cookie jar 中的当前会话）执行改密
    response = await client.post(
        "/auth/change-password",
        headers=_csrf_header(client),
        json={"current_password": ADMIN_PASSWORD, "new_password": NEW_PASSWORD,
              "confirm_password": NEW_PASSWORD},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["data"]["token_rotated"] is True, "应声明已轮换 token"

    # 全部旧会话作废，只剩轮换出的一个新会话
    remaining = await AuthenticationSession.filter(deleted=False, disabled=False).all()
    assert len(remaining) == 1, f"改密后应只剩轮换出的新会话，实际 {len(remaining)}"

    # 新会话可用（响应已重新下发 cookie + Authorization）
    new_token = response.headers.get("authorization")
    assert new_token, "改密响应应下发新会话令牌"
    client.cookies.clear()
    ok = await client.get("/api/v1/roles", headers={"Authorization": new_token})
    assert ok.status_code == 200, f"轮换出的新会话应可用：{ok.status_code}"

    # 正向对照：改密前的两个旧令牌都已作废 → 401
    for label, token in (("会话一", first_token), ("会话二", second_token)):
        old = await client.get("/api/v1/roles", headers={"Authorization": token})
        assert old.status_code == 401, (
            f"{label}的令牌应已作废，实际 {old.status_code}")


async def test_change_password_rejects_mismatched_confirm(client):
    """confirm_password 与 new_password 不一致 → 400。"""
    await _login(client)
    response = await client.post(
        "/auth/change-password",
        headers=_csrf_header(client),
        json={"current_password": ADMIN_PASSWORD, "new_password": NEW_PASSWORD, "confirm_password": "Different123!"},
    )
    assert response.status_code == 400, response.text


async def test_change_password_rejects_same_as_current(client):
    """新口令等于当前口令 → 400。"""
    await _login(client)
    response = await client.post(
        "/auth/change-password",
        headers=_csrf_header(client),
        json={"current_password": ADMIN_PASSWORD, "new_password": ADMIN_PASSWORD, "confirm_password": ADMIN_PASSWORD},
    )
    assert response.status_code == 400, response.text


async def test_change_password_requires_minimum_length(client):
    """新口令低于 8 位下限 → 400（与注册/登录同一长度策略）。"""
    await _login(client)
    response = await client.post(
        "/auth/change-password",
        headers=_csrf_header(client),
        json={"current_password": ADMIN_PASSWORD, "new_password": "short1!", "confirm_password": "short1!"},
    )
    assert response.status_code == 400, response.text


async def test_change_password_requires_session(client):
    """未登录调用 change-password → 401（无会话）。"""
    response = await client.post(
        "/auth/change-password",
        json={"current_password": ADMIN_PASSWORD, "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD},
    )
    assert response.status_code in (401, 403), response.status_code


async def test_blocked_paths_cover_post_trailing_slash_query_associated(client):
    """强制改密拦截覆盖：写方法（POST 带合法 CSRF）、尾斜杠、query 串与 /auth/associated。

    均使用路由真实注册的方法（/api/v1/roles 为 GET/POST，/auth/associated 为 POST），
    避免方法不匹配时 405 路径恰好也被中间件拦成 403 的假阳性；
    正向对照：标志为 False 时同样的请求不返回 403。
    """
    from app.models import Account as _A

    # 正向对照：标志 False 时 POST /auth/associated → 200
    await _login(client)
    control = await client.post("/auth/associated", headers=_csrf_header(client))
    assert control.status_code == 200, (control.status_code, control.text)

    await _A.filter(email=ADMIN_EMAIL).update(must_change_password=True)
    await _login(client)

    post = await client.post(
        "/api/v1/roles",
        headers=_csrf_header(client),
        json={"name": "mcp_probe_role", "description": "probe", "permissions": {}},
    )
    assert post.status_code == 403, f"POST 被漏拦：{post.status_code}"
    assert post.json()["error"] == "PASSWORD_CHANGE_REQUIRED", post.text

    trailing = await client.get("/api/v1/roles/")
    assert trailing.status_code == 403, f"尾斜杠被漏拦：{trailing.status_code}"

    query = await client.get("/api/v1/roles?page=1")
    assert query.status_code == 403, f"query 串被漏拦：{query.status_code}"

    associated = await client.post("/auth/associated", headers=_csrf_header(client))
    assert associated.status_code == 403, (
        f"/auth/associated 被漏拦（fail-closed 不得漏会话信息端点）：{associated.status_code}"
    )


async def test_normal_users_not_affected(client):
    """普通账户（非初始管理员）must_change_password=False，API 正常可用。"""
    other = Account(
        username="mcp_normal",
        email="mcp.normal@test.local",
        verified=True,
        disabled=False,
        is_admin=True,
    )
    other.set_password("OtherPass123!")
    await other.save()

    response = await client.post("/auth/login", json={"email": "mcp.normal@test.local", "password": "OtherPass123!"})
    assert response.status_code == 200
    assert response.json()["data"]["must_change_password"] is False

    roles = await client.get("/api/v1/roles")
    assert roles.status_code == 200, f"普通账户（标志 False）不应被强制改密拦截：{roles.status_code}"
    assert "PASSWORD_CHANGE_REQUIRED" not in roles.text

    # 反向：普通账户标志被置 True 时同样被拦（拦截不看 is_admin）
    from app.models import Account as _A

    await _A.filter(email="mcp.normal@test.local").update(must_change_password=True)
    relogin = await client.post("/auth/login", json={"email": "mcp.normal@test.local", "password": "OtherPass123!"})
    assert relogin.status_code == 200
    blocked = await client.get("/api/v1/roles")
    assert blocked.status_code == 403
    assert blocked.json()["error"] == "PASSWORD_CHANGE_REQUIRED", "普通用户标志 True 时也必须被拦，且 error 字段正确"


async def _login_with_2fa(client, monkeypatch):
    """开启 REQUIRE_TWO_FACTOR 登录；返回登录响应。"""
    from app.config import settings

    monkeypatch.setattr(settings, "REQUIRE_TWO_FACTOR", True, raising=False)
    return await _login(client)


async def test_login_with_two_factor_enabled(client, monkeypatch):
    """REQUIRE_TWO_FACTOR=True 时登录不 500，响应体为 {code, must_change_password}。"""
    from app.models import Account as _A

    response = await _login_with_2fa(client, monkeypatch)
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["must_change_password"] is False
    # 测试环境 DEBUG=True：验证码随响应下发
    assert isinstance(data["code"], str) and data["code"], data

    await _A.filter(email=ADMIN_EMAIL).update(must_change_password=True)
    flagged = await _login(client)
    assert flagged.status_code == 200, flagged.text
    assert flagged.json()["data"]["must_change_password"] is True


async def test_flagged_user_can_complete_two_factor(client, monkeypatch):
    """标志 True + 2FA：/auth/validate-2fa 不被强制改密拦截，完成后可改密。"""
    from app.models import Account as _A

    await _A.filter(email=ADMIN_EMAIL).update(must_change_password=True)
    login = await _login_with_2fa(client, monkeypatch)
    assert login.status_code == 200, login.text
    code = login.json()["data"]["code"]

    # 2FA 未完成：强制改密中间件以显式 priority 先于 /api 蓝图中间件执行，
    # 因此稳定返回 403 PASSWORD_CHANGE_REQUIRED（不会是蓝图中间件的 401）
    pending = await client.get("/api/v1/roles")
    assert pending.status_code == 403, pending.status_code
    assert pending.json()["error"] == "PASSWORD_CHANGE_REQUIRED"

    verify = await client.post("/auth/validate-2fa", headers=_csrf_header(client), json={"code": code})
    assert verify.status_code == 200, (verify.status_code, verify.text)
    assert verify.json()["data"]["must_change_password"] is True

    # 正向对照：2FA 已完成、尚未改密 → /api/ 确定被强制改密拦截
    blocked = await client.get("/api/v1/roles")
    assert blocked.status_code == 403, blocked.status_code
    assert blocked.json()["error"] == "PASSWORD_CHANGE_REQUIRED"

    change = await client.post(
        "/auth/change-password",
        headers=_csrf_header(client),
        json={"current_password": ADMIN_PASSWORD, "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD},
    )
    assert change.status_code == 200, change.text


async def test_two_factor_paths_exempt_with_boundary():
    """/auth/validate-2fa 放行，且按边界匹配（同前缀的其它路径仍拦）。

    /two-step 已从白名单移除（无对应业务路由参与强制改密流程）。
    """
    from types import SimpleNamespace

    import pytest

    from app.middleware.auth_middleware import enforce_password_change
    from app.services.exceptions import PasswordChangeRequiredError

    def _req(path):
        bearer = SimpleNamespace(must_change_password=True)
        session = SimpleNamespace(bearer=bearer)
        return SimpleNamespace(path=path, ctx=SimpleNamespace(authentication_session=session))

    assert await enforce_password_change(_req("/auth/validate-2fa")) is None
    for path in ("/auth/validate-2fax", "/two-step", "/two-step/request", "/api/v1/roles"):
        with pytest.raises(PasswordChangeRequiredError):
            await enforce_password_change(_req(path))


async def test_password_check_runs_before_api_blueprint_middleware(app):
    """/api 路由的最终请求中间件链里，强制改密（应用级，高 priority）总在蓝图鉴权之前。"""
    from app.middleware import AUTH_MIDDLEWARE_PRIORITY
    from app.middleware.auth_middleware import AuthMiddleware

    routes = [r for r in app.router.routes if r.path.startswith("api/v1/")]
    assert routes, "未找到 /api/v1 路由"
    checked = 0
    for route in routes:
        chain = list(route.extra.request_middleware)
        auth_idx = [i for i, m in enumerate(chain) if isinstance(m.func, AuthMiddleware)]
        api_idx = [i for i, m in enumerate(chain) if getattr(m.func, "__name__", "") == "_require_api_authentication"]
        assert auth_idx, route.path  # 应用级中间件对所有路由生效
        assert chain[auth_idx[0]].priority == AUTH_MIDDLEWARE_PRIORITY
        if not api_idx:  # 部分路由不在 api_bp 组内，无蓝图鉴权中间件
            continue
        checked += 1
        assert auth_idx[0] < api_idx[0], (route.path, auth_idx, api_idx)
    # 正向对照：确实有路由同时带两个中间件，否则上面的比较是空转
    assert checked > 0


async def test_change_password_requires_completed_two_factor(client, monkeypatch):
    """账户开 2FA：未完成二次验证时 /auth/change-password 403；完成后 200。"""
    from app.models import Account as _A

    await _A.filter(email=ADMIN_EMAIL).update(must_change_password=True)
    login = await _login_with_2fa(client, monkeypatch)
    assert login.status_code == 200, login.text
    code = login.json()["data"]["code"]
    payload = {"current_password": ADMIN_PASSWORD, "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD}

    # 反向：2FA 未完成 → 403 TWO_FACTOR_REQUIRED，口令与标志均不变
    denied = await client.post("/auth/change-password", headers=_csrf_header(client), json=payload)
    assert denied.status_code == 403, (denied.status_code, denied.text)
    assert denied.json()["error"] == "TWO_FACTOR_REQUIRED"
    account = await _A.get(email=ADMIN_EMAIL)
    assert account.must_change_password is True
    assert account.verify_password(ADMIN_PASSWORD)

    # 正向：完成 2FA 后同一请求成功
    verify = await client.post("/auth/validate-2fa", headers=_csrf_header(client), json={"code": code})
    assert verify.status_code == 200, verify.text
    ok = await client.post("/auth/change-password", headers=_csrf_header(client), json=payload)
    assert ok.status_code == 200, (ok.status_code, ok.text)
    account = await _A.get(email=ADMIN_EMAIL)
    assert account.must_change_password is False
    assert account.verify_password(NEW_PASSWORD)


# ---------------------------------------------------------------------------
# SA-v034-L1：审计日志 / 口令强度 / 拒绝清单 / 当前口令限速
# ---------------------------------------------------------------------------

async def _audit_rows(operation=None):
    from app.models import OperationLog

    q = OperationLog.all()
    if operation:
        q = q.filter(operation=operation)
    return await q.order_by("id").all()


async def test_audit_login_success_and_failure(client):
    """登录成功与失败各写一条审计；字段中不含口令。"""
    ok = await _login(client)
    assert ok.status_code == 200
    rows = await _audit_rows("login_success")
    assert rows, "登录成功应写入审计"
    assert rows[-1].operation_type == "auth"
    assert rows[-1].status == "success"

    bad = await client.post("/auth/login", json={"email": ADMIN_EMAIL,
                                                 "password": "WrongPass!2026"})
    assert bad.status_code == 401
    fails = await _audit_rows("login_failure")
    assert fails, "登录失败应写入审计"
    assert fails[-1].status == "failure"

    # 敏感值不得出现在任何字段里
    for row in rows + fails:
        blob = " ".join(str(v) for v in
                        (row.detail, row.account_name, row.user_agent, row.operation))
        for secret in (ADMIN_PASSWORD, "WrongPass!2026"):
            assert secret not in blob, f"审计里出现了口令: {blob!r}"


async def test_audit_logout(client):
    """登出写一条审计。"""
    await _login(client)
    resp = await client.post("/auth/logout", headers=_csrf_header(client))
    assert resp.status_code == 200
    rows = await _audit_rows("logout")
    assert rows, "登出应写入审计"


async def test_audit_change_password_success(client):
    """改密成功写一条审计，且不含新旧口令。"""
    from app.models import Account

    await Account.filter(email=ADMIN_EMAIL).update(must_change_password=True)
    await _login(client)
    resp = await client.post(
        "/auth/change-password", headers=_csrf_header(client),
        json={"current_password": ADMIN_PASSWORD, "new_password": NEW_PASSWORD,
              "confirm_password": NEW_PASSWORD})
    assert resp.status_code == 200, resp.text
    rows = await _audit_rows("change_password_success")
    assert rows, "改密成功应写入审计"
    for row in rows:
        blob = " ".join(str(v) for v in (row.detail, row.operation, row.account_name))
        for secret in (ADMIN_PASSWORD, NEW_PASSWORD):
            assert secret not in blob, f"审计里出现了口令: {blob!r}"


async def test_audit_change_password_failure(client):
    """当前口令错误写一条失败审计，且不含口令。"""
    from app.models import Account

    await Account.filter(email=ADMIN_EMAIL).update(must_change_password=True)
    await _login(client)
    resp = await client.post(
        "/auth/change-password", headers=_csrf_header(client),
        json={"current_password": "WrongCurrent!1", "new_password": NEW_PASSWORD,
              "confirm_password": NEW_PASSWORD})
    assert resp.status_code == 401
    rows = await _audit_rows("change_password_failure")
    assert rows, "改密失败应写入审计"
    for row in rows:
        assert "WrongCurrent!1" not in str(row.detail)


async def test_password_strength_requires_two_classes():
    """新口令必须含至少两类字符（纯数字/纯小写 均拒绝）。"""
    from app.auth.authentication import validate_password_strength

    assert validate_password_strength("alllowercase") is not None
    assert validate_password_strength("12345678") is not None
    assert validate_password_strength("lower1234") is None
    assert validate_password_strength("Lower1234") is None


async def test_password_rejects_banned_and_email():
    """拒绝系统已知弱口令与等于邮箱的口令。"""
    from app.auth.authentication import validate_not_banlisted

    class _Acct:
        email = "someone@example.com"

    assert validate_not_banlisted("SAdmin@123", _Acct()) is not None
    assert validate_not_banlisted("someone@example.com", _Acct()) is not None
    assert validate_not_banlisted("TotallyFine#2026", _Acct()) is None


async def test_change_password_rejects_weak_and_banned(client):
    """端到端：弱口令与已知弱口令都被拒。"""
    from app.models import Account

    await Account.filter(email=ADMIN_EMAIL).update(must_change_password=True)
    await _login(client)
    for weak in ("alllowercase", "SAdmin@123"):
        resp = await client.post(
            "/auth/change-password", headers=_csrf_header(client),
            json={"current_password": ADMIN_PASSWORD, "new_password": weak,
                  "confirm_password": weak})
        assert resp.status_code == 400, f"{weak!r} 应被拒绝，实际 {resp.status_code}"


async def test_change_password_current_password_rate_limited(client):
    """当前口令连续试错达阈值后返回 429。"""
    from app.models import Account

    await Account.filter(email=ADMIN_EMAIL).update(must_change_password=True)
    await _login(client)

    codes = []
    for _ in range(8):
        resp = await client.post(
            "/auth/change-password", headers=_csrf_header(client),
            json={"current_password": "WrongCurrent!1", "new_password": NEW_PASSWORD,
                  "confirm_password": NEW_PASSWORD})
        codes.append(resp.status_code)
        if resp.status_code == 429:
            break
    assert 429 in codes, f"应在阈值内出现 429，实际序列 {codes}"
