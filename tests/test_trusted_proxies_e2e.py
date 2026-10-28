#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
``TRUSTED_PROXIES`` 的端到端接线：环境变量 → 配置 → Sanic app → 限流键。

为什么这个文件独立存在（EVT-20261028-023-REVIEW finding 4）
==========================================================
``tests/test_trusted_proxies_config.py`` 只验证「env → ``get_config()`` 对象
属性」这一步。审核席指出这**止步于最后一公里之前**：

    环境变量 → get_config() 属性 → **Sanic app.config** → LoginRateLimiter → 限流键

中间两步（`config_to_dict` → `app.config.update`）若存在属性白名单、类型转换、
或任何静默丢弃，修复就会**「配了但不生效」而没有任何测试能发现**。

``tests/test_login_ratelimit.py`` 的 XFF 门控用例也没覆盖这条路径——它们用
``_enable_trusted_proxies(app)`` **直接写** ``app.config["TRUSTED_PROXIES"]``，
跳过了环境变量与 ``get_config`` 两段。

本文件补上被跳过的那段：**设真实环境变量 → 真实构造配置 → 真实创建 app →
真实发 HTTP 请求**，断言限流最终用的是正确的客户端 IP。

不 mock 任何东西
================
不断言 ``_client_ip`` 的返回值（那等于用被测对象证明自己），而是**看限流的
外部可观测行为**：某个 IP 的失败计数是否独立累计。具体做法是让两个不同的
伪造 XFF 各自触顶，再验证它们的计数互不影响——只有真的按 XFF 分桶才会这样。
"""

import os

import pytest


#: 代理自身地址（ASGI 测试通道的直连对端恒为 127.0.0.1，见 conftest.client）
PROXY_IP = "127.0.0.1"

#: 两个「真实客户端」IP，经 XFF 传入。
CLIENT_A = "203.0.113.10"
CLIENT_B = "203.0.113.20"

ADMIN_EMAIL = "SAdmin@Sanic.com"
ADMIN_PASSWORD = "TestAdminPass123!"
WRONG_PASSWORD = "WrongPassword123!"

#: 限流触顶阈值（app/config.py 的 LOGIN_RATELIMIT_MAX_ATTEMPTS 默认值）
MAX_ATTEMPTS = 5


@pytest.fixture()
def env_trusted_proxies(monkeypatch):
    """
    把 ``TRUSTED_PROXIES`` 设成**真实环境变量**，并在测试结束后还原。

    这是本文件与 ``test_login_ratelimit.py`` 的关键区别：那些用例直接写
    ``app.config[...]``，绕过了「环境变量被读到配置对象」这一段。
    """
    monkeypatch.setenv("TRUSTED_PROXIES", PROXY_IP)
    yield PROXY_IP


@pytest.fixture()
async def e2e_app(env_trusted_proxies, tmp_path):
    """
    用**真实 env var 路径**构造的应用实例。

    与 conftest 的 ``app`` 夹具的区别：``_build_config`` 里的
    ``config_to_dict(get_config("testing"))`` 现在会读到
    ``monkeypatch.setenv`` 设下的 ``TRUSTED_PROXIES``，因此走完了
    「环境变量 → 配置对象 → app.config」全链。

    其余部分（独立 sqlite、上传目录、内存缓存）沿用 conftest 的做法。
    """
    import asyncio

    from sanic import Sanic

    from app import create_app
    from app.config import config_to_dict, get_config
    from app.models import Account, Tortoise

    # 与 conftest 保持一致：注册表里只留当前一个应用
    for name in list(Sanic._app_registry):
        Sanic._app_registry.pop(name, None)

    db_path = tmp_path / "e2e.sqlite3"
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)

    cfg = config_to_dict(get_config("testing"))
    cfg.update(
        {
            "TESTING": True,
            "DEBUG": True,
            "ENV": "testing",
            "DATABASE_URL": f"sqlite://{db_path}",
            "UPLOAD_DIR": str(upload_dir),
            "UPLOAD_FOLDER": str(upload_dir),
            "CACHE_TYPE": "memory",
            "USE_CACHE": True,
            "ROUTE_CACHE_ENABLED": False,
            "ENABLE_API_DOCS": True,
            "SESSION_COOKIE_SECURE": False,
        }
    )

    application = create_app(cfg)
    application.asgi = True
    await application._startup()
    loop = asyncio.get_running_loop()
    await application._server_event("init", "before", loop)
    await application._server_event("init", "after", loop)

    await Account.filter(email=os.environ["INITIAL_ADMIN_EMAIL"]).update(
        must_change_password=False
    )

    try:
        yield application
    finally:
        await application._server_event("shutdown", "before", loop)
        await application._server_event("shutdown", "after", loop)
        await Tortoise.close_connections()
        for name in list(Sanic._app_registry):
            Sanic._app_registry.pop(name, None)


@pytest.fixture()
async def e2e_client(e2e_app):
    """ASGI 客户端；直连对端固定 127.0.0.1（即 PROXY_IP）。"""
    import httpx

    transport = httpx.ASGITransport(app=e2e_app, client=(PROXY_IP, 54321))
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver", follow_redirects=True
    ) as client:
        yield client


async def _make_user(username: str, email: str, password: str) -> None:
    """造一个已验证的普通账户（与 test_login_ratelimit.py 同构）。"""
    from app.models import Account

    account = Account(
        username=username, email=email, verified=True, disabled=False, is_admin=False
    )
    account.set_password(password)
    await account.save()


async def _login(client, xff, email=ADMIN_EMAIL, password=WRONG_PASSWORD):
    """带 XFF 打一次登录。"""
    headers = {"X-Forwarded-For": xff} if xff else {}
    return await client.post(
        "/auth/login", json={"email": email, "password": password}, headers=headers
    )


def test_env_var_reaches_app_config(e2e_app):
    """
    第一段断言：环境变量确实走到了 ``app.config``。

    这段单独存在，是因为后面两个用例测的是「行为」，一旦它们红了很难区分
    是「配置没传到」还是「限流逻辑坏了」。这一步把两者分开。
    """
    assert e2e_app.config.get("TRUSTED_PROXIES") == PROXY_IP, (
        "环境变量没有走到 Sanic app.config——"
        f"实际 {e2e_app.config.get('TRUSTED_PROXIES')!r}。"
        "说明 config_to_dict / app.config.update 之间有环节丢弃了该键。"
    )


async def test_xff_client_ip_drives_rate_limit_key(e2e_client, e2e_app):
    """
    端到端：门控开启后，**限流按 XFF 里的客户端 IP 分桶**。

    做法：让 CLIENT_A 把 admin 账户失败到触顶，再验证 CLIENT_B 用**另一个账户**
    不受影响。如果限流还是按 socket 直连对端（代理 IP）计数，A 触顶时 B 也会
    429——那正是本项要修的缺陷（全站共用一个桶）。

    为什么 B 必须换账户（这是第一版写错的地方）
    ==========================================
    限流是**账户 + IP 双维度独立计数**，任一触顶即拒绝（OWASP 建议）。用同一个
    admin 账户时，A 失败 5 次已经把 **acct 键**也打满，此时换 IP 照样 429 ——
    那个 429 来自账户维度，与 IP 分桶无关，测不出任何东西。

    第一版就是这样写的，结果把「账户维度正常工作」误报成「IP 分桶失效」。
    换账户后，acct 维度清零，剩下的唯一差异就是 IP 键是否共用。
    """
    other_email = "e2e.other@example.com"
    await _make_user("e2e_other", other_email, "OtherPass123!")

    for _ in range(MAX_ATTEMPTS):
        resp = await _login(e2e_client, CLIENT_A)
        assert resp.status_code == 401, (
            f"失败登录应返回 401，实际 {resp.status_code}: {resp.text}"
        )

    # A 已触顶：A 的 ip 键与 admin 的 acct 键都满了
    blocked_a = await _login(e2e_client, CLIENT_A)
    assert blocked_a.status_code == 429, (
        f"CLIENT_A 失败 {MAX_ATTEMPTS} 次后应 429，实际 {blocked_a.status_code}"
    )

    # 关键断言：CLIENT_B + 另一个账户，两个维度都是全新的，不该被 A 影响。
    # 若看到 429，说明与 A 共用了一个 IP 桶（缺陷复现）。
    resp_b = await _login(e2e_client, CLIENT_B, email=other_email, password="OtherPass123!")
    assert resp_b.status_code in (200, 401), (
        "CLIENT_B 用的是全新账户 + 全新 IP，两个维度都未触顶，却被限流——"
        "说明它与 CLIENT_A 共用了一个 IP 桶，即限流没有按 XFF 里的客户端 IP 分桶，"
        f"TRUSTED_PROXIES 未真正生效。实际 {resp_b.status_code}: {resp_b.text}"
    )


async def test_empty_xff_falls_back_to_socket_peer(e2e_client):
    """
    不带 XFF 时回退到 socket 直连对端。

    回退是 fail-safe 方向：拿不到可信的客户端 IP 时，宁可把所有人算成同一个
    来源，也不能采信一个可能被伪造的值。
    """
    for _ in range(MAX_ATTEMPTS):
        resp = await _login(e2e_client, xff=None)
        assert resp.status_code == 401, resp.text

    blocked = await _login(e2e_client, xff=None)
    assert blocked.status_code == 429, (
        f"无 XFF 时第 {MAX_ATTEMPTS + 1} 次应 429（回退到直连对端计数），"
        f"实际 {blocked.status_code}"
    )
