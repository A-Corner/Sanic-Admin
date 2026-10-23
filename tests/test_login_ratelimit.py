#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
登录限流测试：**账户**与**来源 IP** 两个独立维度的失败滑动窗口。

规则（v0.3 P2 + F1 修复，常量见 app/config.py）：
* 窗口内（默认 900 秒）任一维度失败达上限（默认 5 次）后，一律 429，
  即使第 N+1 次提交的是正确口令；
* 成功登录清零两个维度的计数；
* X-Forwarded-For 默认**不采信**（可被客户端伪造，F1）：IP 维度恒用 socket
  直连对端；仅当 TRUSTED_PROXIES 声明了直连对端时才解析 XFF。

测试通道说明：经 ASGI client 的直连对端恒为 127.0.0.1，无法直接模拟不同来源
IP——IP 维度的隔离用例在 TRUSTED_PROXIES 门控开启后经 XFF 驱动；默认配置下的
F1 回归（轮换 XFF 绕过）则证明 XFF 不再影响计数。
"""

import asyncio
import time

from app.auth.rate_limit import LoginRateLimiter
from app.cache.memory import MemoryCache
from app.models import Account

ADMIN_EMAIL = "SAdmin@Sanic.com"
ADMIN_PASSWORD = "TestAdminPass123!"

IP_A = "203.0.113.10"
IP_B = "203.0.113.20"


async def _login(client, email: str, password: str, xff: str = None):
    """提交登录；xff 仅在 TRUSTED_PROXIES 门控开启时才影响 IP 维度。"""
    headers = {"X-Forwarded-For": xff} if xff else {}
    return await client.post(
        "/auth/login",
        json={"email": email, "password": password},
        headers=headers,
    )


def _enable_trusted_proxies(app):
    """测试内开启可信代理门控（直连对端 127.0.0.1 视为可信，XFF 生效）。"""
    app.config["TRUSTED_PROXIES"] = "127.0.0.1"


async def _make_user(username: str, email: str, password: str) -> None:
    """造一个已验证的普通账户（测试专用）。"""
    account = Account(
        username=username, email=email, verified=True, disabled=False, is_admin=False
    )
    account.set_password(password)
    await account.save()


class _StubRequest:
    """最小 request stub：仅供限流器单元测试提取来源与 XFF。"""

    def __init__(self, remote_addr="127.0.0.1", xff=None):
        self.remote_addr = remote_addr
        self.client_ip = remote_addr
        self.headers = {"X-Forwarded-For": xff} if xff else {}


async def test_threshold_failures_block_even_correct_password(client):
    """连败 5 次后第 6 次即使口令正确也 429（账户维度触顶）。"""
    for _ in range(5):
        response = await _login(client, ADMIN_EMAIL, "WrongPassword123!")
        assert response.status_code == 401, response.text

    blocked = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    assert blocked.status_code == 429, blocked.text
    body = blocked.json()
    assert body["success"] is False
    assert body["error"] == "RATE_LIMIT_EXCEEDED"

    # 第 7 次仍然 429（窗口未滑动出去之前持续拦截）
    still_blocked = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    assert still_blocked.status_code == 429, still_blocked.text


async def test_success_below_threshold_resets_counter(client):
    """未达阈值时正确口令正常登录，且清零失败计数。"""
    for _ in range(4):
        assert (await _login(client, ADMIN_EMAIL, "WrongPassword123!")).status_code == 401

    ok = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    assert ok.status_code == 200, ok.text

    # 计数已清零：再败 5 次（而非 1 次）才应再次触发拦截
    for _ in range(5):
        assert (await _login(client, ADMIN_EMAIL, "WrongPassword123!")).status_code == 401
    blocked = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    assert blocked.status_code == 429, blocked.text


async def test_success_clears_both_dimensions(client, app):
    """成功登录清零两个维度：清零后计数从 0 重新起算。

    注意：acct 键一旦触顶，任何来源的成功登录都会先被 raise_if_blocked 拦下
    （防爆破设计意图：锁定期内不能靠"正确口令"解锁），所以本用例用 4 次失败
    （未触顶）验证清零语义。
    """
    _enable_trusted_proxies(app)
    for _ in range(4):
        await _login(client, ADMIN_EMAIL, "WrongPassword123!", xff=IP_A)
    # 未触顶：换来源（IP_B）成功登录 → acct 与 ip(IP_B) 两键清零/归零
    ok = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD, xff=IP_B)
    assert ok.status_code == 200, ok.text

    # 清零后 acct 从 0 起算：再败 5 次（而非 1 次）才触顶
    for _ in range(5):
        await _login(client, ADMIN_EMAIL, "WrongPassword123!", xff=IP_B)
    assert (await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD, xff=IP_B)).status_code == 429


async def test_ip_dimension_isolated_under_trusted_proxies(client, app):
    """门控开启时 IP 维度独立计数：同 IP 换标识受 ip 键影响，不同 IP 互不影响。"""
    _enable_trusted_proxies(app)
    other_email = "rl.other@example.com"
    await _make_user("rl_other", other_email, "OtherPass123!")

    # (admin, IP_A) 与 (other, IP_A) 各自失败 3 次 —— ip(IP_A) 共计 6 次 > 5
    for _ in range(3):
        await _login(client, ADMIN_EMAIL, "WrongPassword123!", xff=IP_A)
    for _ in range(3):
        await _login(client, other_email, "WrongPassword123!", xff=IP_A)

    # 两个账户各自 acct 键只有 3 次，但共享的 ip(IP_A) 键已触顶 → 双双 429
    assert (await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD, xff=IP_A)).status_code == 429
    assert (await _login(client, other_email, "OtherPass123!", xff=IP_A)).status_code == 429

    # 换来源 IP（IP_B）：ip 键独立，acct 键也未触顶 → 正常
    ok = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD, xff=IP_B)
    assert ok.status_code == 200, ok.text


async def test_xff_rotation_cannot_bypass_account_lock(client):
    """F1 回归：默认配置下轮换 XFF **不能**绕过账户维度锁定。

    修复前：联合键 identity:ip 掺入无门控采信的 XFF，攻击者逐请求轮换
    XFF 即可让键每次都新，同账户爆破防护实际为零（连败 8 次无一 429）。
    修复后：acct 键不掺 IP，轮换 XFF 照样触顶。
    """
    for i in range(5):
        response = await _login(client, ADMIN_EMAIL, "WrongPassword123!",
                                xff=f"203.0.113.{100 + i}")
        assert response.status_code == 401, response.text

    # 第 6 次：再换一个 XFF + 正确口令 —— 仍必须 429
    blocked = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD, xff="203.0.113.200")
    assert blocked.status_code == 429, (
        f"轮换 XFF 绕过了账户锁定（{blocked.status_code}）—— F1 回归"
    )


async def test_xff_ignored_by_default_even_single_ip(client):
    """默认配置下 XFF 完全不参与计数：伪造 XFF 不会影响其他来源的 ip 键。"""
    # 直连（无 XFF）失败 3 次
    for _ in range(3):
        await _login(client, ADMIN_EMAIL, "WrongPassword123!")

    # 带 5 个不同伪造 XFF 的失败——若 XFF 被采信，ip 键会被分散、
    # 直连 ip(127.0.0.1) 键永远到不了上限
    for i in range(5):
        await _login(client, ADMIN_EMAIL, "WrongPassword123!", xff=f"198.51.100.{i}")

    # 第 9 次失败（直连 ip 键 = 3+5 = 8 次 > 5）：因为 XFF 未采信，
    # 全部落在同一个 ip(127.0.0.1) 键上 → 触顶 429
    blocked = await _login(client, ADMIN_EMAIL, "WrongPassword123!")
    assert blocked.status_code == 429, (
        "XFF 被采信导致 ip 键分散——默认配置必须忽略 XFF（F1）"
    )


async def test_trusted_proxies_enables_xff_and_rightmost_untrusted_wins(client, app):
    """TRUSTED_PROXIES 门控：直连可信时采信 XFF，从右往左取第一个非可信地址。"""
    _enable_trusted_proxies(app)

    # XFF 链右起第一个是可信代理 10.0.0.1，跳过后取 IP_A 为来源
    chain = f"{IP_A},10.0.0.1"
    for _ in range(4):
        await _login(client, ADMIN_EMAIL, "WrongPassword123!", xff=chain)
    # 未触顶：换 IP_B 成功登录（若 ip 键误按整个 XFF 链或 remote 计，本断言会失败）
    ok = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD, xff=IP_B)
    assert ok.status_code == 200, ok.text

    # 清零后再对 ip(IP_A) 键独立打满：4(已清) + 5 = 触顶
    for _ in range(5):
        await _login(client, ADMIN_EMAIL, "WrongPassword123!", xff=chain)
    blocked = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD, xff=chain)
    assert blocked.status_code == 429, blocked.text
    # ip(IP_B) 键独立，未触顶 → 正常
    ok_b = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD, xff=IP_B)
    assert ok_b.status_code == 200, ok_b.text


class _JsonRoundTripCache:
    """
    模拟 RedisCache 序列化语义的最小 cache 实现（get/set/delete + JSON 往返）。

    LoginRateLimiter 只依赖这三个原语；redis 后端会把列表值经 JSON 序列化往返
    （app/cache/redis.py _serialize/_deserialize），这里复刻该行为作为正向对照，
    证明限流器不依赖 memory 后端的对象引用特性。
    """

    def __init__(self):
        import json

        self._data = {}
        self._json = json

    def get(self, key):
        raw = self._data.get(key)
        return self._json.loads(raw) if raw is not None else None

    def set(self, key, value, timeout=None):
        self._data[key] = self._json.dumps(value)
        return True

    def delete(self, key):
        return self._data.pop(key, None) is not None


def test_limiter_contract_with_redis_shaped_backend():
    """限流器逻辑在"redis 形状"的后端（值经 JSON 序列化往返）上行为一致。"""
    limiter = LoginRateLimiter(
        cache=_JsonRoundTripCache(), max_attempts=5, window_seconds=900
    )
    stub = _StubRequest(remote_addr="1.2.3.4")

    async def _drive():
        for _ in range(5):
            await limiter.record_failure("a@b.c", stub)
        blocked = False
        try:
            await limiter.raise_if_blocked("a@b.c", stub)
        except Exception as exc:
            blocked = getattr(exc, "error_code", "") == "RATE_LIMIT_EXCEEDED"
        await limiter.clear("a@b.c", stub)
        cleared = True
        try:
            await limiter.raise_if_blocked("a@b.c", stub)
        except Exception:
            cleared = False
        return blocked, cleared

    blocked, cleared = asyncio.run(_drive())
    assert blocked, "5 次失败后应触发 RATE_LIMIT_EXCEEDED"
    assert cleared, "clear 之后应解除拦截"


def test_window_prunes_old_failures():
    """窗口外的旧失败不计入（滑动窗口语义）。"""
    async def _drive():
        cache = MemoryCache()
        limiter = LoginRateLimiter(cache=cache, max_attempts=5, window_seconds=1)
        stub = _StubRequest(remote_addr="9.9.9.9")
        for _ in range(5):
            await limiter.record_failure("u@x.y", stub)
        # 把记录改成"刚好滑出窗口"的旧时间戳，验证惰性裁剪（acct 与 ip 两键都改）
        stale = [time.time() - 2] * 5
        cache.set("login_rl_acct:u@x.y", stale, timeout=900)
        cache.set("login_rl_ip:9.9.9.9", stale, timeout=900)
        try:
            await limiter.raise_if_blocked("u@x.y", stub)
            return False
        except Exception as exc:
            return getattr(exc, "error_code", "") == "RATE_LIMIT_EXCEEDED"

    assert asyncio.run(_drive()) is False, "窗口外旧失败不应触发拦截"
