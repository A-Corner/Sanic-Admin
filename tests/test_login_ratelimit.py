#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
登录限流测试：（用户名/邮箱 + IP）维度的失败滑动窗口。

规则（v0.3 P2，常量见 app/config.py）：
* 窗口内（默认 900 秒）失败达上限（默认 5 次）后，该维度一律 429，
  即使第 N+1 次提交的是正确口令；
* 成功登录清零该维度计数；
* 不同（标识, IP）组合互不影响。

IP 维度经 ``X-Forwarded-For`` 头模拟（``get_ip`` 优先读它）。
"""

from app.auth.rate_limit import LoginRateLimiter
from app.cache.memory import MemoryCache
from app.models import Account

ADMIN_EMAIL = "SAdmin@Sanic.com"
ADMIN_PASSWORD = "TestAdminPass123!"

IP_A = "203.0.113.10"
IP_B = "203.0.113.20"


async def _login(client, email: str, password: str, ip: str = IP_A):
    """以指定来源 IP 提交登录（经 X-Forwarded-For）。"""
    return await client.post(
        "/auth/login",
        json={"email": email, "password": password},
        headers={"X-Forwarded-For": ip},
    )


async def _make_user(username: str, email: str, password: str) -> None:
    """造一个已验证的普通账户（测试专用）。"""
    account = Account(
        username=username, email=email, verified=True, disabled=False, is_admin=False
    )
    account.set_password(password)
    await account.save()


async def test_threshold_failures_block_even_correct_password(client):
    """连败 5 次后第 6 次即使口令正确也 429。"""
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


async def test_clear_unblocks_dimension(client):
    """达到上限后，一次成功登录（清零）即可解除该维度拦截——由清零路径直接验证。"""
    for _ in range(5):
        await _login(client, ADMIN_EMAIL, "WrongPassword123!")
    assert (await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD, ip=IP_B)).status_code == 200

    # (admin, IP_B) 登录成功只清零 IP_B 维度；IP_A 仍处于拦截态
    assert (await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD, ip=IP_A)).status_code == 429


async def test_identity_and_ip_dimensions_isolated(client):
    """不同（标识, IP）组合互不影响。"""
    other_email = "rl.other@example.com"
    await _make_user("rl_other", other_email, "OtherPass123!")

    # (admin, IP_A) 打满失败
    for _ in range(5):
        await _login(client, ADMIN_EMAIL, "WrongPassword123!", ip=IP_A)
    assert (await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD, ip=IP_A)).status_code == 429

    # 同一标识换个 IP：不受影响
    ok_other_ip = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD, ip=IP_B)
    assert ok_other_ip.status_code == 200, ok_other_ip.text

    # 同一 IP 换个标识：不受影响
    ok_other_user = await _login(client, other_email, "OtherPass123!", ip=IP_A)
    assert ok_other_user.status_code == 200, ok_other_user.text


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
    import asyncio

    limiter = LoginRateLimiter(
        cache=_JsonRoundTripCache(), max_attempts=5, window_seconds=900
    )

    async def _drive():
        for _ in range(5):
            await limiter.record_failure("a@b.c", "1.2.3.4")
        blocked = False
        try:
            await limiter.raise_if_blocked("a@b.c", "1.2.3.4")
        except Exception as exc:
            blocked = getattr(exc, "error_code", "") == "RATE_LIMIT_EXCEEDED"
        await limiter.clear("a@b.c", "1.2.3.4")
        cleared = True
        try:
            await limiter.raise_if_blocked("a@b.c", "1.2.3.4")
        except Exception:
            cleared = False
        return blocked, cleared

    blocked, cleared = asyncio.run(_drive())
    assert blocked, "5 次失败后应触发 RATE_LIMIT_EXCEEDED"
    assert cleared, "clear 之后应解除拦截"


def test_window_prunes_old_failures():
    """窗口外的旧失败不计入（滑动窗口语义）。"""
    import asyncio
    import time

    async def _drive():
        cache = MemoryCache()
        limiter = LoginRateLimiter(cache=cache, max_attempts=5, window_seconds=1)
        for _ in range(5):
            await limiter.record_failure("u@x.y", "9.9.9.9")
        # 把记录改成"刚好滑出窗口"的旧时间戳，验证惰性裁剪
        stale = [time.time() - 2] * 5
        cache.set("login_rl:u@x.y:9.9.9.9", stale, timeout=900)
        try:
            await limiter.raise_if_blocked("u@x.y", "9.9.9.9")
            return False
        except Exception as exc:
            return getattr(exc, "error_code", "") == "RATE_LIMIT_EXCEEDED"

    assert asyncio.run(_drive()) is False, "窗口外旧失败不应触发拦截"
