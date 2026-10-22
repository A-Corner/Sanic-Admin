#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
登录限流：按（提交的用户名/邮箱 + 来源 IP）维度限制登录失败次数。

滑动窗口的近似实现（sliding log）：每个维度在 cache 里保存窗口内的失败时间戳列表，
每次失败先裁掉窗口外的旧记录再追加；key 的 TTL 每次写都刷新为窗口时长，整个 key
在最后一次失败满窗口后自然消失。只用 cache 层的 get/set/delete 三个原语，
memory 与 redis 两种后端语义一致（列表值在 redis 侧经 JSON 序列化往返）。

只统计**凭据错误**（CredentialsError）：账户未验证/禁用、参数缺失等失败不计入，
避免锁定机制被用来放大对正常用户的拒绝服务。
"""

import time
from typing import Optional

from sanic.request import Request

from app.services.utils import get_ip, get_request_value

#: cache 键前缀。实际 redis 键还会叠加全局 CACHE_KEY_PREFIX。
KEY_PREFIX = "login_rl"


class LoginRateLimiter:
    """基于 cache 层的登录失败滑动窗口限流器。"""

    def __init__(self, cache, max_attempts: int, window_seconds: int):
        self.cache = cache
        self.max_attempts = max(max_attempts, 1)
        self.window_seconds = max(window_seconds, 1)

    @classmethod
    def from_request(cls, request: Request) -> "LoginRateLimiter":
        """按应用配置构建限流器；cache 取 app.ctx.cache（before_server_start 已初始化）。"""
        cfg = request.app.config
        return cls(
            cache=request.app.ctx.cache,
            max_attempts=int(cfg.get("LOGIN_RATELIMIT_MAX_ATTEMPTS", 5)),
            window_seconds=int(cfg.get("LOGIN_RATELIMIT_WINDOW_SECONDS", 900)),
        )

    @staticmethod
    def submitted_identity(request: Request) -> Optional[str]:
        """
        取请求提交的登录标识（邮箱优先，其次用户名），小写归一。

        缺失时返回 None（参数校验会以 400 拒绝，无需计数）。
        """
        email = get_request_value(request, "email")
        username = get_request_value(request, "username")
        raw = email or username
        if raw is None:
            return None
        return str(raw).strip().lower() or None

    def _key(self, identity: str, ip: str) -> str:
        return f"{KEY_PREFIX}:{identity}:{ip}"

    def _recent_failures(self, key: str) -> list:
        """读出窗口内的失败时间戳（裁掉已滑出窗口的旧记录，惰性清理）。"""
        value = self.cache.get(key)
        if not value:
            return []
        cutoff = time.time() - self.window_seconds
        return [ts for ts in value if ts > cutoff]

    async def raise_if_blocked(self, identity: str, ip: str) -> None:
        """
        已达失败上限时抛出 429（即使本次口令正确也拒绝）。

        Raises:
            RateLimitExceededError: 窗口内失败次数已达上限
        """
        key = self._key(identity, ip)
        if len(self._recent_failures(key)) >= self.max_attempts:
            from app.services.exceptions import RateLimitExceededError

            raise RateLimitExceededError(
                f"登录失败次数过多，请约 {max(self.window_seconds // 60, 1)} 分钟后再试"
            )

    async def record_failure(self, identity: str, ip: str) -> None:
        """记录一次登录失败（窗口滑动；TTL 随最后一次失败刷新）。"""
        key = self._key(identity, ip)
        failures = self._recent_failures(key)
        failures.append(time.time())
        # 裁剪后只保留最近 max_attempts 条即可判断"是否继续加锁"，
        # 但保留全量窗口记录能让 TTL 到期前窗口自然滑动，这里存全量。
        self.cache.set(key, failures, timeout=self.window_seconds)

    async def clear(self, identity: str, ip: str) -> None:
        """登录成功后清零该维度的失败计数。"""
        self.cache.delete(self._key(identity, ip))


def client_ip(request: Request) -> str:
    """限流维度的 IP（复用项目统一的 get_ip，含 XFF/X-Real-IP 解析）。"""
    return get_ip(request)
