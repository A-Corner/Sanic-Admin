#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
登录限流：按**账户**与**来源 IP**两个独立维度限制登录失败次数（OWASP 建议：
双维度独立计数，任一超限即拒绝——单一联合键会被伪造 XFF 逐请求绕过，见
EVT-20261023-007-REVIEW F1）。

滑动窗口的近似实现（sliding log）：每个键在 cache 里保存窗口内的失败时间戳列表，
每次失败先裁掉窗口外的旧记录再追加；key 的 TTL 每次写都刷新为窗口时长，整个 key
在最后一次失败满窗口后自然消失。只用 cache 层的 get/set/delete 三个原语，
memory 与 redis 两种后端语义一致（列表值在 redis 侧经 JSON 序列化往返）。

只统计**凭据错误**（CredentialsError）：账户未验证/禁用、参数缺失等失败不计入，
避免锁定机制被用来放大对正常用户的拒绝服务。

IP 维度的可信代理门控：X-Forwarded-For 可被客户端任意伪造，**默认不采信**——
恒用 socket 直连对端（``request.remote_addr``）。仅当部署方在 ``TRUSTED_PROXIES``
里声明了反向代理（直连对端命中列表）时，才从 XFF 链从右往左取第一个非可信地址。
"""

import ipaddress
import time
from typing import List, Optional

from sanic.request import Request

from app.services.utils import get_request_value

#: cache 键前缀。实际 redis 键还会叠加全局 CACHE_KEY_PREFIX。
KEY_PREFIX = "login_rl"

#: 两个独立计数维度的键前缀。
ACCOUNT_KEY_PREFIX = "login_rl_acct"
IP_KEY_PREFIX = "login_rl_ip"


class LoginRateLimiter:
    """基于 cache 层的登录失败滑动窗口限流器（账户 / IP 双维度独立计数）。"""

    def __init__(self, cache, max_attempts: int, window_seconds: int,
                 trusted_proxies: Optional[List[str]] = None):
        self.cache = cache
        self.max_attempts = max(max_attempts, 1)
        self.window_seconds = max(window_seconds, 1)
        self.trusted_proxies = [str(p).strip() for p in (trusted_proxies or []) if str(p).strip()]

    @classmethod
    def from_request(cls, request: Request) -> "LoginRateLimiter":
        """按应用配置构建限流器；cache 取 app.ctx.cache（before_server_start 已初始化）。"""
        cfg = request.app.config
        raw_proxies = cfg.get("TRUSTED_PROXIES", "") or ""
        return cls(
            cache=request.app.ctx.cache,
            max_attempts=int(cfg.get("LOGIN_RATELIMIT_MAX_ATTEMPTS", 5)),
            window_seconds=int(cfg.get("LOGIN_RATELIMIT_WINDOW_SECONDS", 900)),
            trusted_proxies=[p for p in raw_proxies.split(",") if p.strip()],
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

    # ------------------------------------------------------------------
    # IP 提取（含可信代理门控）
    # ------------------------------------------------------------------

    def _addr_trusted(self, addr: str) -> bool:
        """直连对端是否在 TRUSTED_PROXIES 里（支持单 IP 与 CIDR 网段）。"""
        try:
            parsed = ipaddress.ip_address(addr)
        except ValueError:
            return False
        for entry in self.trusted_proxies:
            try:
                if "/" in entry:
                    if parsed in ipaddress.ip_network(entry, strict=False):
                        return True
                elif parsed == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue
        return False

    def _client_ip(self, request: Request) -> str:
        """
        限流维度的来源 IP。

        默认恒用 socket 直连对端（不可伪造）。仅当直连对端命中 TRUSTED_PROXIES
        时才解析 X-Forwarded-For：从链的**右侧**向左跳过可信代理，取第一个非可信
        地址——攻击者可以往 XFF 左侧任意追加假地址，但无法篡改代理追加的真实来源。
        直连对端不可信或 XFF 缺失时一律回退直连对端。
        """
        # client_ip：Sanic 按 PROXIES 配置解析的 socket 对端（项目未配 PROXIES_COUNT，
        # 即 scope 直连对端，不可伪造）；23.6 的 ASGI 下 remote_addr 返回空串，
        # client_ip 才有值，故优先取它。
        remote = request.client_ip or request.remote_addr or "unknown"
        if not self.trusted_proxies or not self._addr_trusted(remote):
            return remote
        xff = request.headers.get("X-Forwarded-For")
        if not xff:
            return remote
        candidates = [seg.strip() for seg in xff.split(",") if seg.strip()]
        for seg in reversed(candidates):
            if not self._addr_trusted(seg):
                return seg
        return remote

    def _keys(self, identity: str, request: Request) -> List[str]:
        """两个独立计数键：账户维度（不掺 IP）恒在；IP 维度仅有来源时存在。"""
        keys = []
        if identity:
            keys.append(f"{ACCOUNT_KEY_PREFIX}:{identity}")
        keys.append(f"{IP_KEY_PREFIX}:{self._client_ip(request)}")
        return keys

    def _recent_failures(self, key: str) -> list:
        """读出窗口内的失败时间戳（裁掉已滑出窗口的旧记录，惰性清理）。"""
        value = self.cache.get(key)
        if not value:
            return []
        cutoff = time.time() - self.window_seconds
        return [ts for ts in value if ts > cutoff]

    # ------------------------------------------------------------------
    # 公共接口（routes.py 调用）：以 request 为参，键的推导在限流器内部
    # ------------------------------------------------------------------

    async def raise_if_blocked(self, identity: str, request: Request) -> None:
        """
        任一维度已达失败上限时抛出 429（即使本次口令正确也拒绝）。

        Raises:
            RateLimitExceededError: 窗口内失败次数已达上限
        """
        from app.services.exceptions import RateLimitExceededError

        for key in self._keys(identity, request):
            if len(self._recent_failures(key)) >= self.max_attempts:
                raise RateLimitExceededError(
                    f"登录失败次数过多，请约 {max(self.window_seconds // 60, 1)} 分钟后再试"
                )

    async def record_failure(self, identity: str, request: Request) -> None:
        """记录一次登录失败（两个维度各自累加；TTL 随最后一次失败刷新）。"""
        now = time.time()
        for key in self._keys(identity, request):
            failures = self._recent_failures(key)
            failures.append(now)
            # 裁剪后保留全量窗口记录，让 TTL 到期前窗口自然滑动。
            self.cache.set(key, failures, timeout=self.window_seconds)

    async def clear(self, identity: str, request: Request) -> None:
        """登录成功后清零两个维度的失败计数。"""
        for key in self._keys(identity, request):
            self.cache.delete(key)
