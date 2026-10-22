#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
缓存模块，提供Redis缓存和本地内存缓存支持

``get_cache()`` 按配置（``CACHE_TYPE``）返回进程内单例：
* ``memory``：内存缓存；
* ``redis``：Redis 缓存；Redis 不可达（连接被拒/超时）时记录 warning 并降级为内存缓存，
  不会挂起。production 环境则拒绝降级，抛出 ConfigError。
"""

import logging
from typing import Dict, Optional

from app.cache.base import CacheBackend
from app.cache.memory import MemoryCache
from app.cache.redis import RedisCache

logger = logging.getLogger("sanic.error")

# 按请求的缓存类型保存已解析的实例（redis 降级后同样记录，避免每次调用重复探测 Redis）
_instances: Dict[str, CacheBackend] = {}

# Redis 探测的连接/读写超时（秒），保证无 Redis 时快速失败而非挂起
_REDIS_PROBE_TIMEOUT = 2


def _default_cache_type() -> str:
    try:
        from app.config import config
        return str(getattr(config, "CACHE_TYPE", "memory") or "memory").lower()
    except Exception:  # 配置不可用时退回内存缓存
        return "memory"


def _is_production() -> bool:
    try:
        from app.config import config
        return str(getattr(config, "ENV", "")).lower() == "production"
    except ImportError:
        return False


def _get_memory() -> CacheBackend:
    cache = _instances.get("memory")
    if cache is None:
        cache = _instances["memory"] = MemoryCache()
    return cache


def _build_redis() -> CacheBackend:
    """创建并探测 Redis 缓存；失败时降级为内存缓存。"""
    try:
        cache = RedisCache(socket_connect_timeout=_REDIS_PROBE_TIMEOUT)
        cache._redis.ping()
        return cache
    except Exception as exc:  # noqa: BLE001 - redis.RedisError / OSError / 配置缺失均降级
        if _is_production():
            from app.config import ConfigError
            raise ConfigError(f"production 环境 Redis 缓存不可用，拒绝降级启动: {exc!r}") from exc
        logger.warning(f"[降级] Redis 缓存不可用，改用内存缓存: {exc!r}")
        return _get_memory()


def get_cache(cache_type: Optional[str] = None) -> CacheBackend:
    """
    获取缓存实例（进程内单例）

    Args:
        cache_type: 缓存类型，可选值: "redis", "memory"；为 None 时取配置 ``CACHE_TYPE``

    Returns:
        CacheBackend: 缓存后端实例（redis 不可用时为内存缓存）
    """
    cache_type = (cache_type or _default_cache_type()).lower()
    if cache_type not in ("redis", "memory"):
        raise ValueError(f"不支持的缓存类型: {cache_type!r}，可选 'redis' / 'memory'")

    cache = _instances.get(cache_type)
    if cache is None:
        cache = _build_redis() if cache_type == "redis" else _get_memory()
        _instances[cache_type] = cache
    return cache


__all__ = [
    'CacheBackend',
    'RedisCache',
    'MemoryCache',
    'get_cache'
]
