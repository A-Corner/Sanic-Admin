#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
缓存模块，提供Redis缓存和本地内存缓存支持
"""

from app.cache.redis_cache import RedisCache
from app.cache.memory_cache import MemoryCache

# 默认使用内存缓存
_default_cache = None


def get_cache(cache_type="memory"):
    """
    获取缓存实例
    
    Args:
        cache_type: 缓存类型，可选值: "redis", "memory"
        
    Returns:
        CacheBackend: 缓存后端实例
    """
    global _default_cache
    
    if cache_type == "redis":
        return RedisCache()
    else:
        if _default_cache is None:
            _default_cache = MemoryCache()
        return _default_cache


__all__ = [
    'RedisCache',
    'MemoryCache',
    'get_cache'
] 