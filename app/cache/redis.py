#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Redis缓存实现模块
"""

import json
from typing import Any, Optional, List, Dict, Union, Tuple

import redis

from app.cache.base import CacheBackend
from app.config import config


class RedisCache(CacheBackend):
    """
    Redis缓存实现
    
    基于Redis的缓存后端
    """
    
    def __init__(self, host=None, port=None, db=None, password=None, socket_timeout=None, **kwargs):
        """
        初始化Redis缓存
        
        Args:
            host: Redis主机地址
            port: Redis端口
            db: Redis数据库
            password: Redis密码
            socket_timeout: Socket超时时间
            **kwargs: 其他Redis连接参数
        """
        # 默认从配置中读取Redis配置
        self.host = host or config.REDIS_HOST
        self.port = port or config.REDIS_PORT
        self.db = db if db is not None else config.REDIS_DB
        self.password = password or config.REDIS_PASSWORD
        self.socket_timeout = socket_timeout or config.REDIS_SOCKET_TIMEOUT
        
        # 额外参数
        self.kwargs = kwargs
        
        # 创建Redis连接
        self._redis = self._create_client()
        
        # 键前缀，用于区分不同应用的缓存
        self.key_prefix = config.CACHE_KEY_PREFIX
        
    def _create_client(self) -> redis.Redis:
        """
        创建Redis客户端
        
        Returns:
            redis.Redis: Redis客户端实例
        """
        return redis.Redis(
            host=self.host,
            port=self.port,
            db=self.db,
            password=self.password,
            socket_timeout=self.socket_timeout,
            decode_responses=True,  # 自动解码响应
            **self.kwargs
        )
        
    def _make_key(self, key: str) -> str:
        """
        生成带前缀的缓存键
        
        Args:
            key: 原始缓存键
            
        Returns:
            str: 带前缀的缓存键
        """
        return f"{self.key_prefix}:{key}" if self.key_prefix else key
        
    def _extract_key(self, prefixed_key: str) -> str:
        """
        从带前缀的键中提取原始键
        
        Args:
            prefixed_key: 带前缀的缓存键
            
        Returns:
            str: 原始缓存键
        """
        if self.key_prefix and prefixed_key.startswith(f"{self.key_prefix}:"):
            return prefixed_key[len(self.key_prefix) + 1:]
        return prefixed_key
        
    def _serialize(self, value: Any) -> str:
        """
        序列化值为字符串
        
        Args:
            value: 任意Python对象
            
        Returns:
            str: 序列化后的字符串
        """
        if value is None:
            return ''
        if isinstance(value, (int, float, str, bool)):
            return str(value)
        return json.dumps(value)
        
    def _deserialize(self, value: str) -> Any:
        """
        反序列化字符串为Python对象
        
        Args:
            value: 序列化后的字符串
            
        Returns:
            Any: 反序列化后的Python对象
        """
        if value is None or value == '':
            return None
            
        try:
            # 尝试解析为JSON
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            # 不是有效的JSON，返回原始值
            # 尝试转换为整数或浮点数
            try:
                if value.isdigit():
                    return int(value)
                if value.replace('.', '', 1).isdigit() and value.count('.') <= 1:
                    return float(value)
            except (ValueError, AttributeError):
                pass
                
            # 处理布尔值
            if value.lower() == 'true':
                return True
            if value.lower() == 'false':
                return False
                
            # 返回原始字符串
            return value
    
    def get(self, key: str) -> Any:
        """
        获取缓存值
        
        Args:
            key: 缓存键
            
        Returns:
            Any: 缓存值，如果不存在则返回None
        """
        prefixed_key = self._make_key(key)
        value = self._redis.get(prefixed_key)
        return self._deserialize(value)
        
    def set(self, key: str, value: Any, timeout: Optional[int] = None) -> bool:
        """
        设置缓存值
        
        Args:
            key: 缓存键
            value: 缓存值
            timeout: 过期时间（秒），如果为None则永不过期
            
        Returns:
            bool: 操作是否成功
        """
        prefixed_key = self._make_key(key)
        serialized = self._serialize(value)
        
        if timeout is not None:
            return bool(self._redis.setex(prefixed_key, timeout, serialized))
        else:
            return bool(self._redis.set(prefixed_key, serialized))
            
    def delete(self, key: str) -> bool:
        """
        删除缓存值
        
        Args:
            key: 缓存键
            
        Returns:
            bool: 操作是否成功
        """
        prefixed_key = self._make_key(key)
        return bool(self._redis.delete(prefixed_key))
        
    def exists(self, key: str) -> bool:
        """
        检查缓存键是否存在
        
        Args:
            key: 缓存键
            
        Returns:
            bool: 缓存键是否存在
        """
        prefixed_key = self._make_key(key)
        return bool(self._redis.exists(prefixed_key))
        
    def expire(self, key: str, timeout: int) -> bool:
        """
        设置缓存过期时间
        
        Args:
            key: 缓存键
            timeout: 过期时间（秒）
            
        Returns:
            bool: 操作是否成功
        """
        prefixed_key = self._make_key(key)
        return bool(self._redis.expire(prefixed_key, timeout))
        
    def ttl(self, key: str) -> int:
        """
        获取缓存键的剩余生存时间
        
        Args:
            key: 缓存键
            
        Returns:
            int: 剩余生存时间（秒），-1表示永不过期，-2表示缓存键不存在
        """
        prefixed_key = self._make_key(key)
        return self._redis.ttl(prefixed_key)
        
    def keys(self, pattern: str = "*") -> List[str]:
        """
        获取匹配模式的所有缓存键
        
        Args:
            pattern: 匹配模式
            
        Returns:
            List[str]: 匹配的缓存键列表
        """
        if self.key_prefix:
            pattern = f"{self.key_prefix}:{pattern}"
            
        keys = self._redis.keys(pattern)
        return [self._extract_key(k) for k in keys]
        
    def clear(self) -> bool:
        """
        清除所有缓存
        
        只清除指定前缀的键，避免清除其他应用的缓存
        
        Returns:
            bool: 操作是否成功
        """
        if self.key_prefix:
            pattern = f"{self.key_prefix}:*"
            keys = self._redis.keys(pattern)
            if keys:
                return bool(self._redis.delete(*keys))
            return True
        else:
            # 如果没有设置前缀，则不允许清除所有缓存
            return False
            
    def increment(self, key: str, delta: int = 1) -> int:
        """
        增加缓存值
        
        Args:
            key: 缓存键
            delta: 增加的值
            
        Returns:
            int: 操作后的值
        """
        prefixed_key = self._make_key(key)
        return self._redis.incrby(prefixed_key, delta)
        
    def decrement(self, key: str, delta: int = 1) -> int:
        """
        减少缓存值
        
        Args:
            key: 缓存键
            delta: 减少的值
            
        Returns:
            int: 操作后的值
        """
        return self.increment(key, -delta)
        
    def get_many(self, keys: List[str]) -> Dict[str, Any]:
        """
        获取多个缓存值
        
        Args:
            keys: 缓存键列表
            
        Returns:
            Dict[str, Any]: 缓存键值对字典
        """
        prefixed_keys = [self._make_key(key) for key in keys]
        values = self._redis.mget(prefixed_keys)
        
        result = {}
        for key, value in zip(keys, values):
            if value is not None:
                result[key] = self._deserialize(value)
                
        return result
        
    def set_many(self, mapping: Dict[str, Any], timeout: Optional[int] = None) -> bool:
        """
        设置多个缓存值
        
        Args:
            mapping: 缓存键值对字典
            timeout: 过期时间（秒），如果为None则永不过期
            
        Returns:
            bool: 操作是否成功
        """
        prefixed_mapping = {
            self._make_key(key): self._serialize(value)
            for key, value in mapping.items()
        }
        
        pipe = self._redis.pipeline()
        pipe.mset(prefixed_mapping)
        
        if timeout is not None:
            for key in prefixed_mapping:
                pipe.expire(key, timeout)
                
        try:
            pipe.execute()
            return True
        except redis.RedisError:
            return False
            
    def delete_many(self, keys: List[str]) -> int:
        """
        删除多个缓存值
        
        Args:
            keys: 缓存键列表
            
        Returns:
            int: 成功删除的键数量
        """
        prefixed_keys = [self._make_key(key) for key in keys]
        return self._redis.delete(*prefixed_keys) if prefixed_keys else 0
        
    def get_stats(self) -> Dict[str, Any]:
        """
        获取缓存统计信息
        
        Returns:
            Dict[str, Any]: 缓存统计信息
        """
        try:
            info = self._redis.info()
            keyspace_info = info.get(f"db{self.db}", {})
            
            # 计算我们的缓存键数量
            our_keys_count = 0
            if self.key_prefix:
                pattern = f"{self.key_prefix}:*"
                our_keys_count = len(self._redis.keys(pattern))
                
            return {
                'hits': info.get('keyspace_hits', 0),
                'misses': info.get('keyspace_misses', 0),
                'keys': keyspace_info.get('keys', 0),
                'our_keys': our_keys_count,
                'expires': keyspace_info.get('expires', 0),
                'memory_usage': info.get('used_memory', 0),
                'connected_clients': info.get('connected_clients', 0),
                'uptime_seconds': info.get('uptime_in_seconds', 0)
            }
        except redis.RedisError:
            return {
                'error': 'Could not retrieve Redis stats'
            }