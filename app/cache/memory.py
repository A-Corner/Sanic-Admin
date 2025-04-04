#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
内存缓存实现模块
"""

import time
import threading
from typing import Any, Optional, List, Dict, Union, Tuple
import copy

from app.cache.base import CacheBackend


class MemoryCache(CacheBackend):
    """
    内存缓存实现
    
    使用Python字典实现的简单内存缓存
    """
    
    def __init__(self):
        """
        初始化内存缓存
        """
        self._cache = {}  # 存储键值对
        self._expires = {}  # 存储过期时间
        self._lock = threading.RLock()  # 线程锁，保证线程安全
        
    def get(self, key: str) -> Any:
        """
        获取缓存值
        
        Args:
            key: 缓存键
            
        Returns:
            Any: 缓存值，如果不存在或已过期则返回None
        """
        with self._lock:
            if key not in self._cache:
                return None
                
            # 检查是否过期
            if key in self._expires and self._expires[key] < time.time():
                self.delete(key)
                return None
                
            # 深拷贝防止外部修改缓存值
            return copy.deepcopy(self._cache[key])
            
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
        with self._lock:
            # 深拷贝防止外部修改影响缓存值
            self._cache[key] = copy.deepcopy(value)
            
            # 设置过期时间
            if timeout is not None:
                self._expires[key] = time.time() + timeout
            elif key in self._expires:
                # 如果之前设置了过期时间，现在不设置，则删除过期时间
                del self._expires[key]
                
            return True
            
    def delete(self, key: str) -> bool:
        """
        删除缓存值
        
        Args:
            key: 缓存键
            
        Returns:
            bool: 操作是否成功
        """
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                if key in self._expires:
                    del self._expires[key]
                return True
            return False
            
    def exists(self, key: str) -> bool:
        """
        检查缓存键是否存在
        
        Args:
            key: 缓存键
            
        Returns:
            bool: 缓存键是否存在且未过期
        """
        with self._lock:
            if key not in self._cache:
                return False
                
            # 检查是否过期
            if key in self._expires and self._expires[key] < time.time():
                self.delete(key)
                return False
                
            return True
            
    def expire(self, key: str, timeout: int) -> bool:
        """
        设置缓存过期时间
        
        Args:
            key: 缓存键
            timeout: 过期时间（秒）
            
        Returns:
            bool: 操作是否成功
        """
        with self._lock:
            if key not in self._cache:
                return False
                
            self._expires[key] = time.time() + timeout
            return True
            
    def ttl(self, key: str) -> int:
        """
        获取缓存键的剩余生存时间
        
        Args:
            key: 缓存键
            
        Returns:
            int: 剩余生存时间（秒），-1表示永不过期，-2表示缓存键不存在或已过期
        """
        with self._lock:
            if key not in self._cache:
                return -2
                
            # 检查是否过期
            if key in self._expires:
                ttl = self._expires[key] - time.time()
                if ttl < 0:
                    self.delete(key)
                    return -2
                return int(ttl)
                
            return -1  # 永不过期
            
    def keys(self, pattern: str = "*") -> List[str]:
        """
        获取匹配模式的所有缓存键
        
        Args:
            pattern: 匹配模式，支持简单的通配符：* 和 ?
            
        Returns:
            List[str]: 匹配的缓存键列表
        """
        import fnmatch
        
        with self._lock:
            result = []
            # 先清理过期的键
            self._clean_expired()
            
            # 进行模式匹配
            for key in self._cache.keys():
                if fnmatch.fnmatch(key, pattern):
                    result.append(key)
                    
            return result
            
    def clear(self) -> bool:
        """
        清除所有缓存
        
        Returns:
            bool: 操作是否成功
        """
        with self._lock:
            self._cache.clear()
            self._expires.clear()
            return True
            
    def increment(self, key: str, delta: int = 1) -> int:
        """
        增加缓存值
        
        Args:
            key: 缓存键
            delta: 增加的值
            
        Returns:
            int: 操作后的值，如果键不存在或值不是整数则返回None
        """
        with self._lock:
            if not self.exists(key):
                self.set(key, delta)
                return delta
                
            try:
                value = self.get(key) + delta
                self.set(key, value)
                return value
            except (TypeError, ValueError):
                return None
                
    def decrement(self, key: str, delta: int = 1) -> int:
        """
        减少缓存值
        
        Args:
            key: 缓存键
            delta: 减少的值
            
        Returns:
            int: 操作后的值，如果键不存在或值不是整数则返回None
        """
        return self.increment(key, -delta)
            
    def get_many(self, keys: List[str]) -> Dict[str, Any]:
        """
        获取多个缓存值
        
        Args:
            keys: 缓存键列表
            
        Returns:
            Dict[str, Any]: 缓存键值对字典，只包含存在的键
        """
        result = {}
        for key in keys:
            value = self.get(key)
            if value is not None:
                result[key] = value
        return result
            
    def set_many(self, mapping: Dict[str, Any], timeout: Optional[int] = None) -> bool:
        """
        设置多个缓存值
        
        Args:
            mapping: 缓存键值对字典
            timeout: 过期时间（秒），如果为None则永不过期
            
        Returns:
            bool: 操作是否全部成功
        """
        for key, value in mapping.items():
            self.set(key, value, timeout)
        return True
            
    def delete_many(self, keys: List[str]) -> int:
        """
        删除多个缓存值
        
        Args:
            keys: 缓存键列表
            
        Returns:
            int: 成功删除的键数量
        """
        count = 0
        for key in keys:
            if self.delete(key):
                count += 1
        return count
            
    def get_stats(self) -> Dict[str, Any]:
        """
        获取缓存统计信息
        
        Returns:
            Dict[str, Any]: 缓存统计信息
        """
        with self._lock:
            # 清理过期键
            self._clean_expired()
            
            return {
                'hits': 0,  # 内存缓存没有命中率统计
                'misses': 0,
                'keys': len(self._cache),
                'expires': len(self._expires),
                'memory_usage': self._estimate_memory_usage()
            }
            
    def _clean_expired(self) -> None:
        """
        清理所有过期的键
        """
        now = time.time()
        expired_keys = [k for k, v in self._expires.items() if v < now]
        for key in expired_keys:
            self.delete(key)
            
    def _estimate_memory_usage(self) -> int:
        """
        估计内存使用量（字节）
        
        Returns:
            int: 估计的内存使用量
        """
        import sys
        
        # 简单估计，可能不准确
        usage = sys.getsizeof(self._cache) + sys.getsizeof(self._expires)
        
        # 估计所有键和值的大小
        for key, value in self._cache.items():
            usage += sys.getsizeof(key) + sys.getsizeof(value)
            
        for key, value in self._expires.items():
            usage += sys.getsizeof(key) + sys.getsizeof(value)
            
        return usage 