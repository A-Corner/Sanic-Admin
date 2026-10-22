#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
缓存基类模块，定义缓存接口
"""

from abc import ABC, abstractmethod
from typing import Any, Optional, List, Dict, Union, Tuple
import time


class CacheBackend(ABC):
    """
    缓存后端抽象基类
    
    定义缓存操作的接口
    """
    
    @abstractmethod
    def get(self, key: str) -> Any:
        """
        获取缓存值
        
        Args:
            key: 缓存键
            
        Returns:
            Any: 缓存值，如果不存在则返回None
        """
        pass
    
    @abstractmethod
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
        pass
    
    @abstractmethod
    def delete(self, key: str) -> bool:
        """
        删除缓存值
        
        Args:
            key: 缓存键
            
        Returns:
            bool: 操作是否成功
        """
        pass
    
    @abstractmethod
    def exists(self, key: str) -> bool:
        """
        检查缓存键是否存在
        
        Args:
            key: 缓存键
            
        Returns:
            bool: 缓存键是否存在
        """
        pass
    
    @abstractmethod
    def expire(self, key: str, timeout: int) -> bool:
        """
        设置缓存过期时间
        
        Args:
            key: 缓存键
            timeout: 过期时间（秒）
            
        Returns:
            bool: 操作是否成功
        """
        pass
    
    @abstractmethod
    def ttl(self, key: str) -> int:
        """
        获取缓存键的剩余生存时间
        
        Args:
            key: 缓存键
            
        Returns:
            int: 剩余生存时间（秒），-1表示永不过期，-2表示缓存键不存在
        """
        pass
    
    @abstractmethod
    def keys(self, pattern: str) -> List[str]:
        """
        获取匹配模式的所有缓存键
        
        Args:
            pattern: 匹配模式
            
        Returns:
            List[str]: 匹配的缓存键列表
        """
        pass
    
    @abstractmethod
    def clear(self) -> bool:
        """
        清除所有缓存
        
        Returns:
            bool: 操作是否成功
        """
        pass
    
    @abstractmethod
    def increment(self, key: str, delta: int = 1) -> int:
        """
        增加缓存值
        
        Args:
            key: 缓存键
            delta: 增加的值
            
        Returns:
            int: 操作后的值
        """
        pass
    
    @abstractmethod
    def decrement(self, key: str, delta: int = 1) -> int:
        """
        减少缓存值
        
        Args:
            key: 缓存键
            delta: 减少的值
            
        Returns:
            int: 操作后的值
        """
        pass
    
    @abstractmethod
    def get_many(self, keys: List[str]) -> Dict[str, Any]:
        """
        获取多个缓存值
        
        Args:
            keys: 缓存键列表
            
        Returns:
            Dict[str, Any]: 缓存键值对字典
        """
        pass
    
    @abstractmethod
    def set_many(self, mapping: Dict[str, Any], timeout: Optional[int] = None) -> bool:
        """
        设置多个缓存值
        
        Args:
            mapping: 缓存键值对字典
            timeout: 过期时间（秒），如果为None则永不过期
            
        Returns:
            bool: 操作是否成功
        """
        pass
    
    @abstractmethod
    def delete_many(self, keys: List[str]) -> int:
        """
        删除多个缓存值
        
        Args:
            keys: 缓存键列表
            
        Returns:
            int: 成功删除的键数量
        """
        pass
    
    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """
        获取缓存统计信息
        
        Returns:
            Dict[str, Any]: 缓存统计信息
        """
        pass
    
    def get_or_set(self, key: str, default_func: callable, timeout: Optional[int] = None) -> Any:
        """
        获取缓存值，如果不存在则设置
        
        Args:
            key: 缓存键
            default_func: 默认值获取函数
            timeout: 过期时间（秒）
            
        Returns:
            Any: 缓存值
        """
        value = self.get(key)
        if value is None:
            value = default_func()
            self.set(key, value, timeout)
        return value 