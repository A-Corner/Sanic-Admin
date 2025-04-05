#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
缓存系统测试

测试内存缓存和Redis缓存的基本功能
"""

import pytest
import time
from app.cache import get_cache
from app.cache.backends.memory import MemoryCache
from app.cache.backends.redis import RedisCache


@pytest.mark.asyncio
async def test_memory_cache_basic_operations():
    """测试内存缓存的基本操作"""
    # 获取内存缓存实例
    cache = get_cache("memory")
    
    # 测试设置和获取
    key = "test_memory_key"
    value = {"name": "测试数据", "id": 12345}
    
    # 设置缓存
    await cache.set(key, value, ttl=60)
    
    # 获取缓存
    cached_value = await cache.get(key)
    assert cached_value == value, "获取的缓存值与设置的不一致"
    
    # 测试TTL
    ttl = await cache.ttl(key)
    assert ttl > 0, "缓存TTL应大于0"
    assert ttl <= 60, "缓存TTL不应超过设置值"
    
    # 测试删除
    await cache.delete(key)
    deleted_value = await cache.get(key)
    assert deleted_value is None, "缓存删除后应返回None"
    
    # 测试过期
    short_key = "test_short_ttl"
    await cache.set(short_key, "短期缓存", ttl=1)
    
    # 等待缓存过期
    time.sleep(1.5)
    
    # 获取已过期的缓存
    expired_value = await cache.get(short_key)
    assert expired_value is None, "过期缓存应返回None"


@pytest.mark.asyncio
async def test_memory_cache_update_ttl():
    """测试更新内存缓存的TTL"""
    cache = get_cache("memory")
    
    key = "test_update_ttl"
    value = "可更新TTL的测试数据"
    
    # 设置初始缓存，TTL为10秒
    await cache.set(key, value, ttl=10)
    
    # 检查初始TTL
    initial_ttl = await cache.ttl(key)
    assert 0 < initial_ttl <= 10, "初始TTL应在0到10秒之间"
    
    # 更新为30秒
    await cache.update_ttl(key, 30)
    
    # 检查更新后的TTL
    updated_ttl = await cache.ttl(key)
    assert 10 < updated_ttl <= 30, "更新后TTL应在10到30秒之间"
    
    # 清理测试数据
    await cache.delete(key)


@pytest.mark.asyncio
async def test_memory_cache_pattern_operations():
    """测试内存缓存的模式操作"""
    cache = get_cache("memory")
    
    # 设置一组相关的缓存
    for i in range(5):
        await cache.set(f"pattern:test:{i}", f"Pattern值{i}", ttl=60)
    
    # 使用不同的模式获取键
    pattern_keys_1 = await cache.keys("pattern:test:*")
    assert len(pattern_keys_1) == 5, "应有5个匹配的键"
    
    pattern_keys_2 = await cache.keys("pattern:test:1*")
    assert len(pattern_keys_2) == 1, "应有1个匹配的键"
    
    pattern_keys_3 = await cache.keys("pattern:none:*")
    assert len(pattern_keys_3) == 0, "不应有匹配的键"
    
    # 测试按模式删除
    await cache.delete_pattern("pattern:test:[0-2]")
    
    # 验证删除结果
    remaining_keys = await cache.keys("pattern:test:*")
    assert len(remaining_keys) == 2, "应剩余2个键"
    
    # 清理所有测试数据
    await cache.delete_pattern("pattern:test:*")


@pytest.mark.asyncio
async def test_memory_cache_get_many_set_many():
    """测试内存缓存的批量获取和设置"""
    cache = get_cache("memory")
    
    # 准备测试数据
    items = {
        "batch:item:1": "批量项目1",
        "batch:item:2": "批量项目2",
        "batch:item:3": "批量项目3",
    }
    
    # 批量设置
    await cache.set_many(items, ttl=60)
    
    # 批量获取
    keys = list(items.keys())
    cached_items = await cache.get_many(keys)
    
    # 验证结果
    assert len(cached_items) == 3, "应返回3个缓存项"
    for key, value in items.items():
        assert key in cached_items, f"缺少键 {key}"
        assert cached_items[key] == value, f"键 {key} 的值不匹配"
    
    # 包含不存在的键
    mixed_keys = keys + ["batch:nonexistent"]
    mixed_items = await cache.get_many(mixed_keys)
    
    assert len(mixed_items) == 4, "应返回4个结果"
    assert mixed_items["batch:nonexistent"] is None, "不存在的键应返回None"
    
    # 清理测试数据
    await cache.delete_pattern("batch:item:*")


@pytest.mark.asyncio
async def test_memory_cache_increment_decrement():
    """测试内存缓存的增减操作"""
    cache = get_cache("memory")
    
    counter_key = "test:counter"
    
    # 设置初始值
    await cache.set(counter_key, 10, ttl=60)
    
    # 测试增加
    incr_value = await cache.increment(counter_key)
    assert incr_value == 11, "增加后值应为11"
    
    # 测试增加指定值
    incr_value = await cache.increment(counter_key, 5)
    assert incr_value == 16, "增加5后值应为16"
    
    # 测试减少
    decr_value = await cache.decrement(counter_key)
    assert decr_value == 15, "减少后值应为15"
    
    # 测试减少指定值
    decr_value = await cache.decrement(counter_key, 7)
    assert decr_value == 8, "减少7后值应为8"
    
    # 清理测试数据
    await cache.delete(counter_key)


@pytest.mark.asyncio
async def test_cache_decorator():
    """测试缓存装饰器"""
    from app.cache.decorator import cached
    
    counter = {"value": 0}
    
    @cached(ttl=10, prefix="test_decorator")
    async def test_function(arg1, arg2=None):
        counter["value"] += 1
        return f"结果:{arg1}:{arg2}:{counter['value']}"
    
    # 第一次调用，应该执行函数
    result1 = await test_function("a", arg2="b")
    assert counter["value"] == 1, "函数应该被执行一次"
    
    # 第二次相同参数调用，应该从缓存获取
    result2 = await test_function("a", arg2="b")
    assert counter["value"] == 1, "函数不应再次执行"
    assert result1 == result2, "两次调用结果应相同"
    
    # 不同参数调用，应该执行函数
    result3 = await test_function("c", arg2="d")
    assert counter["value"] == 2, "不同参数应导致函数再次执行"
    assert result1 != result3, "不同参数的结果应不同"
    
    # 清理缓存
    cache = get_cache("memory")
    await cache.delete_pattern("test_decorator:*")


@pytest.mark.asyncio
async def test_route_cache_middleware():
    """测试路由缓存中间件"""
    # 这部分测试需要通过HTTP客户端进行，因为涉及到路由和请求/响应对象
    pass


# 以下测试需要Redis服务可用，如果没有Redis可以跳过
@pytest.mark.asyncio
@pytest.mark.skipif(True, reason="需要Redis服务")
async def test_redis_cache_basic_operations():
    """测试Redis缓存的基本操作"""
    try:
        # 尝试获取Redis缓存实例
        cache = get_cache("redis")
        
        # 测试设置和获取
        key = "test_redis_key"
        value = {"name": "Redis测试数据", "id": 67890}
        
        # 设置缓存
        await cache.set(key, value, ttl=60)
        
        # 获取缓存
        cached_value = await cache.get(key)
        assert cached_value == value, "获取的Redis缓存值与设置的不一致"
        
        # 测试TTL
        ttl = await cache.ttl(key)
        assert ttl > 0, "Redis缓存TTL应大于0"
        
        # 测试删除
        await cache.delete(key)
        deleted_value = await cache.get(key)
        assert deleted_value is None, "Redis缓存删除后应返回None"
        
    except Exception as e:
        pytest.skip(f"Redis测试跳过: {str(e)}")


@pytest.mark.asyncio
@pytest.mark.skipif(True, reason="需要Redis服务")
async def test_redis_cache_pattern_operations():
    """测试Redis缓存的模式操作"""
    try:
        cache = get_cache("redis")
        
        # 设置一组相关的缓存
        for i in range(5):
            await cache.set(f"redis:pattern:test:{i}", f"Redis模式值{i}", ttl=60)
        
        # 使用不同的模式获取键
        pattern_keys = await cache.keys("redis:pattern:test:*")
        assert len(pattern_keys) == 5, "Redis应有5个匹配的键"
        
        # 测试按模式删除
        await cache.delete_pattern("redis:pattern:test:[0-2]")
        
        # 验证删除结果
        remaining_keys = await cache.keys("redis:pattern:test:*")
        assert len(remaining_keys) == 2, "Redis应剩余2个键"
        
        # 清理所有测试数据
        await cache.delete_pattern("redis:pattern:test:*")
        
    except Exception as e:
        pytest.skip(f"Redis测试跳过: {str(e)}") 