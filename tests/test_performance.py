#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
性能测试模块

包含基准测试、并发测试和负载测试场景
"""

import pytest
import asyncio
import time
import statistics
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from tests.utils import (
    assert_success_response,
    assert_error_response,
    get_auth_headers,
    create_test_account,
    create_test_system_logs
)


@pytest.mark.asyncio
async def test_api_response_time_benchmark(client, auth_headers):
    """API响应时间基准测试"""
    # 测试端点列表
    endpoints = [
        {"url": "/api/v1/account/me", "method": "get", "auth": True},
        {"url": "/api/v1/admin/accounts", "method": "get", "auth": True},
        {"url": "/api/v1/admin/roles", "method": "get", "auth": True},
        {"url": "/api/v1/admin/settings", "method": "get", "auth": True},
        {"url": "/api/v1/admin/logs", "method": "get", "auth": True},
        {"url": "/api/v1/dashboard/stats", "method": "get", "auth": True},
    ]
    
    # 为每个端点创建足够的测试数据
    await create_test_system_logs(100)
    
    # 每个端点测试次数
    test_iterations = 5
    
    results = {}
    
    for endpoint in endpoints:
        url = endpoint["url"]
        method = endpoint["method"]
        response_times = []
        
        for _ in range(test_iterations):
            start_time = time.time()
            
            if method == "get":
                if endpoint["auth"]:
                    response = await client.get(url, headers=auth_headers)
                else:
                    response = await client.get(url)
            
            # 可以添加其他HTTP方法的支持
            
            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # 转换为毫秒
            response_times.append(response_time)
            
            # 确保请求成功
            assert response.status in (200, 201, 204), f"请求失败: {url} 返回状态码 {response.status}"
            
            # 添加短暂延迟避免请求过于密集
            await asyncio.sleep(0.1)
        
        # 计算统计信息
        avg_time = statistics.mean(response_times)
        min_time = min(response_times)
        max_time = max(response_times)
        median_time = statistics.median(response_times)
        
        results[url] = {
            "avg": avg_time,
            "min": min_time,
            "max": max_time,
            "median": median_time
        }
        
        # 验证性能是否在可接受范围内
        assert avg_time < 500, f"端点 {url} 的平均响应时间超过500毫秒: {avg_time}毫秒"
    
    # 打印性能结果供参考
    print("\n性能基准测试结果:")
    for url, stats in results.items():
        print(f"端点: {url}")
        print(f"  平均响应时间: {stats['avg']:.2f}毫秒")
        print(f"  最小响应时间: {stats['min']:.2f}毫秒")
        print(f"  最大响应时间: {stats['max']:.2f}毫秒")
        print(f"  中位响应时间: {stats['median']:.2f}毫秒")
        print("---")


@pytest.mark.asyncio
async def test_concurrent_api_requests(client, auth_headers):
    """并发API请求测试"""
    # 基本API端点
    url = "/api/v1/admin/accounts"
    
    # 创建一些测试账号
    for i in range(10):
        await create_test_account(
            username=f"concurrent_test_user_{i}",
            password="Test@123456"
        )
    
    # 并发请求数
    concurrent_requests = 10
    
    # 创建一个同步函数来执行HTTP请求，因为asyncio不能在线程池中直接运行
    def make_request():
        # 使用同步版本的客户端，因为异步客户端在线程间不安全
        import httpx
        headers = {"Authorization": auth_headers["Authorization"]}
        full_url = f"http://localhost:8000{url}"  # 使用正确的测试服务器URL
        
        response = httpx.get(full_url, headers=headers)
        return response.status_code, response.elapsed.total_seconds() * 1000  # 返回状态码和响应时间（毫秒）
    
    # 创建并发请求
    with ThreadPoolExecutor(max_workers=concurrent_requests) as executor:
        futures = [executor.submit(make_request) for _ in range(concurrent_requests)]
        results = [future.result() for future in futures]
    
    # 分析结果
    status_codes = [result[0] for result in results]
    response_times = [result[1] for result in results]
    
    # 计算统计信息
    success_count = status_codes.count(200)
    avg_time = statistics.mean(response_times)
    max_time = max(response_times)
    
    # 验证并发处理能力
    assert success_count == concurrent_requests, f"并发请求成功率: {success_count}/{concurrent_requests}"
    assert avg_time < 1000, f"并发情况下平均响应时间过长: {avg_time:.2f}毫秒"
    
    print(f"\n并发测试结果 ({concurrent_requests} 并发请求):")
    print(f"  成功请求: {success_count}/{concurrent_requests}")
    print(f"  平均响应时间: {avg_time:.2f}毫秒")
    print(f"  最大响应时间: {max_time:.2f}毫秒")


@pytest.mark.asyncio
async def test_database_performance(client, auth_headers):
    """数据库性能测试"""
    # 生成大量测试日志数据
    logs_count = 100
    await create_test_system_logs(logs_count)
    
    # 测试复杂查询性能
    search_params = [
        {"keyword": "登录"},
        {"keyword": "更新"},
        {"status": "0"},  # 成功状态
        {"status": "1"},  # 失败状态
        {"keyword": "账户", "status": "0"},
        {"sort": "-created_at"}  # 按时间倒序
    ]
    
    results = {}
    
    for i, params in enumerate(search_params):
        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        url = f"/api/v1/admin/logs?{query_string}"
        
        # 测量查询时间
        start_time = time.time()
        response = await client.get(url, headers=auth_headers)
        end_time = time.time()
        
        query_time = (end_time - start_time) * 1000  # 转换为毫秒
        
        # 验证响应
        data = assert_success_response(response)
        
        # 记录结果
        results[f"查询 {i+1}"] = {
            "params": params,
            "time": query_time,
            "results_count": len(data["data"]["items"])
        }
        
        # 检查性能是否可接受
        assert query_time < 500, f"查询 {params} 的响应时间超过500毫秒: {query_time:.2f}毫秒"
    
    # 打印结果
    print("\n数据库查询性能测试结果:")
    for query_name, stats in results.items():
        print(f"{query_name}:")
        print(f"  参数: {stats['params']}")
        print(f"  响应时间: {stats['time']:.2f}毫秒")
        print(f"  结果数量: {stats['results_count']}")
        print("---")


@pytest.mark.asyncio
async def test_cache_performance(client, auth_headers):
    """缓存性能测试"""
    # 测试带缓存和不带缓存的API性能差异
    
    # 清除可能的现有缓存
    clear_cache_response = await client.delete(
        "/api/v1/admin/cache?type=all",
        headers=auth_headers
    )
    assert_success_response(clear_cache_response)
    
    # 测试的API端点
    url = "/api/v1/dashboard/stats"
    
    # 第一次请求（无缓存）
    start_time_no_cache = time.time()
    first_response = await client.get(url, headers=auth_headers)
    end_time_no_cache = time.time()
    time_no_cache = (end_time_no_cache - start_time_no_cache) * 1000  # 毫秒
    
    # 确保请求成功
    assert_success_response(first_response)
    
    # 短暂等待
    await asyncio.sleep(0.1)
    
    # 第二次请求（应该使用缓存）
    start_time_with_cache = time.time()
    second_response = await client.get(url, headers=auth_headers)
    end_time_with_cache = time.time()
    time_with_cache = (end_time_with_cache - start_time_with_cache) * 1000  # 毫秒
    
    # 确保请求成功
    assert_success_response(second_response)
    
    # 验证缓存生效
    assert time_with_cache < time_no_cache, f"缓存没有提高性能: 无缓存={time_no_cache:.2f}毫秒, 有缓存={time_with_cache:.2f}毫秒"
    
    # 检查性能提升百分比
    improvement = ((time_no_cache - time_with_cache) / time_no_cache) * 100
    
    print("\n缓存性能测试结果:")
    print(f"  无缓存响应时间: {time_no_cache:.2f}毫秒")
    print(f"  有缓存响应时间: {time_with_cache:.2f}毫秒")
    print(f"  性能提升: {improvement:.2f}%")
    
    # 验证显著的性能提升
    assert improvement > 30, f"缓存性能提升不足: {improvement:.2f}%" 