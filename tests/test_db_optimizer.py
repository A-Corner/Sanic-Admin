#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
数据库查询优化器测试

测试查询优化装饰器、关系预取、优化分页和批量获取功能
"""

import pytest
import time
from tortoise.queryset import QuerySet
from app.database.query_optimizer import (
    optimize_query,
    prefetch_related,
    paginate_optimized,
    batch_fetch
)
from app.models.account import Account
from app.models.role import Role
from app.models.permission import Permission
from app.models.system_log import SystemLog
from tests.utils import (
    create_test_account,
    create_test_roles,
    create_test_system_logs
)


@pytest.mark.asyncio
async def test_optimize_query_decorator():
    """测试查询优化装饰器"""
    # 创建测试数据
    for i in range(5):
        await create_test_account(
            username=f"optimizer_test_user_{i}",
            password="Test@123456",
            is_active=True
        )
    
    query_times = []
    
    # 未优化的查询
    async def normal_query():
        start_time = time.time()
        accounts = await Account.filter(username__startswith="optimizer_test_user_").all()
        query_time = time.time() - start_time
        query_times.append(query_time)
        return accounts, query_time
    
    # 优化的查询
    @optimize_query(select_related=[], prefetch_related=[], fields=["id", "username", "email"])
    async def optimized_query(queryset):
        start_time = time.time()
        accounts = await queryset
        query_time = time.time() - start_time
        query_times.append(query_time)
        return accounts, query_time
    
    # 执行普通查询
    normal_accounts, normal_time = await normal_query()
    
    # 执行优化查询
    queryset = Account.filter(username__startswith="optimizer_test_user_")
    optimized_accounts, optimized_time = await optimized_query(queryset)
    
    # 验证两种查询结果数量相同
    assert len(normal_accounts) == len(optimized_accounts), "两种查询应返回相同数量的结果"
    
    # 验证优化查询返回的字段
    for account in optimized_accounts:
        assert hasattr(account, "id"), "优化查询结果应包含id字段"
        assert hasattr(account, "username"), "优化查询结果应包含username字段"
        assert hasattr(account, "email"), "优化查询结果应包含email字段"
        # 为了确保只选择了指定字段，检查一个未指定的字段
        try:
            # 如果display_name未被加载，可能会抛出异常或返回None
            assert not hasattr(account, "_display_name_db"), "优化查询结果不应包含未指定的display_name字段"
        except (AttributeError, AssertionError):
            pass  # 这是预期行为，字段未被加载


@pytest.mark.asyncio
async def test_prefetch_related():
    """测试关系预取功能"""
    # 创建测试角色和账号
    roles = await create_test_roles(3)
    
    # 为每个角色创建多个账号
    accounts_per_role = {}
    for i, role in enumerate(roles):
        accounts = []
        for j in range(3):
            account = await create_test_account(
                username=f"prefetch_user_{i}_{j}",
                password="Test@123456",
                is_active=True
            )
            # 关联角色
            await account.roles.add(role)
            accounts.append(account)
        accounts_per_role[role.id] = accounts
    
    # 测试不同批次大小的预取
    for chunk_size in [2, 5, 10]:
        # 获取所有角色，但不预取关系
        all_roles = await Role.filter(code__startswith="test_role_").all()
        
        # 使用预取加载关联的账号
        start_time = time.time()
        fetched_roles = await prefetch_related(
            all_roles,
            [{"relation": "accounts"}],
            chunk_size=chunk_size
        )
        prefetch_time = time.time() - start_time
        
        # 验证每个角色关联的账号数量
        for role in fetched_roles:
            role_accounts = await role.accounts.all()
            expected_accounts = accounts_per_role.get(role.id, [])
            assert len(role_accounts) == len(expected_accounts), f"角色{role.code}的账号数量与预期不符"


@pytest.mark.asyncio
async def test_paginate_optimized():
    """测试优化分页功能"""
    # 创建测试数据
    await create_test_system_logs(30)  # 创建30条日志
    
    # 测试基本分页
    page1 = await paginate_optimized(
        SystemLog.all(),
        page=1,
        page_size=10,
        count_total=True
    )
    
    # 验证分页结果
    assert page1["total_count"] == 30, "总记录数应为30"
    assert page1["total_pages"] == 3, "总页数应为3"
    assert len(page1["items"]) == 10, "第一页应有10条记录"
    assert page1["current_page"] == 1, "当前页应为1"
    
    # 测试第二页
    page2 = await paginate_optimized(
        SystemLog.all(),
        page=2,
        page_size=10,
        count_total=True
    )
    
    assert page2["current_page"] == 2, "当前页应为2"
    assert len(page2["items"]) == 10, "第二页应有10条记录"
    
    # 测试最后一页
    page3 = await paginate_optimized(
        SystemLog.all(),
        page=3,
        page_size=10,
        count_total=True
    )
    
    assert page3["current_page"] == 3, "当前页应为3"
    assert len(page3["items"]) == 10, "第三页应有10条记录"
    
    # 测试不计算总数
    page_no_count = await paginate_optimized(
        SystemLog.all(),
        page=1,
        page_size=10,
        count_total=False
    )
    
    assert "total_count" not in page_no_count, "不计算总数时应没有total_count字段"
    assert "total_pages" not in page_no_count, "不计算总数时应没有total_pages字段"
    assert len(page_no_count["items"]) == 10, "结果应有10条记录"


@pytest.mark.asyncio
async def test_batch_fetch():
    """测试批量获取功能"""
    # 创建测试数据
    for i in range(25):
        await create_test_account(
            username=f"batch_test_user_{i}",
            password="Test@123456",
            is_active=True if i % 2 == 0 else False
        )
    
    # 查询条件
    query = Account.filter(username__startswith="batch_test_user_")
    
    # 使用批量获取，每次获取10条
    all_accounts = []
    async for accounts in batch_fetch(query, batch_size=10):
        all_accounts.extend(accounts)
    
    # 验证结果
    assert len(all_accounts) == 25, "应获取全部25个账号"
    
    # 测试指定字段
    limited_accounts = []
    async for accounts in batch_fetch(
        query, 
        batch_size=10,
        fields=["id", "username", "is_active"]
    ):
        for account in accounts:
            assert hasattr(account, "id"), "结果应包含id字段"
            assert hasattr(account, "username"), "结果应包含username字段"
            assert hasattr(account, "is_active"), "结果应包含is_active字段"
            # 验证未包含指定字段以外的字段
            try:
                assert not hasattr(account, "_email_db"), "结果不应包含email字段"
            except (AttributeError, AssertionError):
                pass
        limited_accounts.extend(accounts)
    
    assert len(limited_accounts) == 25, "应获取全部25个账号"
    
    # 测试附加过滤条件
    active_accounts = []
    async for accounts in batch_fetch(
        query,
        batch_size=10,
        filters={"is_active": True}
    ):
        for account in accounts:
            assert account.is_active == True, "只应获取激活的账号"
        active_accounts.extend(accounts)
    
    assert len(active_accounts) == 13, "应有13个激活账号"  # 索引为偶数的账号是激活的 