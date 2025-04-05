#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
账号管理API测试

测试账号创建、修改、查询、删除等功能
"""

import pytest
from tests.utils import (
    assert_success_response,
    assert_error_response,
    assert_pagination,
    assert_has_keys,
    create_test_account,
    generate_random_email
)


@pytest.mark.asyncio
async def test_get_current_account(client, auth_headers):
    """测试获取当前账号信息"""
    response = await client.get("/api/v1/account/me", headers=auth_headers)
    
    # 验证响应
    data = assert_success_response(response)
    account = data["data"]
    
    # 检查返回的账号数据是否包含必要字段
    assert_has_keys(account, ["id", "username", "email", "display_name", "is_active", "is_admin", "created_at"])


@pytest.mark.asyncio
async def test_update_current_account(client, auth_headers):
    """测试更新当前账号信息"""
    # 先获取当前账号信息
    get_response = await client.get("/api/v1/account/me", headers=auth_headers)
    original_data = assert_success_response(get_response)
    original_account = original_data["data"]
    
    # 更新显示名称
    new_display_name = "更新后的测试用户名"
    update_response = await client.put(
        "/api/v1/account/me",
        headers=auth_headers,
        json={
            "display_name": new_display_name
        }
    )
    
    # 验证更新响应
    update_data = assert_success_response(update_response)
    updated_account = update_data["data"]
    assert updated_account["display_name"] == new_display_name, "显示名称未正确更新"
    
    # 再次获取账号信息确认更新成功
    confirm_response = await client.get("/api/v1/account/me", headers=auth_headers)
    confirm_data = assert_success_response(confirm_response)
    confirm_account = confirm_data["data"]
    assert confirm_account["display_name"] == new_display_name, "显示名称更新未持久化"


@pytest.mark.asyncio
async def test_change_password(client, auth_headers):
    """测试修改密码"""
    # 获取当前账号信息
    get_response = await client.get("/api/v1/account/me", headers=auth_headers)
    original_data = assert_success_response(get_response)
    original_account = original_data["data"]
    
    # 创建一个独立测试用户
    test_username = "test_change_pwd_user"
    old_password = "OldTest@123456"
    new_password = "NewTest@789012"
    
    test_account = await create_test_account(
        username=test_username,
        password=old_password,
        is_active=True
    )
    
    # 先用旧密码登录
    login_response = await client.post(
        "/auth/login",
        json={
            "username": test_username,
            "password": old_password
        }
    )
    
    login_data = assert_success_response(login_response)
    test_token = login_data["data"]["access_token"]
    test_headers = {"Authorization": f"Bearer {test_token}"}
    
    # 修改密码
    change_pwd_response = await client.post(
        "/api/v1/account/change-password",
        headers=test_headers,
        json={
            "old_password": old_password,
            "new_password": new_password,
            "confirm_password": new_password
        }
    )
    
    # 验证修改密码响应
    assert_success_response(change_pwd_response)
    
    # 尝试使用旧密码登录
    old_login_response = await client.post(
        "/auth/login",
        json={
            "username": test_username,
            "password": old_password
        }
    )
    
    # 应该失败
    assert_error_response(old_login_response, expected_status=401)
    
    # 使用新密码登录
    new_login_response = await client.post(
        "/auth/login",
        json={
            "username": test_username,
            "password": new_password
        }
    )
    
    # 应该成功
    assert_success_response(new_login_response)


@pytest.mark.asyncio
async def test_admin_list_accounts(client, auth_headers):
    """测试管理员列出所有账号"""
    # 创建一些测试账号
    for i in range(3):
        await create_test_account(
            username=f"test_list_user_{i}",
            password="Test@123456",
            is_active=True
        )
    
    # 获取账号列表
    response = await client.get("/api/v1/admin/accounts", headers=auth_headers)
    
    # 验证响应
    data = assert_success_response(response)
    
    # 验证分页结构
    assert_pagination(data["data"])
    
    # 验证返回的数据是否包含账号列表
    assert "items" in data["data"], "响应中缺少账号列表"
    assert len(data["data"]["items"]) > 0, "账号列表不应为空"
    
    # 检查每个账号是否包含必要字段
    for account in data["data"]["items"]:
        assert_has_keys(account, ["id", "username", "email", "display_name", "is_active", "is_admin", "created_at"])


@pytest.mark.asyncio
async def test_admin_search_accounts(client, auth_headers):
    """测试管理员搜索账号"""
    # 创建一个特殊的测试账号用于搜索
    special_username = "special_search_user"
    await create_test_account(
        username=special_username,
        password="Test@123456",
        is_active=True
    )
    
    # 搜索特殊账号
    response = await client.get(
        f"/api/v1/admin/accounts?keyword={special_username}", 
        headers=auth_headers
    )
    
    # 验证响应
    data = assert_success_response(response)
    
    # 验证分页结构
    assert_pagination(data["data"])
    
    # 验证搜索结果
    assert "items" in data["data"], "响应中缺少账号列表"
    
    # 检查是否包含我们搜索的特殊账号
    found = False
    for account in data["data"]["items"]:
        if account["username"] == special_username:
            found = True
            break
    
    assert found, f"搜索结果中未找到特殊账号: {special_username}"


@pytest.mark.asyncio
async def test_admin_create_account(client, auth_headers):
    """测试管理员创建账号"""
    # 生成测试数据
    test_username = "admin_created_user"
    test_email = generate_random_email()
    test_password = "Test@123456"
    
    # 创建账号
    response = await client.post(
        "/api/v1/admin/accounts",
        headers=auth_headers,
        json={
            "username": test_username,
            "email": test_email,
            "password": test_password,
            "display_name": "管理员创建的测试用户",
            "is_active": True,
            "is_admin": False
        }
    )
    
    # 验证响应
    data = assert_success_response(response)
    account = data["data"]
    
    # 检查账号数据
    assert account["username"] == test_username, "用户名不匹配"
    assert account["email"] == test_email, "邮箱不匹配"
    assert account["is_active"] == True, "激活状态不匹配"
    assert account["is_admin"] == False, "管理员状态不匹配"
    
    # 尝试使用创建的账号登录
    login_response = await client.post(
        "/auth/login",
        json={
            "username": test_username,
            "password": test_password
        }
    )
    
    # 验证登录成功
    assert_success_response(login_response)


@pytest.mark.asyncio
async def test_admin_get_account(client, auth_headers):
    """测试管理员获取特定账号信息"""
    # 创建一个测试账号
    test_username = "test_get_account_user"
    test_account = await create_test_account(
        username=test_username,
        password="Test@123456",
        is_active=True
    )
    
    # 获取账号信息
    response = await client.get(
        f"/api/v1/admin/accounts/{test_account.id}",
        headers=auth_headers
    )
    
    # 验证响应
    data = assert_success_response(response)
    account = data["data"]
    
    # 验证账号信息
    assert account["id"] == str(test_account.id), "账号ID不匹配"
    assert account["username"] == test_username, "用户名不匹配"


@pytest.mark.asyncio
async def test_admin_update_account(client, auth_headers):
    """测试管理员更新账号信息"""
    # 创建一个测试账号
    test_username = "test_update_account_user"
    test_account = await create_test_account(
        username=test_username,
        password="Test@123456",
        is_active=True,
        is_admin=False
    )
    
    # 更新账号信息
    new_display_name = "更新后的管理员测试用户"
    update_response = await client.put(
        f"/api/v1/admin/accounts/{test_account.id}",
        headers=auth_headers,
        json={
            "display_name": new_display_name,
            "is_active": False,
            "is_admin": True
        }
    )
    
    # 验证更新响应
    update_data = assert_success_response(update_response)
    updated_account = update_data["data"]
    
    # 检查更新是否成功
    assert updated_account["display_name"] == new_display_name, "显示名称未正确更新"
    assert updated_account["is_active"] == False, "激活状态未正确更新"
    assert updated_account["is_admin"] == True, "管理员状态未正确更新"
    
    # 获取账号信息确认更新成功
    get_response = await client.get(
        f"/api/v1/admin/accounts/{test_account.id}",
        headers=auth_headers
    )
    
    get_data = assert_success_response(get_response)
    get_account = get_data["data"]
    
    # 再次验证更新是否成功
    assert get_account["display_name"] == new_display_name, "显示名称更新未持久化"
    assert get_account["is_active"] == False, "激活状态更新未持久化"
    assert get_account["is_admin"] == True, "管理员状态更新未持久化"


@pytest.mark.asyncio
async def test_admin_delete_account(client, auth_headers):
    """测试管理员删除账号"""
    # 创建一个测试账号
    test_username = "test_delete_account_user"
    test_account = await create_test_account(
        username=test_username,
        password="Test@123456",
        is_active=True
    )
    
    # 删除账号
    delete_response = await client.delete(
        f"/api/v1/admin/accounts/{test_account.id}",
        headers=auth_headers
    )
    
    # 验证删除响应
    assert_success_response(delete_response)
    
    # 尝试获取已删除账号
    get_response = await client.get(
        f"/api/v1/admin/accounts/{test_account.id}",
        headers=auth_headers
    )
    
    # 应该返回404错误
    assert_error_response(get_response, expected_status=404) 