#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
端到端集成测试

测试完整的用户操作流程和多角色操作场景
"""

import pytest
import json
import uuid
from tests.utils import (
    assert_success_response,
    assert_error_response,
    assert_pagination,
    assert_has_keys,
    get_auth_headers,
    generate_random_email
)


@pytest.mark.asyncio
async def test_complete_user_workflow(client):
    """测试完整的用户工作流程：注册->登录->更新个人信息->修改密码->登出"""
    # 生成随机用户信息
    test_username = f"workflow_user_{uuid.uuid4().hex[:8]}"
    test_email = generate_random_email()
    test_password = "Test@123456"
    new_password = "NewTest@789012"
    
    # 步骤1: 注册新用户
    register_response = await client.post(
        "/auth/register",
        json={
            "username": test_username,
            "email": test_email,
            "password": test_password,
            "confirm_password": test_password,
            "display_name": "工作流测试用户"
        }
    )
    register_data = assert_success_response(register_response)
    
    # 步骤2: 用户登录
    login_response = await client.post(
        "/auth/login",
        json={
            "username": test_username,
            "password": test_password
        }
    )
    login_data = assert_success_response(login_response)
    access_token = login_data["data"]["access_token"]
    auth_headers = get_auth_headers(access_token)
    
    # 步骤3: 获取个人信息
    profile_response = await client.get(
        "/api/v1/account/me",
        headers=auth_headers
    )
    profile_data = assert_success_response(profile_response)
    account_id = profile_data["data"]["id"]
    
    # 步骤4: 更新个人信息
    new_display_name = "更新后的工作流测试用户"
    update_response = await client.put(
        "/api/v1/account/me",
        headers=auth_headers,
        json={
            "display_name": new_display_name
        }
    )
    update_data = assert_success_response(update_response)
    assert update_data["data"]["display_name"] == new_display_name
    
    # 步骤5: 修改密码
    change_pwd_response = await client.post(
        "/api/v1/account/change-password",
        headers=auth_headers,
        json={
            "old_password": test_password,
            "new_password": new_password,
            "confirm_password": new_password
        }
    )
    assert_success_response(change_pwd_response)
    
    # 步骤6: 登出
    logout_response = await client.post(
        "/auth/logout",
        headers=auth_headers
    )
    assert_success_response(logout_response)
    
    # 步骤7: 验证旧令牌已失效
    invalid_token_response = await client.get(
        "/api/v1/account/me",
        headers=auth_headers
    )
    assert_error_response(invalid_token_response, expected_status=401)
    
    # 步骤8: 使用新密码登录
    new_login_response = await client.post(
        "/auth/login",
        json={
            "username": test_username,
            "password": new_password
        }
    )
    assert_success_response(new_login_response)


@pytest.mark.asyncio
async def test_admin_role_operations(client, auth_headers):
    """测试管理员角色操作：创建角色->分配权限->创建用户->分配角色->验证权限"""
    # 步骤1: 创建新角色
    role_code = f"test_role_{uuid.uuid4().hex[:8]}"
    role_name = "集成测试角色"
    
    create_role_response = await client.post(
        "/api/v1/admin/roles",
        headers=auth_headers,
        json={
            "code": role_code,
            "name": role_name,
            "description": "用于集成测试的角色"
        }
    )
    role_data = assert_success_response(create_role_response)
    role_id = role_data["data"]["id"]
    
    # 步骤2: 获取系统权限列表
    permissions_response = await client.get(
        "/api/v1/admin/permissions",
        headers=auth_headers
    )
    permissions_data = assert_success_response(permissions_response)
    permissions = permissions_data["data"]["items"]
    
    # 选择两个权限
    selected_permissions = [permissions[0]["id"], permissions[1]["id"]]
    
    # 步骤3: 分配权限给角色
    assign_permissions_response = await client.post(
        f"/api/v1/admin/roles/{role_id}/permissions",
        headers=auth_headers,
        json={
            "permission_ids": selected_permissions
        }
    )
    assert_success_response(assign_permissions_response)
    
    # 步骤4: 创建新用户
    test_username = f"role_test_user_{uuid.uuid4().hex[:8]}"
    test_email = generate_random_email()
    test_password = "Test@123456"
    
    create_user_response = await client.post(
        "/api/v1/admin/accounts",
        headers=auth_headers,
        json={
            "username": test_username,
            "email": test_email,
            "password": test_password,
            "display_name": "角色测试用户",
            "is_active": True,
            "is_admin": False
        }
    )
    user_data = assert_success_response(create_user_response)
    user_id = user_data["data"]["id"]
    
    # 步骤5: 分配角色给用户
    assign_role_response = await client.post(
        f"/api/v1/admin/accounts/{user_id}/roles",
        headers=auth_headers,
        json={
            "role_ids": [role_id]
        }
    )
    assert_success_response(assign_role_response)
    
    # 步骤6: 用户登录
    login_response = await client.post(
        "/auth/login",
        json={
            "username": test_username,
            "password": test_password
        }
    )
    login_data = assert_success_response(login_response)
    user_token = login_data["data"]["access_token"]
    user_headers = get_auth_headers(user_token)
    
    # 步骤7: 获取用户权限
    permissions_response = await client.get(
        "/api/v1/account/permissions",
        headers=user_headers
    )
    perm_data = assert_success_response(permissions_response)
    user_permissions = perm_data["data"]
    
    # 验证用户是否获得了正确的权限
    assert len(user_permissions) >= 2, "用户应该至少拥有所分配的两个权限"
    
    # 步骤8: 管理员移除用户角色
    remove_role_response = await client.delete(
        f"/api/v1/admin/accounts/{user_id}/roles/{role_id}",
        headers=auth_headers
    )
    assert_success_response(remove_role_response)
    
    # 步骤9: 再次获取用户权限
    permissions_response_after = await client.get(
        "/api/v1/account/permissions",
        headers=user_headers
    )
    perm_data_after = assert_success_response(permissions_response_after)
    user_permissions_after = perm_data_after["data"]
    
    # 验证用户权限已被移除
    assert len(user_permissions_after) < len(user_permissions), "用户权限应该减少"
    
    # 步骤10: 清理 - 删除角色和用户
    delete_user_response = await client.delete(
        f"/api/v1/admin/accounts/{user_id}",
        headers=auth_headers
    )
    assert_success_response(delete_user_response)
    
    delete_role_response = await client.delete(
        f"/api/v1/admin/roles/{role_id}",
        headers=auth_headers
    )
    assert_success_response(delete_role_response)


@pytest.mark.asyncio
async def test_system_settings_integration(client, auth_headers):
    """测试系统设置集成流程：创建设置->获取设置->更新设置->删除设置"""
    # 步骤1: 创建系统设置
    setting_key = f"test_setting_{uuid.uuid4().hex[:8]}"
    setting_value = "测试值"
    
    create_setting_response = await client.post(
        "/api/v1/admin/settings",
        headers=auth_headers,
        json={
            "key": setting_key,
            "name": "测试设置名称",
            "value": setting_value,
            "category": "测试",
            "description": "集成测试创建的设置"
        }
    )
    setting_data = assert_success_response(create_setting_response)
    setting_id = setting_data["data"]["id"]
    
    # 步骤2: 获取所有设置
    get_settings_response = await client.get(
        "/api/v1/admin/settings",
        headers=auth_headers
    )
    settings_data = assert_success_response(get_settings_response)
    
    # 验证设置列表中包含新设置
    found = False
    for setting in settings_data["data"]["items"]:
        if setting["key"] == setting_key:
            found = True
            break
    assert found, f"未找到创建的设置 {setting_key}"
    
    # 步骤3: 更新设置
    new_value = "更新后的测试值"
    update_setting_response = await client.put(
        f"/api/v1/admin/settings/{setting_id}",
        headers=auth_headers,
        json={
            "value": new_value,
            "description": "已更新的测试设置"
        }
    )
    updated_setting = assert_success_response(update_setting_response)
    assert updated_setting["data"]["value"] == new_value, "设置值未正确更新"
    
    # 步骤4: 获取特定设置
    get_setting_response = await client.get(
        f"/api/v1/admin/settings/{setting_id}",
        headers=auth_headers
    )
    get_setting_data = assert_success_response(get_setting_response)
    assert get_setting_data["data"]["value"] == new_value, "获取的设置值与更新后的值不一致"
    
    # 步骤5: 删除设置
    delete_setting_response = await client.delete(
        f"/api/v1/admin/settings/{setting_id}",
        headers=auth_headers
    )
    assert_success_response(delete_setting_response)
    
    # 步骤6: 验证设置已删除
    get_deleted_setting_response = await client.get(
        f"/api/v1/admin/settings/{setting_id}",
        headers=auth_headers
    )
    assert_error_response(get_deleted_setting_response, expected_status=404)


@pytest.mark.asyncio
async def test_error_handling_integration(client, auth_headers):
    """测试错误处理集成：测试各种错误情况和错误响应"""
    # 测试1: 访问不存在的路由
    not_found_response = await client.get("/api/v1/nonexistent")
    assert_error_response(not_found_response, expected_status=404)
    
    # 测试2: 无效的请求体
    invalid_body_response = await client.post(
        "/auth/login",
        json={"invalid": "format"}
    )
    assert_error_response(invalid_body_response, expected_status=400)
    
    # 测试3: 权限不足
    # 创建一个没有管理权限的普通用户
    test_username = f"perm_test_user_{uuid.uuid4().hex[:8]}"
    test_password = "Test@123456"
    
    create_user_response = await client.post(
        "/api/v1/admin/accounts",
        headers=auth_headers,
        json={
            "username": test_username,
            "email": generate_random_email(),
            "password": test_password,
            "display_name": "权限测试用户",
            "is_active": True,
            "is_admin": False
        }
    )
    user_data = assert_success_response(create_user_response)
    user_id = user_data["data"]["id"]
    
    # 用户登录
    login_response = await client.post(
        "/auth/login",
        json={
            "username": test_username,
            "password": test_password
        }
    )
    login_data = assert_success_response(login_response)
    user_token = login_data["data"]["access_token"]
    user_headers = get_auth_headers(user_token)
    
    # 尝试访问管理员接口
    forbidden_response = await client.get(
        "/api/v1/admin/accounts",
        headers=user_headers
    )
    assert_error_response(forbidden_response, expected_status=403)
    
    # 测试4: 提交冲突数据（尝试创建同名账户）
    duplicate_response = await client.post(
        "/api/v1/admin/accounts",
        headers=auth_headers,
        json={
            "username": test_username,  # 使用已存在的用户名
            "email": generate_random_email(),
            "password": test_password,
            "display_name": "重复用户名测试",
            "is_active": True,
            "is_admin": False
        }
    )
    assert_error_response(duplicate_response, expected_status=400)
    
    # 测试5: 提交过长数据
    long_string = "a" * 1000  # 创建一个非常长的字符串
    long_data_response = await client.post(
        "/api/v1/admin/accounts",
        headers=auth_headers,
        json={
            "username": long_string,  # 用户名过长
            "email": generate_random_email(),
            "password": test_password,
            "display_name": "长数据测试",
            "is_active": True,
            "is_admin": False
        }
    )
    assert_error_response(long_data_response, expected_status=400)
    
    # 清理测试账户
    delete_response = await client.delete(
        f"/api/v1/admin/accounts/{user_id}",
        headers=auth_headers
    )
    assert_success_response(delete_response) 