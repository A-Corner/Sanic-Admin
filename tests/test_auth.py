#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
认证模块测试

测试登录、注册、密码重置等认证功能
"""

import pytest
from tests.utils import (
    assert_success_response,
    assert_error_response,
    get_auth_headers,
    create_test_account,
    generate_random_email
)


@pytest.mark.asyncio
async def test_login_success(client):
    """测试登录成功"""
    # 先创建一个测试账户
    test_username = "test_login_user"
    test_password = "Test@123456"
    
    await create_test_account(
        username=test_username,
        password=test_password,
        is_active=True
    )
    
    # 使用创建的账户登录
    response = await client.post(
        "/auth/login",
        json={
            "username": test_username,
            "password": test_password
        }
    )
    
    # 验证响应
    data = assert_success_response(response)
    assert "access_token" in data["data"], "响应中缺少access_token"
    assert "refresh_token" in data["data"], "响应中缺少refresh_token"
    assert "token_type" in data["data"], "响应中缺少token_type"
    assert data["data"]["token_type"] == "bearer", "token_type应为bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    """测试密码错误的登录"""
    # 先创建一个测试账户
    test_username = "test_wrong_pwd_user"
    test_password = "Test@123456"
    
    await create_test_account(
        username=test_username,
        password=test_password,
        is_active=True
    )
    
    # 使用错误密码登录
    response = await client.post(
        "/auth/login",
        json={
            "username": test_username,
            "password": "wrong_password"
        }
    )
    
    # 验证响应
    assert_error_response(response, expected_status=401, expected_code="LOGIN_FAILED")


@pytest.mark.asyncio
async def test_login_inactive_account(client):
    """测试未激活账户登录"""
    # 先创建一个未激活的测试账户
    test_username = "test_inactive_user"
    test_password = "Test@123456"
    
    await create_test_account(
        username=test_username,
        password=test_password,
        is_active=False
    )
    
    # 使用未激活账户登录
    response = await client.post(
        "/auth/login",
        json={
            "username": test_username,
            "password": test_password
        }
    )
    
    # 验证响应
    assert_error_response(response, expected_status=401, expected_code="ACCOUNT_INACTIVE")


@pytest.mark.asyncio
async def test_logout(client):
    """测试登出功能"""
    # 先创建一个测试账户并登录
    test_username = "test_logout_user"
    test_password = "Test@123456"
    
    await create_test_account(
        username=test_username,
        password=test_password,
        is_active=True
    )
    
    # 登录
    login_response = await client.post(
        "/auth/login",
        json={
            "username": test_username,
            "password": test_password
        }
    )
    
    login_data = assert_success_response(login_response)
    token = login_data["data"]["access_token"]
    
    # 使用令牌登出
    logout_response = await client.post(
        "/auth/logout",
        headers=get_auth_headers(token)
    )
    
    # 验证响应
    assert_success_response(logout_response)
    
    # 尝试使用已登出的令牌访问需要认证的接口
    profile_response = await client.get(
        "/api/v1/account/me",
        headers=get_auth_headers(token)
    )
    
    # 应该返回401错误
    assert_error_response(profile_response, expected_status=401)


@pytest.mark.asyncio
async def test_register(client):
    """测试注册功能"""
    # 生成测试数据
    test_username = f"test_register_user"
    test_email = generate_random_email()
    test_password = "Test@123456"
    
    # 注册新账户
    response = await client.post(
        "/auth/register",
        json={
            "username": test_username,
            "email": test_email,
            "password": test_password,
            "confirm_password": test_password,
            "display_name": "测试注册用户"
        }
    )
    
    # 验证响应
    data = assert_success_response(response)
    assert "account" in data["data"], "响应中缺少account信息"
    assert data["data"]["account"]["username"] == test_username
    assert data["data"]["account"]["email"] == test_email
    
    # 尝试使用新注册的账户登录
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
async def test_register_duplicate_username(client):
    """测试重复用户名注册"""
    # 先创建一个测试账户
    test_username = "test_dup_username"
    test_password = "Test@123456"
    
    await create_test_account(
        username=test_username,
        password=test_password,
        is_active=True
    )
    
    # 尝试使用相同用户名注册
    response = await client.post(
        "/auth/register",
        json={
            "username": test_username,
            "email": generate_random_email(),
            "password": "NewPassword@123",
            "confirm_password": "NewPassword@123",
            "display_name": "测试重复用户名"
        }
    )
    
    # 验证响应
    assert_error_response(response, expected_status=400, expected_code="USERNAME_EXISTS")


@pytest.mark.asyncio
async def test_refresh_token(client):
    """测试刷新令牌"""
    # 先创建一个测试账户并登录
    test_username = "test_refresh_token_user"
    test_password = "Test@123456"
    
    await create_test_account(
        username=test_username,
        password=test_password,
        is_active=True
    )
    
    # 登录
    login_response = await client.post(
        "/auth/login",
        json={
            "username": test_username,
            "password": test_password
        }
    )
    
    login_data = assert_success_response(login_response)
    refresh_token = login_data["data"]["refresh_token"]
    
    # 使用刷新令牌获取新的访问令牌
    refresh_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    
    # 验证响应
    refresh_data = assert_success_response(refresh_response)
    assert "access_token" in refresh_data["data"], "响应中缺少access_token"
    assert refresh_data["data"]["access_token"] != login_data["data"]["access_token"], "新旧访问令牌不应相同"
    
    # 使用新令牌访问需要认证的接口
    profile_response = await client.get(
        "/api/v1/account/me",
        headers=get_auth_headers(refresh_data["data"]["access_token"])
    )
    
    # 验证可以成功访问
    assert_success_response(profile_response) 