#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
测试帮助函数模块

提供测试断言和辅助函数，简化测试编写
"""

import json
from typing import Dict, Any, List, Optional, Tuple, Union

from sanic.response import HTTPResponse
from sanic_testing import TestManager


def extract_response_data(response: HTTPResponse) -> Dict[str, Any]:
    """
    从响应中提取数据

    Args:
        response: Sanic HTTP响应对象

    Returns:
        Dict[str, Any]: 响应数据字典
    """
    response_text = response.body.decode('utf-8')
    return json.loads(response_text)


def assert_success_response(response: HTTPResponse) -> Dict[str, Any]:
    """
    断言响应是成功的

    Args:
        response: Sanic HTTP响应对象

    Returns:
        Dict[str, Any]: 响应数据
    """
    assert response.status == 200, f"Expected 200 status code, got {response.status}"
    
    data = extract_response_data(response)
    
    assert data.get("success") is True, f"Expected success=True, got {data.get('success')}"
    assert "data" in data, "Response does not contain 'data' field"
    
    return data


def assert_error_response(
    response: HTTPResponse,
    expected_status: int = 400,
    expected_code: Optional[str] = None
) -> Dict[str, Any]:
    """
    断言响应是错误的

    Args:
        response: Sanic HTTP响应对象
        expected_status: 期望的HTTP状态码
        expected_code: 期望的错误代码

    Returns:
        Dict[str, Any]: 响应数据
    """
    assert response.status == expected_status, f"Expected {expected_status} status code, got {response.status}"
    
    data = extract_response_data(response)
    
    assert data.get("success") is False, f"Expected success=False, got {data.get('success')}"
    assert "error" in data, "Response does not contain 'error' field"
    
    if expected_code:
        assert data.get("error", {}).get("code") == expected_code, \
            f"Expected error code {expected_code}, got {data.get('error', {}).get('code')}"
    
    return data


def assert_pagination(data: Dict[str, Any], page: int, page_size: int) -> None:
    """
    断言分页响应格式正确

    Args:
        data: 响应数据
        page: 期望的页码
        page_size: 期望的每页数量
    """
    assert "pagination" in data, "Response does not contain 'pagination' field"
    pagination = data["pagination"]
    
    assert "page" in pagination, "Pagination does not contain 'page' field"
    assert pagination["page"] == page, f"Expected page {page}, got {pagination['page']}"
    
    assert "page_size" in pagination, "Pagination does not contain 'page_size' field"
    assert pagination["page_size"] == page_size, f"Expected page_size {page_size}, got {pagination['page_size']}"
    
    assert "total" in pagination, "Pagination does not contain 'total' field"
    assert "total_pages" in pagination, "Pagination does not contain 'total_pages' field"


def assert_has_keys(obj: Dict[str, Any], keys: List[str]) -> None:
    """
    断言对象包含所有指定的键

    Args:
        obj: 要检查的对象
        keys: 期望包含的键列表
    """
    for key in keys:
        assert key in obj, f"Object does not contain key '{key}'"


def assert_list_has_length(data_list: List[Any], expected_length: int) -> None:
    """
    断言列表长度符合预期

    Args:
        data_list: 要检查的列表
        expected_length: 期望的长度
    """
    assert len(data_list) == expected_length, f"Expected list length {expected_length}, got {len(data_list)}"


async def login_user(
    client: TestManager,
    username: str = "admin",
    password: str = "admin"
) -> Tuple[HTTPResponse, Optional[str]]:
    """
    登录用户并获取访问令牌

    Args:
        client: 测试客户端
        username: 用户名
        password: 密码

    Returns:
        Tuple: (响应对象, 访问令牌)
    """
    response = await client.post(
        "/auth/login",
        json={"username": username, "password": password}
    )
    
    if response.status != 200:
        return response, None
    
    data = extract_response_data(response)
    token = data.get("data", {}).get("access_token")
    
    return response, token


def get_auth_headers(token: str) -> Dict[str, str]:
    """
    获取带有认证令牌的请求头

    Args:
        token: 访问令牌

    Returns:
        Dict[str, str]: 请求头字典
    """
    return {"Authorization": f"Bearer {token}"}


def json_fixture(fixture_name: str) -> Dict[str, Any]:
    """
    从fixtures目录加载JSON测试数据

    Args:
        fixture_name: 数据文件名（不含扩展名）

    Returns:
        Dict[str, Any]: 加载的JSON数据
    """
    import os
    import json
    
    fixtures_dir = os.path.join(os.path.dirname(__file__), "..", "fixtures")
    fixture_path = os.path.join(fixtures_dir, f"{fixture_name}.json")
    
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f) 