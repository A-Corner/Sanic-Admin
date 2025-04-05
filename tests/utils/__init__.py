#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
测试工具包，包含测试帮助函数和数据生成器
"""

from tests.utils.helpers import (
    extract_response_data,
    assert_success_response,
    assert_error_response,
    assert_pagination,
    assert_has_keys,
    assert_list_has_length,
    login_user,
    get_auth_headers,
    json_fixture
)

from tests.utils.data_generator import (
    create_test_account,
    create_test_roles,
    create_test_system_logs,
    create_test_system_settings,
    generate_random_string,
    generate_random_email
)

__all__ = [
    # 测试帮助函数
    'extract_response_data',
    'assert_success_response',
    'assert_error_response',
    'assert_pagination',
    'assert_has_keys',
    'assert_list_has_length',
    'login_user',
    'get_auth_headers',
    'json_fixture',
    
    # 数据生成器
    'create_test_account',
    'create_test_roles',
    'create_test_system_logs',
    'create_test_system_settings',
    'generate_random_string',
    'generate_random_email'
] 