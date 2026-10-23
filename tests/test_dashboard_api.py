#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
仪表盘只读端点测试（v0.3 P6 覆盖率）。

覆盖 ``app/api/resources/dashboard.py``、``dashboard_user.py``、
``dashboard_performance.py`` 三个模块的 9 个 GET 端点。这些端点是只读聚合，
空库也应返回 200 和统一的 ``success/data`` 信封；本文件同时钉住这一契约。
"""

import pytest

#: 三个 dashboard 模块注册的全部只读端点（与 register_view 一一对应）
DASHBOARD_ENDPOINTS = [
    "/api/v1/dashboard/summary",
    "/api/v1/dashboard/activities",
    "/api/v1/dashboard/storage",
    "/api/v1/dashboard/user-activity",
    "/api/v1/dashboard/feature-usage",
    "/api/v1/dashboard/permission-analysis",
    "/api/v1/dashboard/performance",
    "/api/v1/dashboard/exceptions",
    "/api/v1/dashboard/alerts",
]


@pytest.mark.parametrize("path", DASHBOARD_ENDPOINTS)
async def test_dashboard_endpoint_returns_envelope(client, auth_headers, path):
    """每个仪表盘端点空库下也要 200，且返回 success/data 信封。"""
    response = await client.get(path, headers=auth_headers)
    assert response.status_code == 200, (
        f"GET {path} 返回 {response.status_code}：{response.text[:200]}"
    )
    body = response.json()
    assert body.get("success") is True, f"{path} 的 success 应为 True"
    assert "data" in body, f"{path} 响应缺少 data 字段"


@pytest.mark.parametrize("path", DASHBOARD_ENDPOINTS)
async def test_dashboard_endpoint_requires_auth(client, path):
    """未登录访问仪表盘端点必须 401（组级认证中间件覆盖）。"""
    response = await client.get(path)
    assert response.status_code == 401, (
        f"未登录 GET {path} 返回 {response.status_code}，应 401"
    )
