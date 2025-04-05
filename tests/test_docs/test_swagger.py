#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Swagger UI集成测试

测试Swagger UI和ReDoc集成功能是否正常工作
"""

import pytest
from sanic import Sanic
from bs4 import BeautifulSoup

from app.docs import setup_swagger_ui, setup_openapi, get_redoc_html


@pytest.fixture
def test_app():
    """测试应用fixture"""
    app = Sanic("test_app")
    
    # 设置OpenAPI
    setup_openapi(
        app,
        title="Test API",
        version="1.0.0",
        description="Test API Documentation"
    )
    
    # 设置Swagger UI
    setup_swagger_ui(
        app,
        swagger_url="/swagger",
        swagger_json_url="/swagger.json"
    )
    
    # 设置ReDoc路由
    @app.route("/redoc")
    async def redoc_ui(request):
        return get_redoc_html(openapi_url="/swagger.json", title="API文档")
    
    return app


@pytest.mark.asyncio
async def test_swagger_ui_endpoint(test_app):
    """测试Swagger UI端点"""
    # 创建测试客户端
    request, response = await test_app.asgi_client.get("/swagger")
    
    # 验证响应
    assert response.status == 200
    assert "text/html" in response.content_type
    
    # 解析HTML
    soup = BeautifulSoup(response.body, "html.parser")
    
    # 验证Swagger UI页面结构
    assert soup.title is not None
    assert "Swagger" in soup.title.text
    
    # 查找关键元素
    swagger_ui_div = soup.find("div", id="swagger-ui")
    assert swagger_ui_div is not None
    
    # 查找swagger-ui初始化脚本
    scripts = soup.find_all("script")
    has_swagger_config = False
    for script in scripts:
        if script.string and "/swagger.json" in script.string:
            has_swagger_config = True
            break
    
    assert has_swagger_config, "Swagger UI初始化脚本未找到"


@pytest.mark.asyncio
async def test_redoc_endpoint(test_app):
    """测试ReDoc端点"""
    # 创建测试客户端
    request, response = await test_app.asgi_client.get("/redoc")
    
    # 验证响应
    assert response.status == 200
    assert "text/html" in response.content_type
    
    # 解析HTML
    soup = BeautifulSoup(response.body, "html.parser")
    
    # 验证ReDoc页面结构
    assert soup.title is not None
    assert "API" in soup.title.text
    
    # 查找redoc元素
    redoc_div = soup.find("redoc")
    assert redoc_div is not None
    
    # 查找ReDoc脚本
    redoc_script = soup.find("script", attrs={"src": lambda src: src and "redoc" in src})
    assert redoc_script is not None, "ReDoc脚本未找到"


@pytest.mark.asyncio
async def test_swagger_json_url_configuration(test_app):
    """测试Swagger JSON URL配置"""
    # 创建测试客户端
    request, response = await test_app.asgi_client.get("/swagger")
    
    # 验证响应
    assert response.status == 200
    
    # 解析HTML并查找swagger.json URL
    body_text = response.body.decode('utf-8')
    assert '"/swagger.json"' in body_text, "swagger.json URL配置错误" 