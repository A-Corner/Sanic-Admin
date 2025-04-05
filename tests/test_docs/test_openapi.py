#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
OpenAPI规范生成器测试

测试OpenAPI规范生成功能是否正常工作
"""

import pytest
import json
from sanic import Sanic, Blueprint, response
from pydantic import BaseModel, Field
from typing import Optional

from app.docs import (
    setup_openapi, 
    get_openapi_spec,
    api_tags,
    api_summary,
    api_body,
    api_response,
    register_model
)


class TestItem(BaseModel):
    """测试项目模型"""
    id: int = Field(..., description="ID")
    name: str = Field(..., description="名称")


class TestCreateRequest(BaseModel):
    """测试创建请求"""
    name: str = Field(..., description="名称")
    description: Optional[str] = Field(None, description="描述")


class TestResponse(BaseModel):
    """测试响应"""
    success: bool = Field(True, description="是否成功")
    data: TestItem = Field(..., description="数据")


@pytest.fixture
def test_app():
    """测试应用fixture"""
    app = Sanic("test_app")
    
    # 注册模型
    register_model(TestItem)
    register_model(TestCreateRequest)
    register_model(TestResponse)
    
    # 创建测试蓝图
    bp = Blueprint("test_api", url_prefix="/api/test")
    
    @bp.route("/", methods=["GET"])
    @api_tags("测试")
    @api_summary("获取测试列表")
    async def get_items(request):
        return response.json({"success": True, "data": []})
    
    @bp.route("/<item_id:int>", methods=["GET"])
    @api_tags("测试")
    @api_summary("获取测试项详情")
    @api_response(model=TestResponse, description="测试项详情")
    async def get_item(request, item_id):
        return response.json({
            "success": True,
            "data": {"id": item_id, "name": f"测试项{item_id}"}
        })
    
    @bp.route("/", methods=["POST"])
    @api_tags("测试")
    @api_summary("创建测试项")
    @api_body(TestCreateRequest)
    @api_response(model=TestResponse, status_code=201)
    async def create_item(request):
        return response.json({
            "success": True,
            "data": {"id": 1, "name": request.json.get("name")}
        }, status=201)
    
    # 注册蓝图
    app.blueprint(bp)
    
    # 设置OpenAPI
    setup_openapi(
        app,
        title="Test API",
        version="1.0.0",
        description="Test API Documentation"
    )
    
    return app


@pytest.mark.asyncio
async def test_openapi_spec_generation(test_app):
    """测试OpenAPI规范生成"""
    # 获取OpenAPI规范
    spec = get_openapi_spec()
    
    # 验证基本信息
    assert spec["info"]["title"] == "Test API"
    assert spec["info"]["version"] == "1.0.0"
    assert spec["info"]["description"] == "Test API Documentation"
    
    # 验证路径
    assert "/api/test/" in spec["paths"]
    assert "/api/test/{item_id}" in spec["paths"]
    
    # 验证GET方法
    get_path = spec["paths"]["/api/test/"]
    assert "get" in get_path
    assert get_path["get"]["summary"] == "获取测试列表"
    assert "测试" in get_path["get"]["tags"]
    
    # 验证POST方法
    post_path = spec["paths"]["/api/test/"]
    assert "post" in post_path
    assert post_path["post"]["summary"] == "创建测试项"
    assert "requestBody" in post_path["post"]
    
    # 验证模式
    assert "TestItem" in spec["components"]["schemas"]
    assert "TestCreateRequest" in spec["components"]["schemas"]
    assert "TestResponse" in spec["components"]["schemas"]


@pytest.mark.asyncio
async def test_openapi_json_endpoint(test_app):
    """测试OpenAPI JSON端点"""
    # 创建测试客户端
    request, response = await test_app.asgi_client.get("/swagger.json")
    
    # 验证响应
    assert response.status == 200
    assert response.content_type == "application/json"
    
    # 解析响应体
    data = json.loads(response.body)
    
    # 验证基本信息
    assert data["info"]["title"] == "Test API"
    assert "paths" in data
    assert "components" in data


@pytest.mark.asyncio
async def test_api_tags_decorator():
    """测试API标签装饰器"""
    @api_tags("标签1", "标签2")
    def test_func():
        pass
    
    assert hasattr(test_func, "__api_spec__")
    assert "tags" in test_func.__api_spec__
    assert test_func.__api_spec__["tags"] == ["标签1", "标签2"]


@pytest.mark.asyncio
async def test_api_summary_decorator():
    """测试API摘要装饰器"""
    @api_summary("测试摘要")
    def test_func():
        pass
    
    assert hasattr(test_func, "__api_spec__")
    assert "summary" in test_func.__api_spec__
    assert test_func.__api_spec__["summary"] == "测试摘要"


@pytest.mark.asyncio
async def test_register_model():
    """测试模型注册"""
    # 清除已注册模型
    from app.docs.models import _schemas
    _schemas.clear()
    
    # 注册模型
    register_model(TestItem)
    
    # 获取模式
    from app.docs.models import get_schemas
    schemas = get_schemas()
    
    # 验证模型注册
    assert "TestItem" in schemas
    assert schemas["TestItem"]["type"] == "object"
    assert "id" in schemas["TestItem"]["properties"]
    assert "name" in schemas["TestItem"]["properties"] 