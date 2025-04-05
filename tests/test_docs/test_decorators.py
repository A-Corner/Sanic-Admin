#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
API装饰器测试

测试API文档装饰器功能是否正常工作
"""

import pytest
from pydantic import BaseModel, Field
from typing import Optional, List

from app.docs.decorators import (
    api_tags,
    api_exclude,
    api_summary,
    api_description,
    api_body,
    api_response,
    api_response_list,
    api_response_pagination,
    api_param,
    api_paginated_params,
    api_security
)


class TestModel(BaseModel):
    """测试模型"""
    id: int = Field(..., description="ID")
    name: str = Field(..., description="名称")
    
    
class TestResponseModel(BaseModel):
    """测试响应模型"""
    success: bool = Field(True, description="是否成功")
    data: TestModel = Field(..., description="数据")


def test_api_tags_decorator():
    """测试API标签装饰器"""
    # 应用装饰器
    @api_tags("标签1", "标签2")
    def test_func():
        pass
    
    # 验证装饰器效果
    assert hasattr(test_func, "__api_spec__")
    assert "tags" in test_func.__api_spec__
    assert test_func.__api_spec__["tags"] == ["标签1", "标签2"]


def test_api_exclude_decorator():
    """测试API排除装饰器"""
    # 应用装饰器
    @api_exclude()
    def test_func():
        pass
    
    # 验证装饰器效果
    assert hasattr(test_func, "__api_spec__")
    assert "exclude" in test_func.__api_spec__
    assert test_func.__api_spec__["exclude"] is True


def test_api_summary_decorator():
    """测试API摘要装饰器"""
    # 应用装饰器
    @api_summary("测试摘要")
    def test_func():
        pass
    
    # 验证装饰器效果
    assert hasattr(test_func, "__api_spec__")
    assert "summary" in test_func.__api_spec__
    assert test_func.__api_spec__["summary"] == "测试摘要"


def test_api_description_decorator():
    """测试API描述装饰器"""
    # 应用装饰器
    @api_description("测试描述")
    def test_func():
        pass
    
    # 验证装饰器效果
    assert hasattr(test_func, "__api_spec__")
    assert "description" in test_func.__api_spec__
    assert test_func.__api_spec__["description"] == "测试描述"


def test_api_body_decorator():
    """测试API请求体装饰器"""
    # 应用装饰器
    @api_body(TestModel, description="测试请求体")
    def test_func():
        pass
    
    # 验证装饰器效果
    assert hasattr(test_func, "__api_spec__")
    assert "requestBody" in test_func.__api_spec__
    assert test_func.__api_spec__["requestBody"]["description"] == "测试请求体"
    assert "application/json" in test_func.__api_spec__["requestBody"]["content"]
    schema_ref = test_func.__api_spec__["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    assert schema_ref == "#/components/schemas/TestModel"


def test_api_response_decorator():
    """测试API响应装饰器"""
    # 应用装饰器
    @api_response(model=TestResponseModel, status_code=200, description="测试响应")
    def test_func():
        pass
    
    # 验证装饰器效果
    assert hasattr(test_func, "__api_spec__")
    assert "responses" in test_func.__api_spec__
    assert "200" in test_func.__api_spec__["responses"]
    assert test_func.__api_spec__["responses"]["200"]["description"] == "测试响应"
    
    content = test_func.__api_spec__["responses"]["200"]["content"]
    assert "application/json" in content
    schema_ref = content["application/json"]["schema"]["$ref"]
    assert schema_ref == "#/components/schemas/TestResponseModel"


def test_api_response_list_decorator():
    """测试API列表响应装饰器"""
    # 应用装饰器
    @api_response_list(model=TestModel, status_code=200, description="测试列表响应")
    def test_func():
        pass
    
    # 验证装饰器效果
    assert hasattr(test_func, "__api_spec__")
    assert "responses" in test_func.__api_spec__
    assert "200" in test_func.__api_spec__["responses"]
    
    content = test_func.__api_spec__["responses"]["200"]["content"]
    assert "application/json" in content
    schema = content["application/json"]["schema"]
    assert schema["type"] == "array"
    assert schema["items"]["$ref"] == "#/components/schemas/TestModel"


def test_api_response_pagination_decorator():
    """测试API分页响应装饰器"""
    # 应用装饰器
    @api_response_pagination(model=TestModel, status_code=200, description="测试分页响应")
    def test_func():
        pass
    
    # 验证装饰器效果
    assert hasattr(test_func, "__api_spec__")
    assert "responses" in test_func.__api_spec__
    assert "200" in test_func.__api_spec__["responses"]
    
    content = test_func.__api_spec__["responses"]["200"]["content"]
    assert "application/json" in content
    schema = content["application/json"]["schema"]
    assert "allOf" in schema
    assert len(schema["allOf"]) == 2
    assert schema["allOf"][0]["$ref"] == "#/components/schemas/Pagination"
    assert schema["allOf"][1]["type"] == "object"
    assert "items" in schema["allOf"][1]["properties"]
    assert schema["allOf"][1]["properties"]["items"]["type"] == "array"
    assert schema["allOf"][1]["properties"]["items"]["items"]["$ref"] == "#/components/schemas/TestModel"


def test_api_param_decorator():
    """测试API参数装饰器"""
    # 应用装饰器
    @api_param(
        name="test_param",
        param_type="query",
        data_type="string",
        required=True,
        description="测试参数"
    )
    def test_func():
        pass
    
    # 验证装饰器效果
    assert hasattr(test_func, "__api_spec__")
    assert "parameters" in test_func.__api_spec__
    assert len(test_func.__api_spec__["parameters"]) == 1
    
    param = test_func.__api_spec__["parameters"][0]
    assert param["name"] == "test_param"
    assert param["in"] == "query"
    assert param["required"] is True
    assert param["description"] == "测试参数"
    assert param["schema"]["type"] == "string"


def test_api_paginated_params_decorator():
    """测试API分页参数装饰器"""
    # 应用装饰器
    @api_paginated_params()
    def test_func():
        pass
    
    # 验证装饰器效果
    assert hasattr(test_func, "__api_spec__")
    assert "parameters" in test_func.__api_spec__
    assert len(test_func.__api_spec__["parameters"]) == 2
    
    # 检查page参数
    page_param = next(
        (p for p in test_func.__api_spec__["parameters"] if p["name"] == "page"),
        None
    )
    assert page_param is not None
    assert page_param["in"] == "query"
    assert page_param["schema"]["type"] == "integer"
    
    # 检查page_size参数
    page_size_param = next(
        (p for p in test_func.__api_spec__["parameters"] if p["name"] == "page_size"),
        None
    )
    assert page_size_param is not None
    assert page_size_param["in"] == "query"
    assert page_size_param["schema"]["type"] == "integer"


def test_api_security_decorator():
    """测试API安全装饰器"""
    # 应用装饰器
    @api_security("BearerAuth")
    def test_func():
        pass
    
    # 验证装饰器效果
    assert hasattr(test_func, "__api_spec__")
    assert "security" in test_func.__api_spec__
    assert len(test_func.__api_spec__["security"]) == 1
    assert "BearerAuth" in test_func.__api_spec__["security"][0]


def test_multiple_decorators_combination():
    """测试多个装饰器组合使用"""
    # 应用多个装饰器
    @api_tags("测试")
    @api_summary("测试接口")
    @api_description("这是一个测试接口")
    @api_param("id", param_type="path", required=True, description="ID")
    @api_body(TestModel, description="请求体")
    @api_response(model=TestResponseModel, description="成功响应")
    @api_security("BearerAuth")
    def test_func():
        pass
    
    # 验证装饰器效果
    assert hasattr(test_func, "__api_spec__")
    
    # 验证各个属性
    spec = test_func.__api_spec__
    assert spec["tags"] == ["测试"]
    assert spec["summary"] == "测试接口"
    assert spec["description"] == "这是一个测试接口"
    assert len(spec["parameters"]) == 1
    assert "requestBody" in spec
    assert "responses" in spec
    assert "security" in spec 