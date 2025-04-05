#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
示例API模块

演示API文档装饰器的使用方法
"""

from sanic import Blueprint, response
from sanic.request import Request
from pydantic import BaseModel, Field
from typing import List, Optional

from app.docs import (
    api_tags, 
    api_summary, 
    api_description,
    api_body, 
    api_response, 
    api_response_list,
    api_response_pagination,
    api_param, 
    api_paginated_params,
    api_security,
    register_model
)

# 创建蓝图
example_bp = Blueprint("example", url_prefix="/api/examples")

# ===== 模型定义 =====

class ExampleItem(BaseModel):
    """示例数据项模型"""
    id: int = Field(..., description="唯一标识符")
    name: str = Field(..., description="名称")
    description: Optional[str] = Field(None, description="描述")
    is_active: bool = Field(True, description="是否激活")

    class Config:
        schema_extra = {
            "example": {
                "id": 1,
                "name": "示例项目",
                "description": "这是一个示例数据项",
                "is_active": True
            }
        }

class ExampleCreateRequest(BaseModel):
    """示例创建请求模型"""
    name: str = Field(..., description="名称", min_length=2, max_length=50)
    description: Optional[str] = Field(None, description="描述")
    is_active: bool = Field(True, description="是否激活")

class ExampleUpdateRequest(BaseModel):
    """示例更新请求模型"""
    name: Optional[str] = Field(None, description="名称", min_length=2, max_length=50)
    description: Optional[str] = Field(None, description="描述")
    is_active: Optional[bool] = Field(None, description="是否激活")

class ExampleResponse(BaseModel):
    """示例响应模型"""
    success: bool = Field(True, description="操作是否成功")
    data: ExampleItem = Field(..., description="数据项")

class ExampleListResponse(BaseModel):
    """示例列表响应模型"""
    success: bool = Field(True, description="操作是否成功")
    data: List[ExampleItem] = Field(..., description="数据项列表")

class ExamplePaginationResponse(BaseModel):
    """示例分页响应模型"""
    success: bool = Field(True, description="操作是否成功")
    data: dict = Field(..., description="分页数据")

# 注册模型
register_model(ExampleItem)
register_model(ExampleCreateRequest)
register_model(ExampleUpdateRequest)
register_model(ExampleResponse)
register_model(ExampleListResponse)
register_model(ExamplePaginationResponse)

# ===== API端点 =====

@example_bp.route("/", methods=["GET"])
@api_tags("示例")
@api_summary("获取示例列表")
@api_description("获取所有示例数据项的列表")
@api_paginated_params()
@api_param("name", description="按名称过滤")
@api_param("is_active", data_type="boolean", description="按激活状态过滤")
@api_security("BearerAuth")
@api_response_pagination(ExampleItem, description="示例数据分页列表")
async def get_examples(request: Request):
    """
    获取示例列表
    
    返回所有示例数据项，支持分页和过滤
    """
    # 模拟数据
    items = [
        {
            "id": 1,
            "name": "示例1",
            "description": "这是第一个示例",
            "is_active": True
        },
        {
            "id": 2,
            "name": "示例2",
            "description": "这是第二个示例",
            "is_active": True
        },
        {
            "id": 3,
            "name": "示例3",
            "description": "这是第三个示例",
            "is_active": False
        }
    ]
    
    # 构建响应
    return response.json({
        "success": True,
        "data": {
            "items": items,
            "total_count": len(items),
            "page": int(request.args.get("page", 1)),
            "page_size": int(request.args.get("page_size", 10)),
            "total_pages": 1
        }
    })

@example_bp.route("/<example_id:int>", methods=["GET"])
@api_tags("示例")
@api_summary("获取示例详情")
@api_description("根据ID获取特定示例数据项的详情")
@api_param("example_id", param_type="path", data_type="integer", required=True, 
          description="示例ID")
@api_security("BearerAuth")
@api_response(model=ExampleResponse, description="示例数据详情")
@api_response(status_code=404, description="示例数据不存在")
async def get_example_by_id(request: Request, example_id: int):
    """
    获取示例详情
    
    根据ID获取特定示例数据项
    """
    # 模拟数据
    example = {
        "id": example_id,
        "name": f"示例{example_id}",
        "description": f"这是示例{example_id}的详情",
        "is_active": True
    }
    
    # 构建响应
    return response.json({
        "success": True,
        "data": example
    })

@example_bp.route("/", methods=["POST"])
@api_tags("示例")
@api_summary("创建示例")
@api_description("创建新的示例数据项")
@api_body(ExampleCreateRequest, description="示例创建请求")
@api_security("BearerAuth")
@api_response(model=ExampleResponse, status_code=201, description="创建成功，返回新创建的示例")
async def create_example(request: Request):
    """
    创建示例
    
    创建新的示例数据项
    """
    # 从请求体获取数据
    data = request.json
    
    # 模拟创建操作
    new_example = {
        "id": 999,  # 模拟ID
        "name": data.get("name"),
        "description": data.get("description"),
        "is_active": data.get("is_active", True)
    }
    
    # 构建响应
    return response.json({
        "success": True,
        "data": new_example
    }, status=201)

@example_bp.route("/<example_id:int>", methods=["PUT"])
@api_tags("示例")
@api_summary("更新示例")
@api_description("更新指定ID的示例数据项")
@api_param("example_id", param_type="path", data_type="integer", required=True, 
          description="示例ID")
@api_body(ExampleUpdateRequest, description="示例更新请求")
@api_security("BearerAuth")
@api_response(model=ExampleResponse, description="更新成功，返回更新后的示例")
@api_response(status_code=404, description="示例数据不存在")
async def update_example(request: Request, example_id: int):
    """
    更新示例
    
    更新指定ID的示例数据项
    """
    # 从请求体获取数据
    data = request.json
    
    # 模拟更新操作
    updated_example = {
        "id": example_id,
        "name": data.get("name", f"示例{example_id}"),
        "description": data.get("description", f"这是示例{example_id}的详情"),
        "is_active": data.get("is_active", True)
    }
    
    # 构建响应
    return response.json({
        "success": True,
        "data": updated_example
    })

@example_bp.route("/<example_id:int>", methods=["DELETE"])
@api_tags("示例")
@api_summary("删除示例")
@api_description("删除指定ID的示例数据项")
@api_param("example_id", param_type="path", data_type="integer", required=True, 
          description="示例ID")
@api_security("BearerAuth")
@api_response(status_code=204, description="删除成功，无内容返回")
@api_response(status_code=404, description="示例数据不存在")
async def delete_example(request: Request, example_id: int):
    """
    删除示例
    
    删除指定ID的示例数据项
    """
    # 模拟删除操作
    # 实际删除逻辑省略...
    
    # 返回204状态码
    return response.empty(status=204) 