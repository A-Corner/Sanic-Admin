#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
API 基础模块，提供API资源的基类和通用功能
"""

from sanic.views import HTTPMethodView
from sanic.request import Request
from sanic.response import json
from tortoise.exceptions import DoesNotExist
from typing import Type, Dict, Any, List, Optional, Union, Tuple
from app.models.base import BaseModel
from app.services.exceptions import (
    ResourceNotFoundError,
    ValidationError,
    InsufficientPermissionsError
)


class BaseResource(HTTPMethodView):
    """
    API资源基类
    
    所有API资源都应继承此类，提供基本的CRUD操作和响应格式化
    """
    # 关联的数据模型类
    model_class: Type[BaseModel] = None
    
    # 资源名称（用于错误消息和日志）
    resource_name: str = "资源"
    
    # 默认排序字段和方向
    default_sort_field: str = "id"
    default_sort_direction: str = "desc"
    
    # 默认分页参数
    default_page_size: int = 20
    max_page_size: int = 100
    
    # 可搜索字段
    searchable_fields: List[str] = []
    
    # 可过滤字段
    filterable_fields: List[str] = []
    
    @classmethod
    def format_model(cls, model: BaseModel) -> Dict[str, Any]:
        """
        将模型实例格式化为字典
        
        Args:
            model: 模型实例
            
        Returns:
            Dict[str, Any]: 格式化的字典
        """
        if hasattr(model, "to_dict"):
            return model.to_dict()
        
        # 默认转换逻辑
        data = {}
        for field in model._meta.fields:
            data[field] = getattr(model, field)
        
        return data
    
    @classmethod
    def format_models(cls, models: List[BaseModel]) -> List[Dict[str, Any]]:
        """
        将模型实例列表格式化为字典列表
        
        Args:
            models: 模型实例列表
            
        Returns:
            List[Dict[str, Any]]: 格式化的字典列表
        """
        return [cls.format_model(model) for model in models]
    
    @classmethod
    def success_response(cls, data: Any = None, message: str = "操作成功", status: int = 200) -> json:
        """
        生成成功响应
        
        Args:
            data: 响应数据
            message: 成功消息
            status: HTTP状态码
            
        Returns:
            Response: Sanic JSON响应
        """
        return json({
            "success": True,
            "data": data,
            "message": message
        }, status=status)
    
    @classmethod
    def error_response(cls, message: str = "操作失败", status: int = 400, error_code: str = None) -> json:
        """
        生成错误响应
        
        Args:
            message: 错误消息
            status: HTTP状态码
            error_code: 错误代码
            
        Returns:
            Response: Sanic JSON响应
        """
        return json({
            "success": False,
            "error": error_code or "ERROR",
            "message": message
        }, status=status)
    
    @classmethod
    def list_response(cls, 
                      items: List[Dict[str, Any]], 
                      total: int, 
                      page: int, 
                      page_size: int,
                      message: str = "获取成功") -> json:
        """
        生成列表响应
        
        Args:
            items: 项目列表
            total: 总项目数
            page: 当前页码
            page_size: 每页大小
            message: 成功消息
            
        Returns:
            Response: Sanic JSON响应
        """
        return json({
            "success": True,
            "data": {
                "items": items,
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": (total + page_size - 1) // page_size
            },
            "message": message
        })
    
    async def get_model_by_id(self, model_id: Union[int, str]) -> BaseModel:
        """
        通过ID获取模型实例
        
        Args:
            model_id: 模型ID
            
        Returns:
            BaseModel: 模型实例
            
        Raises:
            ResourceNotFoundError: 如果找不到指定ID的资源
        """
        if not self.model_class:
            raise ValueError(f"未指定{self.resource_name}的模型类")
        
        try:
            return await self.model_class.get(id=model_id)
        except DoesNotExist:
            raise ResourceNotFoundError(f"找不到ID为{model_id}的{self.resource_name}")
    
    def get_pagination_params(self, request: Request) -> Tuple[int, int]:
        """
        从请求中获取分页参数
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Tuple[int, int]: (页码, 每页大小)
        """
        try:
            page = int(request.args.get("page", 1))
            page_size = int(request.args.get("page_size", self.default_page_size))
            
            # 验证页码和每页大小
            page = max(1, page)
            page_size = min(max(1, page_size), self.max_page_size)
            
            return page, page_size
        except ValueError:
            return 1, self.default_page_size
    
    def get_sort_params(self, request: Request) -> Tuple[str, str]:
        """
        从请求中获取排序参数
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Tuple[str, str]: (排序字段, 排序方向)
        """
        sort_field = request.args.get("sort_by", self.default_sort_field)
        sort_direction = request.args.get("sort_dir", self.default_sort_direction).lower()
        
        # 验证排序方向
        if sort_direction not in ["asc", "desc"]:
            sort_direction = self.default_sort_direction
        
        return sort_field, sort_direction
    
    def get_search_params(self, request: Request) -> Optional[str]:
        """
        从请求中获取搜索参数
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Optional[str]: 搜索关键词
        """
        return request.args.get("search")
    
    def get_filter_params(self, request: Request) -> Dict[str, Any]:
        """
        从请求中获取过滤参数
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Dict[str, Any]: 过滤参数字典
        """
        filters = {}
        
        for field in self.filterable_fields:
            if field in request.args:
                filters[field] = request.args.get(field)
        
        return filters
    
    async def apply_query_params(self, query, request: Request):
        """
        应用查询参数（分页、排序、搜索、过滤）
        
        Args:
            query: Tortoise查询对象
            request: Sanic请求对象
            
        Returns:
            查询对象和总数
        """
        # 应用过滤
        filters = self.get_filter_params(request)
        for field, value in filters.items():
            query = query.filter(**{field: value})
        
        # 应用搜索
        search = self.get_search_params(request)
        if search and self.searchable_fields:
            search_conditions = []
            for field in self.searchable_fields:
                search_conditions.append(getattr(self.model_class, field).contains(search))
            
            from tortoise.expressions import Q
            search_q = Q(*search_conditions, join_type="OR")
            query = query.filter(search_q)
        
        # 获取总数
        total = await query.count()
        
        # 应用排序
        sort_field, sort_direction = self.get_sort_params(request)
        if sort_direction == "desc":
            query = query.order_by(f"-{sort_field}")
        else:
            query = query.order_by(sort_field)
        
        # 应用分页
        page, page_size = self.get_pagination_params(request)
        offset = (page - 1) * page_size
        query = query.offset(offset).limit(page_size)
        
        return query, total, page, page_size


class CRUDResource(BaseResource):
    """
    CRUD资源基类
    
    提供完整的创建、读取、更新、删除操作
    """
    # 创建和更新时允许的字段
    allowed_create_fields: List[str] = []
    allowed_update_fields: List[str] = []
    
    # 创建和更新时必需的字段
    required_create_fields: List[str] = []
    required_update_fields: List[str] = []
    
    def extract_model_data(self, request: Request, for_update: bool = False) -> Dict[str, Any]:
        """
        从请求中提取模型数据
        
        Args:
            request: Sanic请求对象
            for_update: 是否用于更新操作
            
        Returns:
            Dict[str, Any]: 提取的模型数据
            
        Raises:
            ValidationError: 如果缺少必需字段或提供了不允许的字段
        """
        # 确定允许的字段和必需的字段
        allowed_fields = self.allowed_update_fields if for_update else self.allowed_create_fields
        required_fields = self.required_update_fields if for_update else self.required_create_fields
        
        # 从请求中获取数据
        if request.json:
            data = request.json
        elif request.form:
            data = {key: request.form.get(key) for key in request.form.keys()}
        else:
            data = {}
        
        # 检查必需字段
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            raise ValidationError(f"缺少必需字段: {', '.join(missing_fields)}")
        
        # 过滤允许的字段
        if allowed_fields:
            filtered_data = {k: v for k, v in data.items() if k in allowed_fields}
        else:
            filtered_data = data
        
        return filtered_data
    
    async def get(self, request: Request, resource_id: str = None):
        """
        GET请求处理
        
        获取单个资源或资源列表
        
        Args:
            request: Sanic请求对象
            resource_id: 资源ID，如果不提供则获取列表
            
        Returns:
            Response: Sanic响应
        """
        try:
            if resource_id:
                # 获取单个资源
                model = await self.get_model_by_id(resource_id)
                return self.success_response(
                    data=self.format_model(model),
                    message=f"成功获取{self.resource_name}"
                )
            else:
                # 获取资源列表
                query = self.model_class.all()
                query, total, page, page_size = await self.apply_query_params(query, request)
                
                models = await query
                items = self.format_models(models)
                
                return self.list_response(
                    items=items,
                    total=total,
                    page=page,
                    page_size=page_size,
                    message=f"成功获取{self.resource_name}列表"
                )
        except ResourceNotFoundError as e:
            return self.error_response(message=str(e), status=404, error_code="RESOURCE_NOT_FOUND")
        except Exception as e:
            return self.error_response(message=str(e), status=500, error_code="SERVER_ERROR")
    
    async def post(self, request: Request):
        """
        POST请求处理
        
        创建新资源
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应
        """
        try:
            # 提取并验证数据
            data = self.extract_model_data(request)
            
            # 创建新模型
            model = await self.model_class.create(**data)
            
            return self.success_response(
                data=self.format_model(model),
                message=f"{self.resource_name}创建成功",
                status=201
            )
        except ValidationError as e:
            return self.error_response(message=str(e), status=400, error_code="VALIDATION_ERROR")
        except Exception as e:
            return self.error_response(message=str(e), status=500, error_code="SERVER_ERROR")
    
    async def put(self, request: Request, resource_id: str):
        """
        PUT请求处理
        
        更新资源
        
        Args:
            request: Sanic请求对象
            resource_id: 资源ID
            
        Returns:
            Response: Sanic响应
        """
        try:
            # 获取模型
            model = await self.get_model_by_id(resource_id)
            
            # 提取并验证数据
            data = self.extract_model_data(request, for_update=True)
            
            # 更新模型
            for key, value in data.items():
                setattr(model, key, value)
            
            await model.save()
            
            return self.success_response(
                data=self.format_model(model),
                message=f"{self.resource_name}更新成功"
            )
        except ResourceNotFoundError as e:
            return self.error_response(message=str(e), status=404, error_code="RESOURCE_NOT_FOUND")
        except ValidationError as e:
            return self.error_response(message=str(e), status=400, error_code="VALIDATION_ERROR")
        except Exception as e:
            return self.error_response(message=str(e), status=500, error_code="SERVER_ERROR")
    
    async def patch(self, request: Request, resource_id: str):
        """
        PATCH请求处理
        
        部分更新资源
        
        Args:
            request: Sanic请求对象
            resource_id: 资源ID
            
        Returns:
            Response: Sanic响应
        """
        # 部分更新与完全更新的逻辑相似，但不要求提供所有字段
        return await self.put(request, resource_id)
    
    async def delete(self, request: Request, resource_id: str):
        """
        DELETE请求处理
        
        删除资源
        
        Args:
            request: Sanic请求对象
            resource_id: 资源ID
            
        Returns:
            Response: Sanic响应
        """
        try:
            # 获取模型
            model = await self.get_model_by_id(resource_id)
            
            # 删除模型
            await model.delete()
            
            return self.success_response(
                message=f"{self.resource_name}删除成功"
            )
        except ResourceNotFoundError as e:
            return self.error_response(message=str(e), status=404, error_code="RESOURCE_NOT_FOUND")
        except Exception as e:
            return self.error_response(message=str(e), status=500, error_code="SERVER_ERROR") 