#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
API响应模块，提供统一的API响应格式和序列化功能
"""

from sanic.response import json
from typing import Any, Dict, List, Optional, Union
import datetime
import decimal
from tortoise.models import Model
import json as json_lib


class APIResponse:
    """
    API响应工具类
    
    提供统一的API响应格式和序列化方法
    """
    
    @staticmethod
    def success(data: Any = None, message: str = "操作成功", status_code: int = 200) -> json:
        """
        生成成功响应
        
        Args:
            data: 响应数据，将自动序列化
            message: 成功消息
            status_code: HTTP状态码
            
        Returns:
            json: Sanic JSON响应
        """
        return json({
            "success": True,
            "message": message,
            "data": APIResponse.serialize(data)
        }, status=status_code)
    
    @staticmethod
    def error(message: str = "操作失败", error_code: str = "ERROR", status_code: int = 400, 
              details: Any = None) -> json:
        """
        生成错误响应
        
        Args:
            message: 错误消息
            error_code: 错误代码
            status_code: HTTP状态码
            details: 错误详情，可选
            
        Returns:
            json: Sanic JSON响应
        """
        response = {
            "success": False,
            "message": message,
            "error": error_code
        }
        
        if details:
            response["details"] = APIResponse.serialize(details)
        
        return json(response, status=status_code)
    
    @staticmethod
    def list(items: List[Any], total: int, page: int = 1, page_size: int = 20, 
             message: str = "获取列表成功") -> json:
        """
        生成列表响应
        
        Args:
            items: 列表项目
            total: 总项目数
            page: 当前页码
            page_size: 每页大小
            message: 成功消息
            
        Returns:
            json: Sanic JSON响应
        """
        # 计算总页数
        total_pages = (total + page_size - 1) // page_size if page_size > 0 else 0
        
        return json({
            "success": True,
            "message": message,
            "data": {
                "items": APIResponse.serialize(items),
                "pagination": {
                    "total": total,
                    "page": page,
                    "page_size": page_size,
                    "total_pages": total_pages
                }
            }
        })
    
    @staticmethod
    def paginated_list(items: List[Any], total: int, page: int = 1, page_size: int = 20, 
                      extra_data: Dict[str, Any] = None, message: str = "获取列表成功") -> json:
        """
        生成带有额外数据的分页列表响应
        
        Args:
            items: 列表项目
            total: 总项目数
            page: 当前页码
            page_size: 每页大小
            extra_data: 额外的响应数据
            message: 成功消息
            
        Returns:
            json: Sanic JSON响应
        """
        response = {
            "success": True,
            "message": message,
            "data": {
                "items": APIResponse.serialize(items),
                "pagination": {
                    "total": total,
                    "page": page,
                    "page_size": page_size,
                    "total_pages": (total + page_size - 1) // page_size if page_size > 0 else 0
                }
            }
        }
        
        if extra_data:
            response["data"].update(APIResponse.serialize(extra_data))
        
        return json(response)
    
    @staticmethod
    def empty(message: str = "操作成功", status_code: int = 204) -> json:
        """
        生成空响应
        
        Args:
            message: 成功消息
            status_code: HTTP状态码
            
        Returns:
            json: Sanic JSON响应
        """
        return json({
            "success": True,
            "message": message
        }, status=status_code)
    
    @staticmethod
    def created(data: Any = None, message: str = "创建成功", location: str = None) -> json:
        """
        生成资源创建成功响应
        
        Args:
            data: 创建的资源数据
            message: 成功消息
            location: 新资源的位置URI
            
        Returns:
            json: Sanic JSON响应，状态码201
        """
        response = {
            "success": True,
            "message": message,
            "data": APIResponse.serialize(data)
        }
        
        if location:
            response["location"] = location
        
        return json(response, status=201)
    
    @staticmethod
    def serialize(data: Any) -> Any:
        """
        序列化数据为JSON可序列化的格式
        
        支持Tortoise模型、日期时间、小数等特殊类型
        
        Args:
            data: 要序列化的数据
            
        Returns:
            Any: 序列化后的数据
        """
        if data is None:
            return None
        
        # 处理模型实例
        if isinstance(data, Model):
            if hasattr(data, "to_dict"):
                return APIResponse.serialize(data.to_dict())
            else:
                # 默认转换逻辑
                result = {}
                for field in data._meta.fields:
                    result[field] = getattr(data, field)
                return APIResponse.serialize(result)
        
        # 处理模型列表
        if isinstance(data, list):
            return [APIResponse.serialize(item) for item in data]
        
        # 处理字典
        if isinstance(data, dict):
            return {k: APIResponse.serialize(v) for k, v in data.items()}
        
        # 处理日期和时间
        if isinstance(data, (datetime.datetime, datetime.date)):
            return data.isoformat()
        
        # 处理时间间隔
        if isinstance(data, datetime.timedelta):
            return str(data)
        
        # 处理小数
        if isinstance(data, decimal.Decimal):
            return float(data)
        
        # 处理集合
        if isinstance(data, set):
            return [APIResponse.serialize(item) for item in data]
        
        # 处理bytes
        if isinstance(data, bytes):
            return data.decode('utf-8')
        
        # 其他基本类型直接返回
        return data
    
    @staticmethod
    def json_dumps(data: Any) -> str:
        """
        将数据转换为JSON字符串
        
        Args:
            data: 要转换的数据
            
        Returns:
            str: JSON字符串
        """
        return json_lib.dumps(APIResponse.serialize(data), ensure_ascii=False)


class APIError:
    """
    API错误代码
    
    定义标准化的API错误代码
    """
    # 通用错误
    BAD_REQUEST = "BAD_REQUEST"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    CONFLICT = "CONFLICT"
    GONE = "GONE"
    SERVER_ERROR = "SERVER_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    
    # 认证和授权错误
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    INVALID_TOKEN = "INVALID_TOKEN"
    INSUFFICIENT_PERMISSIONS = "INSUFFICIENT_PERMISSIONS"
    
    # 资源错误
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    RESOURCE_EXISTS = "RESOURCE_EXISTS"
    RESOURCE_GONE = "RESOURCE_GONE"
    INVALID_RESOURCE_STATE = "INVALID_RESOURCE_STATE"
    
    # 输入错误
    MISSING_PARAMETER = "MISSING_PARAMETER"
    INVALID_PARAMETER = "INVALID_PARAMETER"
    UNSUPPORTED_PARAMETER = "UNSUPPORTED_PARAMETER"
    
    # 数据库错误
    DATABASE_ERROR = "DATABASE_ERROR"
    CONSTRAINT_VIOLATION = "CONSTRAINT_VIOLATION"
    
    # 限制错误
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    
    # 文件错误
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    INVALID_FILE_TYPE = "INVALID_FILE_TYPE"
    FILE_UPLOAD_ERROR = "FILE_UPLOAD_ERROR" 