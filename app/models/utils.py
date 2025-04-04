#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
模型工具函数模块，提供通用数据库操作功能
"""
from typing import Type, Dict, Any
from tortoise.models import Model
from tortoise.exceptions import DoesNotExist
from app.services.exceptions import DatabaseOperationError


async def get_or_create_record(model_class: Type[Model], data: Dict[str, Any]):
    """
    获取或创建记录
    
    首先尝试查找匹配的记录，如果不存在则创建新记录
    
    Args:
        model_class: 模型类
        data: 记录数据
        
    Returns:
        模型实例: 获取到的或新创建的记录
        
    Raises:
        DatabaseOperationError: 数据库操作错误
    """
    try:
        # 尝试查找记录
        unique_fields = []
        for field_name, field in model_class._meta.fields_map.items():
            if field.unique and field_name in data:
                unique_fields.append(field_name)
        
        # 如果存在唯一字段，则使用这些字段查询
        if unique_fields:
            query_params = {field: data[field] for field in unique_fields if field in data}
            if query_params:
                try:
                    return await model_class.get(**query_params)
                except DoesNotExist:
                    # 记录不存在，创建新记录
                    return await model_class.create(**data)
        
        # 如果没有唯一字段或查询失败，直接创建新记录
        return await model_class.create(**data)
    except Exception as e:
        raise DatabaseOperationError(f"数据库操作失败: {str(e)}") from e


async def bulk_create_or_update(model_class: Type[Model], data_list: list[Dict[str, Any]], unique_fields: list[str] = None):
    """
    批量创建或更新记录
    
    Args:
        model_class: 模型类
        data_list: 记录数据列表
        unique_fields: 用于确定记录唯一性的字段列表
        
    Returns:
        list: 创建或更新的记录列表
    """
    result = []
    
    if not unique_fields:
        # 如果未指定唯一字段，查找模型中的唯一字段
        unique_fields = []
        for field_name, field in model_class._meta.fields_map.items():
            if field.unique:
                unique_fields.append(field_name)
    
    for data in data_list:
        # 构建查询条件
        query_params = {}
        for field in unique_fields:
            if field in data:
                query_params[field] = data[field]
        
        if query_params:
            # 尝试查找记录
            instance = await model_class.get_or_none(**query_params)
            if instance:
                # 更新记录
                for key, value in data.items():
                    setattr(instance, key, value)
                await instance.save()
                result.append(instance)
                continue
        
        # 创建新记录
        instance = await model_class.create(**data)
        result.append(instance)
    
    return result 