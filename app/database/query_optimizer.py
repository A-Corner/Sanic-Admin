#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ORM查询优化器模块

提供Tortoise ORM查询优化工具，包括查询装饰器、预加载关系支持、
优化分页和批量获取功能
"""

import asyncio
import functools
import time
import logging
from typing import Any, Callable, Dict, List, Optional, Set, Type, TypeVar, Union, cast

from tortoise.models import Model
from tortoise.queryset import QuerySet
from tortoise.exceptions import OperationalError

logger = logging.getLogger("app.database")

T = TypeVar('T', bound=Model)
QueryFunction = Callable[..., QuerySet]
ModelType = Type[Model]


def optimize_query(
    prefetch_related_fields: Optional[List[str]] = None,
    select_related_fields: Optional[List[str]] = None,
    limit_fields: Optional[List[str]] = None,
    log_slow_queries: bool = True,
    slow_query_threshold: float = 0.5
):
    """
    查询优化装饰器

    优化Tortoise ORM查询，支持预加载关系、限制字段和慢查询日志

    Args:
        prefetch_related_fields: 需要预加载的多对多或反向关系字段
        select_related_fields: 需要直接选择的外键关系字段
        limit_fields: 限制只查询指定字段，减少数据传输
        log_slow_queries: 是否记录慢查询日志
        slow_query_threshold: 慢查询阈值（秒）

    Returns:
        函数装饰器
    """

    def decorator(func: QueryFunction) -> QueryFunction:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> QuerySet:
            start_time = time.time()
            
            # 执行原始查询函数
            queryset = await func(*args, **kwargs)
            
            if not isinstance(queryset, QuerySet):
                return queryset
            
            # 应用选择相关字段（外键关系）
            if select_related_fields:
                queryset = queryset.select_related(*select_related_fields)
            
            # 应用预加载相关字段（多对多或反向关系）
            if prefetch_related_fields:
                queryset = queryset.prefetch_related(*prefetch_related_fields)
            
            # 应用字段限制
            if limit_fields:
                queryset = queryset.only(*limit_fields)
            
            # 执行查询
            try:
                results = await queryset
                
                # 记录慢查询
                if log_slow_queries:
                    execution_time = time.time() - start_time
                    if execution_time > slow_query_threshold:
                        query_info = {
                            "function": func.__name__,
                            "args": args,
                            "kwargs": kwargs,
                            "execution_time": execution_time,
                            "query": str(queryset.query),
                        }
                        logger.warning(f"慢查询: {query_info}")
                
                return results
            except OperationalError as e:
                logger.error(f"查询执行错误: {str(e)}, 查询: {str(queryset.query)}")
                raise
        
        return cast(QueryFunction, wrapper)
    
    return decorator


async def prefetch_related(
    queryset: QuerySet,
    *relations: str,
    chunk_size: int = 100
) -> List[Model]:
    """
    优化的预加载关系函数

    使用分块加载方式优化大量记录的关系预加载，减少内存使用

    Args:
        queryset: 原始查询集
        relations: 需要预加载的关系
        chunk_size: 每次加载的记录数量

    Returns:
        List[Model]: 预加载关系后的模型列表
    """
    # 克隆查询集以避免修改原始查询
    queryset = queryset.clone()
    
    # 获取总记录数
    total = await queryset.count()
    
    # 如果记录数少于chunk_size，直接使用标准预加载
    if total <= chunk_size:
        return await queryset.prefetch_related(*relations)
    
    # 分块查询并手动预加载关系
    all_results = []
    for offset in range(0, total, chunk_size):
        chunk = await queryset.offset(offset).limit(chunk_size).prefetch_related(*relations)
        all_results.extend(chunk)
    
    return all_results


async def paginate_optimized(
    queryset: QuerySet,
    page: int = 1,
    page_size: int = 10,
    prefetch_fields: Optional[List[str]] = None,
    count_total: bool = True
) -> Dict[str, Any]:
    """
    优化的分页查询函数

    提供高效的分页功能，支持可选的总数计算和关系预加载

    Args:
        queryset: 要分页的查询集
        page: 当前页码，从1开始
        page_size: 每页记录数
        prefetch_fields: 需要预加载的关系字段
        count_total: 是否计算总记录数

    Returns:
        Dict: 包含分页结果的字典
    """
    if page < 1:
        page = 1
    
    offset = (page - 1) * page_size
    
    # 克隆查询集以避免修改原始查询
    paginated_qs = queryset.clone().offset(offset).limit(page_size)
    
    # 应用预加载
    if prefetch_fields:
        paginated_qs = paginated_qs.prefetch_related(*prefetch_fields)
    
    # 异步获取数据和总数（如果需要）
    tasks = [paginated_qs]
    if count_total:
        tasks.append(queryset.count())
    
    results = await asyncio.gather(*tasks)
    
    data = results[0]
    total = results[1] if count_total else None
    
    return {
        "data": data,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size if total else None
        }
    }


async def batch_fetch(
    model_class: Type[Model],
    ids: List[int],
    fields: Optional[List[str]] = None,
    relations: Optional[List[str]] = None,
    batch_size: int = 500
) -> Dict[int, Model]:
    """
    批量获取模型实例

    高效地批量获取模型记录，支持字段限制和关系预加载

    Args:
        model_class: 模型类
        ids: 要获取的ID列表
        fields: 要包含的字段列表
        relations: 要预加载的关系
        batch_size: 每批次处理的ID数量

    Returns:
        Dict[int, Model]: ID到模型实例的映射
    """
    if not ids:
        return {}
    
    # 去重并转换为集合提高性能
    unique_ids = set(ids)
    result_dict = {}
    
    # 分批次处理ID
    for i in range(0, len(unique_ids), batch_size):
        batch_ids = list(unique_ids)[i:i + batch_size]
        
        # 构建查询
        query = model_class.filter(id__in=batch_ids)
        
        # 应用字段限制
        if fields:
            query = query.only(*fields)
        
        # 应用关系预加载
        if relations:
            query = query.prefetch_related(*relations)
        
        # 执行查询并映射结果
        batch_results = await query
        for model in batch_results:
            result_dict[model.id] = model
    
    return result_dict 