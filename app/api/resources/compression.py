#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
响应压缩管理API资源模块

提供响应压缩统计信息和配置管理接口
"""

from sanic import Blueprint
from sanic.response import json
from sanic.exceptions import NotFound, Forbidden

from app.api.base import BaseResource, response
from app.auth.authorization import requires_permission
from app.utils.validator import validate_request
from app.middleware.compression import (
    get_compression_stats,
    configure_compression,
    MIN_COMPRESS_LENGTH,
    DEFAULT_COMPRESSION_LEVEL,
    EXCLUDED_PATHS,
    COMPRESSIBLE_CONTENT_TYPES
)

bp = Blueprint("compression", url_prefix="/api/compression")


class CompressionStatsResource(BaseResource):
    """响应压缩统计资源"""
    
    @requires_permission("system:compression:view")
    async def get(self, request):
        """
        获取响应压缩统计信息
        
        返回压缩统计数据，包括压缩率、节省的带宽等信息
        """
        stats = get_compression_stats()
        
        # 添加当前配置信息
        stats["configuration"] = {
            "min_compress_length": MIN_COMPRESS_LENGTH,
            "compression_level": DEFAULT_COMPRESSION_LEVEL,
            "excluded_paths": EXCLUDED_PATHS,
            "compressible_types": list(COMPRESSIBLE_CONTENT_TYPES)
        }
        
        return response(data=stats)


class CompressionConfigResource(BaseResource):
    """响应压缩配置资源"""
    
    @requires_permission("system:compression:manage")
    @validate_request(json={
        "min_length": {"type": "integer", "min": 0, "nullable": True},
        "compression_level": {"type": "integer", "min": 0, "max": 9, "nullable": True},
        "exclude_paths": {"type": "list", "schema": {"type": "string"}, "nullable": True},
        "compressible_types": {"type": "list", "schema": {"type": "string"}, "nullable": True}
    })
    async def put(self, request):
        """
        更新响应压缩配置
        
        更新压缩中间件的配置参数，如压缩阈值、压缩级别等
        """
        # 获取当前应用实例
        app = request.app
        
        # 提取配置参数
        min_length = request.json.get("min_length")
        compression_level = request.json.get("compression_level")
        exclude_paths = request.json.get("exclude_paths")
        compressible_types = request.json.get("compressible_types")
        
        # 转换为集合
        if compressible_types:
            compressible_types = set(compressible_types)
        
        # 重新配置压缩中间件
        configure_compression(
            app,
            min_length=min_length if min_length is not None else MIN_COMPRESS_LENGTH,
            compression_level=compression_level if compression_level is not None else DEFAULT_COMPRESSION_LEVEL,
            exclude_paths=exclude_paths,
            compressible_types=compressible_types
        )
        
        # 返回更新后的统计信息
        stats = get_compression_stats()
        stats["configuration"] = {
            "min_compress_length": MIN_COMPRESS_LENGTH,
            "compression_level": DEFAULT_COMPRESSION_LEVEL,
            "excluded_paths": EXCLUDED_PATHS,
            "compressible_types": list(COMPRESSIBLE_CONTENT_TYPES)
        }
        
        return response(data=stats, message="响应压缩配置已更新")


# 注册路由
bp.add_route(CompressionStatsResource.as_view(), "/stats")
bp.add_route(CompressionConfigResource.as_view(), "/config") 