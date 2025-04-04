#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
响应压缩中间件模块

提供Gzip响应压缩功能，显著减少API响应体积，加快数据传输速度
"""

import gzip
import zlib
import time
from typing import Dict, Any, List, Optional, Set, Callable
from functools import wraps
import re
import logging
from io import BytesIO
from sanic import Sanic, Request, Response

# 最小压缩阈值，小于此值的响应不会被压缩
MIN_COMPRESS_LENGTH = 1024  # 1KB

# 默认压缩级别 (0-9)，级别越高压缩率越好但CPU占用越高
DEFAULT_COMPRESSION_LEVEL = 6

# 保存压缩统计
_compression_stats = {
    "compressed_responses": 0,
    "uncompressed_responses": 0,
    "total_original_size": 0,
    "total_compressed_size": 0,
    "avg_compression_ratio": 0,
    "min_compression_ratio": float('inf'),
    "max_compression_ratio": 0,
    "avg_compression_time": 0,
    "total_requests": 0
}

# 可压缩的内容类型
COMPRESSIBLE_CONTENT_TYPES = {
    'text/plain',
    'text/html',
    'text/css',
    'text/xml',
    'text/javascript',
    'application/javascript',
    'application/json',
    'application/xml',
    'application/xhtml+xml',
    'application/rss+xml',
    'application/atom+xml',
    'application/x-javascript',
    'application/x-httpd-php',
    'application/x-httpd-fastphp',
    'application/x-httpd-eruby'
}

# 不进行压缩的URL路径模式
EXCLUDED_PATHS = [
    r'^/static/',
    r'^/media/',
    r'^/uploads/',
    r'^/favicon\.ico$'
]

# 编译正则表达式
EXCLUDED_PATHS_REGEX = [re.compile(pattern) for pattern in EXCLUDED_PATHS]

logger = logging.getLogger('app.middleware.compression')


def should_compress(request: Request, response: Response) -> bool:
    """
    判断响应是否应该被压缩
    
    Args:
        request: Sanic请求对象
        response: Sanic响应对象
        
    Returns:
        bool: 是否应该压缩
    """
    # 检查响应大小
    if len(response.body) < MIN_COMPRESS_LENGTH:
        return False
    
    # 检查Content-Type
    content_type = response.content_type
    if content_type:
        base_content_type = content_type.split(';')[0].lower().strip()
        if base_content_type not in COMPRESSIBLE_CONTENT_TYPES:
            return False
    
    # 检查请求头是否支持压缩
    accept_encoding = request.headers.get('Accept-Encoding', '')
    if 'gzip' not in accept_encoding:
        return False
    
    # 检查响应是否已压缩
    if response.headers.get('Content-Encoding'):
        return False
    
    # 检查排除路径
    path = request.path
    for pattern in EXCLUDED_PATHS_REGEX:
        if pattern.match(path):
            return False
    
    return True


def compress_response(response: Response, level: int = DEFAULT_COMPRESSION_LEVEL) -> Response:
    """
    使用gzip压缩响应内容
    
    Args:
        response: 原始响应对象
        level: 压缩级别 (0-9)
        
    Returns:
        Response: 压缩后的响应对象
    """
    original_size = len(response.body)
    
    # 计时开始
    start_time = time.time()
    
    # 使用gzip压缩
    buffer = BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb', compresslevel=level) as gz:
        if isinstance(response.body, str):
            gz.write(response.body.encode())
        else:
            gz.write(response.body)
    
    # 获取压缩结果
    compressed_body = buffer.getvalue()
    compression_time = time.time() - start_time
    compressed_size = len(compressed_body)
    
    # 更新响应
    response.body = compressed_body
    response.headers['Content-Encoding'] = 'gzip'
    response.headers['Content-Length'] = str(compressed_size)
    response.headers['Vary'] = 'Accept-Encoding'
    
    # 计算压缩率
    compression_ratio = (original_size - compressed_size) / original_size * 100 if original_size > 0 else 0
    
    # 更新统计信息
    global _compression_stats
    _compression_stats["compressed_responses"] += 1
    _compression_stats["total_original_size"] += original_size
    _compression_stats["total_compressed_size"] += compressed_size
    
    # 更新平均压缩率
    total_compressed = _compression_stats["compressed_responses"]
    _compression_stats["avg_compression_ratio"] = (
        (_compression_stats["avg_compression_ratio"] * (total_compressed - 1) + compression_ratio) / 
        total_compressed
    )
    
    # 更新最大和最小压缩率
    if compression_ratio > _compression_stats["max_compression_ratio"]:
        _compression_stats["max_compression_ratio"] = compression_ratio
    if compression_ratio < _compression_stats["min_compression_ratio"]:
        _compression_stats["min_compression_ratio"] = compression_ratio
    
    # 更新平均压缩时间
    _compression_stats["avg_compression_time"] = (
        (_compression_stats["avg_compression_time"] * (total_compressed - 1) + compression_time) / 
        total_compressed
    )
    
    return response


async def compression_middleware(request: Request, response: Response) -> Response:
    """
    响应压缩中间件
    
    根据请求和响应内容自动决定是否压缩响应
    
    Args:
        request: Sanic请求对象
        response: Sanic响应对象
        
    Returns:
        Response: 处理后的响应对象
    """
    # 增加请求总数统计
    _compression_stats["total_requests"] += 1
    
    # 检查是否应该压缩
    if should_compress(request, response):
        try:
            return compress_response(response)
        except Exception as e:
            logger.error(f"响应压缩失败: {str(e)}")
            # 出错时不压缩，返回原始响应
            _compression_stats["uncompressed_responses"] += 1
            return response
    else:
        # 不需要压缩时记录为未压缩
        _compression_stats["uncompressed_responses"] += 1
        return response


def configure_compression(
    app: Sanic,
    min_length: int = MIN_COMPRESS_LENGTH,
    compression_level: int = DEFAULT_COMPRESSION_LEVEL,
    exclude_paths: Optional[List[str]] = None,
    compressible_types: Optional[Set[str]] = None
) -> None:
    """
    配置并注册响应压缩中间件
    
    Args:
        app: Sanic应用实例
        min_length: 最小压缩阈值
        compression_level: 压缩级别 (0-9)
        exclude_paths: 排除的URL路径模式
        compressible_types: 可压缩的内容类型
    """
    global MIN_COMPRESS_LENGTH, DEFAULT_COMPRESSION_LEVEL
    global EXCLUDED_PATHS, EXCLUDED_PATHS_REGEX
    global COMPRESSIBLE_CONTENT_TYPES
    
    # 更新配置
    MIN_COMPRESS_LENGTH = min_length
    DEFAULT_COMPRESSION_LEVEL = compression_level
    
    if exclude_paths:
        EXCLUDED_PATHS = exclude_paths
        EXCLUDED_PATHS_REGEX = [re.compile(pattern) for pattern in EXCLUDED_PATHS]
    
    if compressible_types:
        COMPRESSIBLE_CONTENT_TYPES = compressible_types
    
    # 注册中间件
    app.middleware('response')(compression_middleware)
    
    logger.info(f"已启用响应压缩中间件 (最小阈值: {min_length}字节, 压缩级别: {compression_level})")


def get_compression_stats() -> Dict[str, Any]:
    """
    获取压缩统计信息
    
    Returns:
        Dict[str, Any]: 压缩统计数据
    """
    stats = _compression_stats.copy()
    
    # 计算总体压缩率
    if stats["total_original_size"] > 0:
        stats["overall_compression_ratio"] = (
            (stats["total_original_size"] - stats["total_compressed_size"]) / 
            stats["total_original_size"] * 100
        )
    else:
        stats["overall_compression_ratio"] = 0
    
    # 计算压缩率
    if stats["total_requests"] > 0:
        stats["compression_rate"] = (
            stats["compressed_responses"] / stats["total_requests"] * 100
        )
    else:
        stats["compression_rate"] = 0
    
    # 计算总节省的带宽
    stats["total_bytes_saved"] = stats["total_original_size"] - stats["total_compressed_size"]
    
    return stats 