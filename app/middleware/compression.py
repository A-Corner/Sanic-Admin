#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
响应压缩中间件模块

提供Gzip响应压缩功能，显著减少API响应体积，加快数据传输速度
"""

import gzip
import zlib
import time
import math
import decimal
from typing import Dict, Any, List, Optional, Set, Callable
from functools import wraps
import re
import logging
from io import BytesIO
from sanic import Sanic, Request
from sanic.response import HTTPResponse as Response
from app.middleware._headers import append_vary

# 最小压缩阈值，小于此值的响应不会被压缩
MIN_COMPRESS_LENGTH = 1024  # 1KB

# 默认压缩级别 (0-9)，级别越高压缩率越好但CPU占用越高
DEFAULT_COMPRESSION_LEVEL = 6

# 保存压缩统计
# min_compression_ratio 初始为 None：表示"尚无任何响应被压缩过"。
# 绝不能用 float('inf') 表示无数据 —— Infinity 不是标准 JSON（RFC 8259 只允许
# null/true/false/数字/字符串/数组/对象），会污染 API 响应体：浏览器 JSON.parse()
# 直接抛错，Go / Rust / Java 的严格解析器同样拒绝。
_compression_stats = {
    "compressed_responses": 0,
    "uncompressed_responses": 0,
    "total_original_size": 0,
    "total_compressed_size": 0,
    "avg_compression_ratio": 0,
    "min_compression_ratio": None,
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


def _sanitize_non_finite(value: Any) -> Any:
    """
    递归清洗统计值，保证结果是严格合法 JSON（RFC 8259）。

    非有限数值（``inf`` / ``-inf`` / ``nan``，含 ``Decimal`` 的 ``Infinity`` /
    ``NaN``）统一转成 ``None``（JSON ``null``），其余结构原样保留。

    这是 ``get_compression_stats()`` 出口处的防御：即使内部统计状态因异常路径
    演化出非有限值（例如除零、异常耗时），也不会让 ``Infinity`` 字面量漏进
    API 响应体导致浏览器 ``JSON.parse()`` 抛错。

    Args:
        value: 任意待清洗的值

    Returns:
        Any: 保证可被标准 JSON 序列化的等价结构
    """
    # bool 是 int 的子类，但 JSON 原生支持 true/false，直接原样返回
    if isinstance(value, bool) or value is None:
        return value

    # 浮点数：非有限值（inf / -inf / nan）转 None
    if isinstance(value, float):
        return value if math.isfinite(value) else None

    # Decimal：非有限值（Infinity / NaN）转 None；有限值转 float 便于序列化
    if isinstance(value, decimal.Decimal):
        if not value.is_finite():
            return None
        converted = float(value)
        return converted if math.isfinite(converted) else None

    # 整数：JSON 原生支持，原样返回
    if isinstance(value, int):
        return value

    # 字典：递归清洗值
    if isinstance(value, dict):
        return {key: _sanitize_non_finite(item) for key, item in value.items()}

    # 列表 / 元组：递归清洗元素
    if isinstance(value, (list, tuple)):
        return [_sanitize_non_finite(item) for item in value]

    # bytes：解码为字符串
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')

    # 其他类型（str / 自定义对象等）原样返回
    return value


def should_compress(request: Request, response: Response) -> bool:
    """
    判断响应是否应该被压缩
    
    Args:
        request: Sanic请求对象
        response: Sanic响应对象
        
    Returns:
        bool: 是否应该压缩
    """
    # 检查响应大小（流式/文件响应没有内存中的 body，不压缩）
    if not response.body or len(response.body) < MIN_COMPRESS_LENGTH:
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
    append_vary(response.headers, 'Accept-Encoding')
    
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
    # min 初始为 None（尚无压缩记录），第一次压缩时直接落值；之后才做比较。
    current_min = _compression_stats["min_compression_ratio"]
    if current_min is None or compression_ratio < current_min:
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
        None: 响应被原地修改；返回响应对象会使 Sanic 跳过其余响应中间件（如 CORS 头）
    """
    # 增加请求总数统计
    _compression_stats["total_requests"] += 1
    
    # 检查是否应该压缩
    if should_compress(request, response):
        try:
            compress_response(response)  # 原地修改 response
            return None
        except Exception as e:
            logger.error(f"响应压缩失败: {str(e)}")
            # 出错时不压缩，返回原始响应
            _compression_stats["uncompressed_responses"] += 1
            return None
    else:
        # 不需要压缩时记录为未压缩
        _compression_stats["uncompressed_responses"] += 1
        return None


def update_compression_options(
    min_length: int = None,
    compression_level: int = None,
    exclude_paths: Optional[List[str]] = None,
    compressible_types: Optional[Set[str]] = None
) -> None:
    """
    更新压缩参数（只改配置，不注册中间件，可重复调用）

    Raises:
        re.error: exclude_paths 中含不合法的正则时抛出，此时不修改任何配置
    """
    global MIN_COMPRESS_LENGTH, DEFAULT_COMPRESSION_LEVEL
    global EXCLUDED_PATHS, EXCLUDED_PATHS_REGEX
    global COMPRESSIBLE_CONTENT_TYPES

    compiled = [re.compile(pattern) for pattern in exclude_paths] if exclude_paths else None

    if min_length is not None:
        MIN_COMPRESS_LENGTH = min_length
    if compression_level is not None:
        DEFAULT_COMPRESSION_LEVEL = compression_level
    if compiled is not None:
        EXCLUDED_PATHS = list(exclude_paths)
        EXCLUDED_PATHS_REGEX = compiled
    if compressible_types:
        COMPRESSIBLE_CONTENT_TYPES = set(compressible_types)


def configure_compression(
    app: Sanic,
    min_length: int = MIN_COMPRESS_LENGTH,
    compression_level: int = DEFAULT_COMPRESSION_LEVEL,
    exclude_paths: Optional[List[str]] = None,
    compressible_types: Optional[Set[str]] = None
) -> None:
    """
    配置并向应用注册响应压缩中间件（每个应用只注册一次；运行期调参请用 update_compression_options）

    Args:
        app: Sanic应用实例
        min_length: 最小压缩阈值
        compression_level: 压缩级别 (0-9)
        exclude_paths: 排除的URL路径模式
        compressible_types: 可压缩的内容类型
    """
    update_compression_options(min_length, compression_level, exclude_paths, compressible_types)

    if not getattr(app.ctx, "_compression_registered", False):
        app.middleware('response')(compression_middleware)
        app.ctx._compression_registered = True

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
    
    # 出口处清洗：确保返回的是严格合法 JSON，不含 Infinity / NaN 字面量
    return _sanitize_non_finite(stats) 