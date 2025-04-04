#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
工具函数模块，提供各种通用功能
"""
import datetime
import random
import string
from sanic.request import Request
from sanic.response import json as json_response
from typing import Dict, Any, Optional, Union


def get_ip(request: Request) -> str:
    """
    获取请求的真实IP地址
    
    尝试从X-Forwarded-For头、X-Real-IP头或request.ip获取
    
    Args:
        request: Sanic请求对象
        
    Returns:
        str: IP地址
    """
    # 先尝试从X-Forwarded-For获取（通常在负载均衡器或反向代理后面）
    if request.headers.get("X-Forwarded-For"):
        # X-Forwarded-For格式: client, proxy1, proxy2, ...
        # 取第一个地址，即客户端真实IP
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    
    # 尝试从X-Real-IP获取
    if request.headers.get("X-Real-IP"):
        return request.headers.get("X-Real-IP")
    
    # 最后使用请求的直接IP
    return request.ip


def get_code(length: int = 6) -> str:
    """
    生成随机验证码
    
    Args:
        length: 验证码长度，默认为6
        
    Returns:
        str: 随机验证码
    """
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))


def get_expiration_date(seconds: int) -> datetime.datetime:
    """
    获取未来的过期时间
    
    Args:
        seconds: 从现在起多少秒后过期
        
    Returns:
        datetime: 过期时间
    """
    return datetime.datetime.now() + datetime.timedelta(seconds=seconds)


def json(
    message: str,
    data: Optional[Union[Dict[str, Any], list]] = None,
    status: int = 200
) -> json_response:
    """
    创建标准格式的JSON响应
    
    Args:
        message: 响应消息
        data: 响应数据，可以是字典或列表
        status: HTTP状态码，默认为200
        
    Returns:
        JSONResponse: JSON响应对象
    """
    return json_response(
        {
            "status": 0 if status < 400 else 1,
            "msg": message,
            "data": data or {}
        },
        status=status
    )


def format_datetime(dt: datetime.datetime) -> str:
    """
    格式化日期时间为标准字符串
    
    Args:
        dt: 日期时间对象
        
    Returns:
        str: 格式化的日期时间字符串
    """
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def parse_datetime(dt_str: str) -> Optional[datetime.datetime]:
    """
    解析日期时间字符串为日期时间对象
    
    Args:
        dt_str: 日期时间字符串
        
    Returns:
        datetime: 日期时间对象，解析失败则返回None
    """
    if not dt_str:
        return None
    
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d",
    ]
    
    for format_str in formats:
        try:
            return datetime.datetime.strptime(dt_str, format_str)
        except ValueError:
            continue
    
    return None 