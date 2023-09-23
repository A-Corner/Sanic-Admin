# Encoding: UTF-8
# 导入所需的模块
from typing import Optional
import random
import string
from datetime import datetime, timedelta, timezone
from sanic.request import Request
from sanic.response import json as sanic_json, HTTPResponse

# 从客户端请求中获取 IP 地址


def get_ip(request: Request) -> str:
    """
    Get the IP address from the client request.
    从客户端请求中获取 IP 地址。
    Args:
        request (Request): Sanic request object.
    Returns:
        ip
    """
    return request.remote_addr or request.ip

# 生成随机验证码用于验证


def get_code() -> str:
    """
    Generate a random verification code for validation.
    生成随机验证码，用于验证。
    Returns:
        code
    """
    return "".join(random.choices(string.digits + string.ascii_uppercase, k=6))

# 创建预格式化的 Sanic JSON 响应


def json(message: str, data, status_code: int = 200) -> HTTPResponse:
    """
    Create a pre-formatted Sanic JSON response.
    创建预格式化的 Sanic JSON 响应。
    Args:
        message (int): A message describing the data or conveying human-readable information.
        data (Any): The raw information to be used by the client.
        status_code (int): The HTTP response code.
    Returns:
        json
    """
    return sanic_json(
        {"message": message, "code": status_code, "data": data}, status=status_code
    )

# 获取过期日期


def get_expiration_date(seconds: int) -> Optional[datetime]:
    """
    Get the expiration date for something like a session.
    获取某物（如会话）不再有效的日期。
    Args:
        seconds: The number of seconds to add to the current time.
    Returns:
        expiration_date
    """
    # Calculate the expiration date for something (e.g., a session).
    return (
        datetime.now(timezone.utc) + timedelta(seconds=seconds)
        if seconds > 0
        else None
    )
