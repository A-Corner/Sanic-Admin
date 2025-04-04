#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
数据库连接池管理模块

提供数据库连接池配置、管理和监控功能
"""

import logging
import asyncio
import time
from typing import Dict, Any, Optional, List
from contextlib import asynccontextmanager

from tortoise import Tortoise
from tortoise.backends.base.client import BaseDBAsyncClient
from tortoise.exceptions import OperationalError

logger = logging.getLogger("app.database")

# 连接池全局配置
_pool_options = {
    "min_size": 5,       # 最小连接数
    "max_size": 20,      # 最大连接数
    "max_idle_time": 300,  # 最大空闲时间(秒)
    "connect_timeout": 10.0,  # 连接超时时间(秒)
    "echo": False,       # 是否记录SQL语句
    "retry_limit": 3,    # 连接重试次数
    "retry_interval": 1.0,  # 重试间隔(秒)
}

# 连接池状态
_pool_stats = {
    "created_at": None,            # 创建时间
    "total_connections": 0,        # 总连接数
    "active_connections": 0,       # 活跃连接数
    "idle_connections": 0,         # 空闲连接数
    "wait_count": 0,               # 等待次数
    "max_wait_time": 0.0,          # 最大等待时间
    "connection_timeouts": 0,      # 连接超时次数
    "connection_errors": 0,        # 连接错误次数
    "last_health_check": None,     # 最后健康检查时间
    "is_healthy": True,            # 是否健康
}

# 锁，防止并发修改
_pool_lock = asyncio.Lock()
# 健康检查任务
_health_check_task = None


def set_pool_options(**options) -> Dict[str, Any]:
    """
    设置连接池选项

    Args:
        **options: 连接池配置选项

    Returns:
        Dict[str, Any]: 更新后的连接池选项
    """
    global _pool_options
    
    for key, value in options.items():
        if key in _pool_options:
            _pool_options[key] = value
    
    # 如果Tortoise已初始化，应用新的连接池设置
    if Tortoise._inited:
        _apply_pool_options()
    
    return _pool_options


def _apply_pool_options() -> None:
    """
    应用连接池选项到当前连接
    """
    # 获取当前所有连接
    for conn_name, conn in Tortoise._connections.items():
        if hasattr(conn, '_pool'):
            # 根据数据库后端类型设置池选项
            if conn.capabilities.dialect == "mysql":
                _set_mysql_pool_options(conn)
            elif conn.capabilities.dialect == "postgres":
                _set_postgres_pool_options(conn)
            elif conn.capabilities.dialect == "sqlite":
                # SQLite不支持真正的连接池
                pass


def _set_mysql_pool_options(conn: BaseDBAsyncClient) -> None:
    """
    设置MySQL连接池选项

    Args:
        conn: MySQL数据库连接
    """
    if hasattr(conn, '_pool'):
        conn._pool_params = {
            "minsize": _pool_options["min_size"],
            "maxsize": _pool_options["max_size"],
            "pool_recycle": _pool_options["max_idle_time"],
            "echo": _pool_options["echo"],
            "connect_timeout": _pool_options["connect_timeout"],
        }


def _set_postgres_pool_options(conn: BaseDBAsyncClient) -> None:
    """
    设置PostgreSQL连接池选项

    Args:
        conn: PostgreSQL数据库连接
    """
    if hasattr(conn, '_pool'):
        conn._pool_params = {
            "min_size": _pool_options["min_size"],
            "max_size": _pool_options["max_size"],
            "max_inactive_connection_lifetime": _pool_options["max_idle_time"],
            "connection_timeout": _pool_options["connect_timeout"],
            "statement_cache_size": 1000,
        }


async def get_connection_pool() -> Dict[str, Any]:
    """
    获取连接池信息和状态

    Returns:
        Dict[str, Any]: 连接池状态信息
    """
    if not Tortoise._inited:
        return {
            "status": "not_initialized",
            "options": _pool_options,
            "stats": None
        }
    
    # 更新连接池统计信息
    await _update_pool_stats()
    
    connections_info = {}
    for conn_name, conn in Tortoise._connections.items():
        if hasattr(conn, '_pool'):
            connections_info[conn_name] = {
                "dialect": conn.capabilities.dialect,
                "pool_size": getattr(conn._pool, 'size', 0) if hasattr(conn, '_pool') else 0,
                "min_size": getattr(conn._pool, 'minsize', 0) if hasattr(conn, '_pool') else 0,
                "max_size": getattr(conn._pool, 'maxsize', 0) if hasattr(conn, '_pool') else 0,
                "freesize": getattr(conn._pool, 'freesize', 0) if hasattr(conn, '_pool') else 0,
            }
    
    return {
        "status": "initialized",
        "options": _pool_options,
        "stats": _pool_stats,
        "connections": connections_info
    }


async def _update_pool_stats() -> None:
    """
    更新连接池统计信息
    """
    global _pool_stats
    
    async with _pool_lock:
        # 设置创建时间（如果未设置）
        if _pool_stats["created_at"] is None:
            _pool_stats["created_at"] = time.time()
        
        # 更新统计数据
        total_connections = 0
        active_connections = 0
        idle_connections = 0
        
        for conn_name, conn in Tortoise._connections.items():
            if hasattr(conn, '_pool'):
                # 基于连接池类型获取统计信息
                pool = conn._pool
                if hasattr(pool, 'size'):
                    total_connections += pool.size
                if hasattr(pool, 'freesize'):
                    idle_connections += pool.freesize
        
        active_connections = total_connections - idle_connections
        
        _pool_stats.update({
            "total_connections": total_connections,
            "active_connections": active_connections,
            "idle_connections": idle_connections,
            "last_health_check": time.time(),
        })


@asynccontextmanager
async def connection_context(conn_name: str = "default", timeout: float = 5.0):
    """
    数据库连接上下文管理器
    
    提供带超时和重试的数据库连接

    Args:
        conn_name: 连接名称
        timeout: 连接获取超时时间(秒)

    Yields:
        BaseDBAsyncClient: 数据库连接
    """
    start_time = time.time()
    retry_count = 0
    
    # 更新等待计数
    _pool_stats["wait_count"] += 1
    
    while True:
        try:
            # 尝试获取连接
            conn = Tortoise.get_connection(conn_name)
            # 测试连接是否有效
            await conn.execute_query("SELECT 1")
            break
        except OperationalError as e:
            retry_count += 1
            if retry_count > _pool_options["retry_limit"]:
                _pool_stats["connection_errors"] += 1
                logger.error(f"数据库连接失败，已达重试次数上限: {str(e)}")
                raise
            
            # 等待后重试
            await asyncio.sleep(_pool_options["retry_interval"])
        
        # 检查超时
        if time.time() - start_time > timeout:
            _pool_stats["connection_timeouts"] += 1
            logger.error(f"获取数据库连接超时 (>{timeout}秒)")
            raise TimeoutError(f"获取数据库连接超时 (>{timeout}秒)")
    
    # 更新最大等待时间
    wait_time = time.time() - start_time
    if wait_time > _pool_stats["max_wait_time"]:
        _pool_stats["max_wait_time"] = wait_time
    
    try:
        yield conn
    finally:
        # 连接返回池中
        pass


async def start_health_check(interval: int = 60) -> None:
    """
    启动定期健康检查

    Args:
        interval: 健康检查间隔(秒)
    """
    global _health_check_task
    
    if _health_check_task and not _health_check_task.done():
        return
    
    _health_check_task = asyncio.create_task(_health_check_loop(interval))


async def _health_check_loop(interval: int) -> None:
    """
    健康检查循环

    Args:
        interval: 健康检查间隔(秒)
    """
    while True:
        try:
            await _perform_health_check()
        except Exception as e:
            logger.error(f"数据库健康检查出错: {str(e)}")
        
        await asyncio.sleep(interval)


async def _perform_health_check() -> None:
    """
    执行数据库健康检查
    """
    global _pool_stats
    
    all_healthy = True
    
    for conn_name, conn in Tortoise._connections.items():
        try:
            # 简单连接测试
            await conn.execute_query("SELECT 1")
        except Exception as e:
            all_healthy = False
            logger.error(f"数据库连接 {conn_name} 健康检查失败: {str(e)}")
    
    async with _pool_lock:
        _pool_stats["is_healthy"] = all_healthy
        _pool_stats["last_health_check"] = time.time()


async def close_idle_connections() -> int:
    """
    关闭空闲连接

    Returns:
        int: 关闭的连接数量
    """
    closed_count = 0
    
    if not Tortoise._inited:
        return closed_count
    
    for conn_name, conn in Tortoise._connections.items():
        if hasattr(conn, '_pool') and hasattr(conn._pool, 'close'):
            try:
                # 尝试关闭空闲连接
                # 注意：tortoise-orm没有直接提供关闭空闲连接的API
                # 这里实际上取决于底层数据库适配器的实现
                closed = await conn._pool.close(timeout=_pool_options["max_idle_time"])
                if isinstance(closed, int):
                    closed_count += closed
            except Exception as e:
                logger.error(f"关闭空闲连接时出错: {str(e)}")
    
    # 更新统计信息
    await _update_pool_stats()
    
    return closed_count 