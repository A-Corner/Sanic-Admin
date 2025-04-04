#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
缓存管理API资源模块，提供缓存查询、清理等操作
"""

from sanic.request import Request
from sanic.views import HTTPMethodView
from app.api import APIResponse, v1_bp, APIError
from app.auth.authorization import check_permissions
from app.cache import get_cache
from app.cache.decorators import clear_route_cache
from typing import Dict, Any, List, Optional


class CacheResource(HTTPMethodView):
    """
    缓存资源
    
    提供缓存信息查询和管理功能
    """
    
    async def get(self, request: Request):
        """
        获取缓存统计信息
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应，包含缓存统计信息
        """
        @check_permissions("system", "admin")
        async def get_cache_stats(request):
            cache = get_cache()
            
            # 获取缓存统计信息
            stats = cache.get_stats()
            
            # 获取缓存键数量
            keys_count = len(cache.keys())
            
            # 获取缓存类型
            cache_type = request.app.config.get('CACHE_TYPE', 'memory')
            
            return APIResponse.success(data={
                "cache_type": cache_type,
                "stats": stats,
                "keys_count": keys_count,
                "enabled": request.app.config.get('USE_CACHE', True),
                "route_cache_enabled": request.app.config.get('ROUTE_CACHE_ENABLED', True)
            }, message="获取缓存统计信息成功")
        
        return await get_cache_stats(request)
    
    async def delete(self, request: Request):
        """
        清除缓存
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应，表示操作结果
        """
        @check_permissions("system", "admin")
        async def clear_cache(request):
            pattern = request.args.get('pattern', '*')
            cache_type = request.args.get('type', 'all')
            
            cache = get_cache()
            
            # 根据缓存类型选择清除方式
            if cache_type == 'route':
                # 清除路由缓存
                keys_count = clear_route_cache(pattern)
                message = f"已清除 {keys_count} 个路由缓存键"
            elif cache_type == 'all':
                # 清除所有缓存
                cache.clear()
                message = "已清除所有缓存"
            else:
                # 清除指定模式的缓存
                keys = cache.keys(pattern)
                keys_count = cache.delete_many(keys)
                message = f"已清除 {keys_count} 个缓存键"
            
            return APIResponse.success(message=message)
        
        return await clear_cache(request)


class CacheKeysResource(HTTPMethodView):
    """
    缓存键资源
    
    提供缓存键查询功能
    """
    
    async def get(self, request: Request):
        """
        获取缓存键列表
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Response: Sanic响应，包含缓存键列表
        """
        @check_permissions("system", "admin")
        async def get_cache_keys(request):
            pattern = request.args.get('pattern', '*')
            limit = int(request.args.get('limit', '100'))
            page = int(request.args.get('page', '1'))
            
            if page < 1:
                page = 1
            if limit < 1 or limit > 1000:
                limit = 100
                
            # 计算分页
            start = (page - 1) * limit
            end = start + limit
                
            cache = get_cache()
            
            # 获取缓存键
            all_keys = cache.keys(pattern)
            total = len(all_keys)
            
            # 分页
            keys = all_keys[start:end]
            
            # 获取键的详细信息
            keys_info = []
            for key in keys:
                ttl = cache.ttl(key)
                
                # 获取值的类型和预览
                value = cache.get(key)
                value_type = type(value).__name__
                
                # 创建值的简短预览
                if value is None:
                    preview = "None"
                elif isinstance(value, (int, float, bool)):
                    preview = str(value)
                elif isinstance(value, str):
                    preview = value[:50] + "..." if len(value) > 50 else value
                elif isinstance(value, (list, tuple)):
                    preview = f"{value_type}[{len(value)}]"
                elif isinstance(value, dict):
                    preview = f"dict{{{len(value)}}}"
                else:
                    preview = f"{value_type} object"
                
                keys_info.append({
                    "key": key,
                    "ttl": ttl,
                    "expires_in": "永不过期" if ttl == -1 else f"{ttl}秒" if ttl >= 0 else "已过期",
                    "value_type": value_type,
                    "preview": preview
                })
            
            return APIResponse.success(data={
                "keys": keys_info,
                "total": total,
                "page": page,
                "limit": limit,
                "pages": (total + limit - 1) // limit
            }, message="获取缓存键列表成功")
            
        return await get_cache_keys(request)


class CacheKeyResource(HTTPMethodView):
    """
    单个缓存键资源
    
    提供单个缓存键的查询、修改和删除功能
    """
    
    async def get(self, request: Request, key: str):
        """
        获取单个缓存键的详细信息
        
        Args:
            request: Sanic请求对象
            key: 缓存键
            
        Returns:
            Response: Sanic响应，包含缓存键详细信息
        """
        @check_permissions("system", "admin")
        async def get_cache_key(request, key):
            cache = get_cache()
            
            # 检查键是否存在
            if not cache.exists(key):
                raise APIError(f"缓存键 '{key}' 不存在", status=404)
            
            # 获取键的详细信息
            value = cache.get(key)
            ttl = cache.ttl(key)
            
            # 获取值的类型
            value_type = type(value).__name__
            
            # 获取值的字符串表示
            try:
                import json
                if isinstance(value, (dict, list, tuple)):
                    value_str = json.dumps(value, ensure_ascii=False, indent=2)
                else:
                    value_str = str(value)
            except:
                value_str = str(value)
            
            return APIResponse.success(data={
                "key": key,
                "ttl": ttl,
                "expires_in": "永不过期" if ttl == -1 else f"{ttl}秒" if ttl >= 0 else "已过期",
                "value_type": value_type,
                "value": value,
                "value_str": value_str
            }, message="获取缓存键详细信息成功")
            
        return await get_cache_key(request, key)
    
    async def delete(self, request: Request, key: str):
        """
        删除单个缓存键
        
        Args:
            request: Sanic请求对象
            key: 缓存键
            
        Returns:
            Response: Sanic响应，表示操作结果
        """
        @check_permissions("system", "admin")
        async def delete_cache_key(request, key):
            cache = get_cache()
            
            # 检查键是否存在
            if not cache.exists(key):
                raise APIError(f"缓存键 '{key}' 不存在", status=404)
            
            # 删除键
            success = cache.delete(key)
            
            if success:
                return APIResponse.success(message=f"缓存键 '{key}' 已删除")
            else:
                raise APIError(f"删除缓存键 '{key}' 失败", status=500)
                
        return await delete_cache_key(request, key)
    
    async def put(self, request: Request, key: str):
        """
        更新缓存键的过期时间
        
        Args:
            request: Sanic请求对象
            key: 缓存键
            
        Returns:
            Response: Sanic响应，表示操作结果
        """
        @check_permissions("system", "admin")
        async def update_cache_key(request, key):
            # 获取请求数据
            data = request.json
            
            if not data:
                raise APIError("请求数据不能为空", status=400)
                
            # 获取过期时间
            timeout = data.get('timeout')
            
            if timeout is None:
                raise APIError("缺少必要参数：timeout", status=400)
                
            if not isinstance(timeout, int):
                raise APIError("参数类型错误：timeout必须是整数", status=400)
                
            cache = get_cache()
            
            # 检查键是否存在
            if not cache.exists(key):
                raise APIError(f"缓存键 '{key}' 不存在", status=404)
            
            # 更新过期时间
            if timeout <= 0:
                # 如果timeout <= 0，则设置为永不过期
                value = cache.get(key)
                success = cache.set(key, value)
            else:
                success = cache.expire(key, timeout)
            
            if success:
                return APIResponse.success(message=f"缓存键 '{key}' 过期时间已更新")
            else:
                raise APIError(f"更新缓存键 '{key}' 过期时间失败", status=500)
                
        return await update_cache_key(request, key)


# 注册路由
v1_bp.add_route(CacheResource.as_view(), '/cache')
v1_bp.add_route(CacheKeysResource.as_view(), '/cache/keys')
v1_bp.add_route(CacheKeyResource.as_view(), '/cache/keys/<key>') 