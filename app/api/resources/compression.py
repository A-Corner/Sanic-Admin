#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
响应压缩管理API资源模块

提供响应压缩统计信息和配置管理接口。
权限资源名为 ``system:compression``（操作 view / manage），管理员账户拥有全部权限。
"""

import re

from sanic import Blueprint
from sanic.views import HTTPMethodView

from app.api.responses import APIResponse, APIError
from app.auth.authorization import requires_permission
from app.api.resources.route_methods import register_view
from app.middleware import compression as comp

bp = Blueprint("compression", url_prefix="/compression")

MAX_PATTERN_LENGTH = 200
MAX_LIST_ITEMS = 50


def _bad_request(message: str):
    return APIResponse.error(message=message, error_code=APIError.VALIDATION_ERROR, status_code=400)


def _stats_with_configuration() -> dict:
    stats = comp.get_compression_stats()
    # 通过模块属性读取，保证拿到 update_compression_options 更新后的最新值
    stats["configuration"] = {
        "min_compress_length": comp.MIN_COMPRESS_LENGTH,
        "compression_level": comp.DEFAULT_COMPRESSION_LEVEL,
        "excluded_paths": list(comp.EXCLUDED_PATHS),
        "compressible_types": sorted(comp.COMPRESSIBLE_CONTENT_TYPES),
    }
    return stats


def _string_list(value, name: str):
    if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
        return None, f"{name} 必须是不超过 {MAX_LIST_ITEMS} 项的字符串列表"
    if not all(isinstance(item, str) and 0 < len(item) <= MAX_PATTERN_LENGTH for item in value):
        return None, f"{name} 的每一项必须是 1 到 {MAX_PATTERN_LENGTH} 个字符的字符串"
    return value, None


class CompressionStatsResource(HTTPMethodView):
    """响应压缩统计资源"""

    @requires_permission("system:compression:view")
    async def get(self, request):
        """获取响应压缩统计信息与当前配置。"""
        return APIResponse.success(data=_stats_with_configuration())


class CompressionConfigResource(HTTPMethodView):
    """响应压缩配置资源"""

    @requires_permission("system:compression:manage")
    async def put(self, request):
        """更新压缩阈值、压缩级别、排除路径与可压缩类型（不会重复注册中间件）。"""
        body = request.json
        if not isinstance(body, dict):
            return _bad_request("请求体必须是 JSON 对象")
        unknown = sorted(set(body) - {"min_length", "compression_level", "exclude_paths", "compressible_types"})
        if unknown:
            return _bad_request(f"不支持的选项: {', '.join(unknown)}")

        min_length = body.get("min_length")
        level = body.get("compression_level")
        if min_length is not None and (
                isinstance(min_length, bool) or not isinstance(min_length, int) or min_length < 0):
            return _bad_request("min_length 必须是非负整数")
        if level is not None and (
                isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 9):
            return _bad_request("compression_level 必须是 0 到 9 的整数")

        exclude_paths = body.get("exclude_paths")
        if exclude_paths is not None:
            exclude_paths, err = _string_list(exclude_paths, "exclude_paths")
            if err:
                return _bad_request(err)
            try:
                for pattern in exclude_paths:
                    re.compile(pattern)
            except re.error:
                return _bad_request("exclude_paths 含不合法的正则表达式")

        types = body.get("compressible_types")
        if types is not None:
            types, err = _string_list(types, "compressible_types")
            if err:
                return _bad_request(err)

        comp.update_compression_options(
            min_length=min_length,
            compression_level=level,
            exclude_paths=exclude_paths,
            compressible_types=set(types) if types else None,
        )
        return APIResponse.success(data=_stats_with_configuration(), message="响应压缩配置已更新")


# 注册路由
# register_view：为未支持方法挂 405 兜底（带 Allow 头），与 v1 资源行为一致
register_view(bp, "/stats", CompressionStatsResource, ["GET"], "compression_stats")
register_view(bp, "/config", CompressionConfigResource, ["GET", "PUT"], "compression_config")
