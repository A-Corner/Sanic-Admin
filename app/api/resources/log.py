#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
操作日志 API 资源模块，提供日志查询与统计接口。

安全要点：
* 只读：本模块不写入 OperationLog（日志写入由认证/管理路径负责）。
* 全部接口需要 ``log:read`` 权限。
* 使用 OperationLog 模型的真实字段，不回显任何敏感凭据。
"""

import datetime
from typing import Any, Dict, Optional

from sanic.request import Request
from sanic.views import HTTPMethodView
from tortoise.functions import Count

from app.api import APIResponse, v1_bp
from app.api.resources.route_methods import register_view
from app.api.responses import APIError
from app.api.validators import parse_pagination
from app.auth.authorization import check_permissions
from app.models import OperationLog


def log_info(record: OperationLog) -> Dict[str, Any]:
    """日志的对外表示（与模型字段一一对应）。"""
    return {
        "id": record.id,
        "account_id": record.account_id,
        "account_name": record.account_name,
        "operation": record.operation,
        "operation_type": record.operation_type,
        "detail": record.detail,
        "status": record.status,
        "ip_address": record.ip_address,
        "user_agent": record.user_agent,
        "created_at": record.created_at,
    }


def _parse_datetime(raw: Optional[str]) -> Optional[datetime.datetime]:
    """
    解析 ISO 日期时间；格式非法时抛出 ValueError。
    """
    if not raw:
        return None
    return datetime.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))


class LogResource(HTTPMethodView):
    """
    操作日志资源（只读）。

    * ``GET /api/v1/logs``       日志列表（支持关键字/类型/状态/账户/时间区间过滤）
    * ``GET /api/v1/logs/<id>``  单条日志
    """

    @check_permissions("log", "read")
    async def get(self, request: Request, log_id: Optional[int] = None):
        """获取日志列表或单条日志。"""
        if log_id is not None:
            record = await OperationLog.filter(id=log_id).first()
            if record is None:
                return APIResponse.error(message="日志不存在", error_code="LOG_NOT_FOUND",
                                         status_code=404)
            return APIResponse.success(data=log_info(record), message="获取日志成功")

        query = OperationLog.all()

        keyword = (request.args.get("keyword") or request.args.get("search") or "").strip()
        if keyword:
            from tortoise.expressions import Q
            query = query.filter(
                Q(operation__contains=keyword)
                | Q(operation_type__contains=keyword)
                | Q(detail__contains=keyword)
                | Q(account_name__contains=keyword)
                | Q(ip_address__contains=keyword)
            )

        for field in ("operation_type", "status", "account_id"):
            value = request.args.get(field)
            if value:
                if field == "account_id":
                    try:
                        value = int(value)
                    except (TypeError, ValueError):
                        return APIResponse.error(message="account_id 必须是整数",
                                                 error_code=APIError.INVALID_PARAMETER,
                                                 status_code=400)
                query = query.filter(**{field: value})

        try:
            start_date = _parse_datetime(request.args.get("start_date"))
            end_date = _parse_datetime(request.args.get("end_date"))
        except ValueError:
            return APIResponse.error(
                message="日期格式无效，请使用 ISO 格式 (YYYY-MM-DDTHH:MM:SS)",
                error_code="INVALID_DATE_FORMAT", status_code=400)

        if start_date:
            query = query.filter(created_at__gte=start_date)
        if end_date:
            query = query.filter(created_at__lte=end_date)

        page, page_size = parse_pagination(request)
        total = await query.count()
        records = await query.order_by("-created_at").offset((page - 1) * page_size).limit(page_size)

        return APIResponse.list(items=[log_info(r) for r in records], total=total, page=page,
                                page_size=page_size, message="获取日志列表成功")


class LogStatisticsResource(HTTPMethodView):
    """
    日志统计资源：``GET /api/v1/logs/statistics``。
    """

    @check_permissions("log", "read")
    async def get(self, request: Request):
        """获取日志统计数据（总数 + 按类型/状态/账户分组）。"""
        query = OperationLog.all()

        try:
            start_date = _parse_datetime(request.args.get("start_date"))
            end_date = _parse_datetime(request.args.get("end_date"))
        except ValueError:
            return APIResponse.error(
                message="日期格式无效，请使用 ISO 格式 (YYYY-MM-DDTHH:MM:SS)",
                error_code="INVALID_DATE_FORMAT", status_code=400)

        if start_date:
            query = query.filter(created_at__gte=start_date)
        if end_date:
            query = query.filter(created_at__lte=end_date)

        total_count = await query.count()

        operation_type_stats = await query.group_by("operation_type").annotate(
            count=Count("id")
        ).values("operation_type", "count")

        status_stats = await query.group_by("status").annotate(
            count=Count("id")
        ).values("status", "count")

        # 注意：.values() 返回的 ValuesQuery 没有 .limit 方法，
        # 因此 limit 必须在 values() 之前应用。
        account_stats = await query.group_by("account_id", "account_name").annotate(
            count=Count("id")
        ).limit(10).values("account_id", "account_name", "count")

        statistics = {
            "total_count": total_count,
            "by_operation_type": {row["operation_type"]: row["count"]
                                   for row in operation_type_stats},
            "by_status": {row["status"]: row["count"] for row in status_stats},
            "by_account": [
                {
                    "account_id": row["account_id"],
                    "account_name": row["account_name"],
                    "count": row["count"],
                }
                for row in account_stats
            ],
        }

        return APIResponse.success(data=statistics, message="获取日志统计数据成功")


# 注册路由
# 显式给出路由名：Sanic 23.6 禁止同名路由，同一个视图注册到多个 URI 时
# 会得到相同的隐式名，必须逐条命名。
log_resource = LogResource()
log_statistics_resource = LogStatisticsResource()

register_view(v1_bp, "/logs/<log_id:int>", log_resource, ["GET"], "log_detail")
register_view(v1_bp, "/logs", log_resource, ["GET"], "log_list")
register_view(v1_bp, "/logs/statistics", log_statistics_resource, ["GET"], "log_statistics")
