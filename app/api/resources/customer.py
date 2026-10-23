#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
客户 API 资源模块（由 SA-v04-S0 spike 生成器产出）。

CRUD 全部走 ``requires_permission("customer:<action>")``，字段白名单与
规格（spike/customer.yaml）一致。
"""

from sanic.request import Request
from sanic.views import HTTPMethodView

from app.api import APIResponse, v1_bp
from app.api.responses import APIError
from app.api.validators import (
    Length,
    Required,
    Type,
    extract_whitelisted,
    parse_pagination,
    request_payload,
    validate_fields,
)
from app.auth.authorization import requires_permission
from app.api.resources.route_methods import register_view
from app.models import Customer

CUSTOMER = "customer"

FIELD_RULES = {
    "name": [Required(), Length(max_=128)],
    "email": [Required(), Length(max_=255)],
}

#: 允许写入的字段（白名单，来自规格）
WRITE_FIELDS = ("name", "email", "status", "notes", "account_id")


def customer_info(obj: Customer) -> dict:
    """对外表示（模型 json 属性透传）。"""
    return obj.json


class CustomerResource(HTTPMethodView):
    """客户 列表 / 详情 / 创建 / 更新 / 删除。"""

    @requires_permission("customer:read")
    async def get(self, request: Request, customer_id: int = None):
        """获取客户列表或详情。"""
        if customer_id is not None:
            obj = await Customer.filter(id=customer_id).first()
            if obj is None:
                return APIResponse.error(
                    message="客户不存在", error_code="CUSTOMER_NOT_FOUND",
                    status_code=404)
            return APIResponse.success(data=customer_info(obj),
                                       message="获取客户成功")

        query = Customer.all()
        keyword = (request.args.get("keyword") or "").strip()
        if keyword:
            from tortoise.expressions import Q
            conds = Q()
            for f in ["name"]:
                conds |= Q(**{f + "__contains": keyword})
            query = query.filter(conds)

        page, page_size = parse_pagination(request)
        total = await query.count()
        rows = await query.order_by("-id").offset((page - 1) * page_size).limit(page_size)
        return APIResponse.list(items=[customer_info(r) for r in rows],
                                total=total, page=page, page_size=page_size,
                                message="获取客户列表成功")

    @requires_permission("customer:create")
    async def post(self, request: Request):
        """创建客户。"""
        # 与 role.py 同款两步：先白名单提取，再对提取结果做规则校验
        payload = extract_whitelisted(request_payload(request), WRITE_FIELDS)
        errors = validate_fields(payload, FIELD_RULES)
        if errors:
            return APIResponse.error(message="参数验证失败",
                                     error_code=APIError.VALIDATION_ERROR,
                                     status_code=400, details=errors)
        obj = await Customer.create(**payload)
        return APIResponse.created(data=customer_info(obj),
                                   message="创建客户成功",
                                   location=f"/api/v1/customers/{obj.id}")

    @requires_permission("customer:update")
    async def put(self, request: Request, customer_id: int):
        """更新客户。"""
        obj = await Customer.filter(id=customer_id).first()
        if obj is None:
            return APIResponse.error(message="客户不存在",
                                     error_code="CUSTOMER_NOT_FOUND",
                                     status_code=404)
        payload = extract_whitelisted(request_payload(request), WRITE_FIELDS)
        if not payload:
            return APIResponse.error(message="没有可更新的字段",
                                     error_code=APIError.MISSING_PARAMETER,
                                     status_code=400)
        for name, value in payload.items():
            setattr(obj, name, value)
        await obj.save()
        return APIResponse.success(data=customer_info(obj), message="客户更新成功")

    @requires_permission("customer:delete")
    async def delete(self, request: Request, customer_id: int):
        """删除客户（spike 为物理删除；生产化应评估软删除）。"""
        obj = await Customer.filter(id=customer_id).first()
        if obj is None:
            return APIResponse.error(message="客户不存在",
                                     error_code="CUSTOMER_NOT_FOUND",
                                     status_code=404)
        await obj.delete()
        return APIResponse.success(message="删除客户成功")


# 路由注册（register_view 会为未实现的方法挂 405 兜底）
register_view(v1_bp, "/customers/<customer_id:int>", CustomerResource,
              ["GET", "PUT", "DELETE"], "customer_detail")
register_view(v1_bp, "/customers", CustomerResource, ["GET", "POST"],
              "customer_list")
