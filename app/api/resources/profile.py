#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
个人资料 API 资源模块，提供个人资料的管理接口与自助接口。

安全要点：
* ``account_id`` 永远从认证会话取，不接受请求体中的值（否则可越权改他人资料）。
* 字段白名单：只接受资料自身的展示字段，不接受 ``account_id``/``id``/``created_at`` 等。
* ``ProfileResource``（管理他人）需要 ``profile:read`` / ``profile:update`` 权限，
  且改他人资料还需 ``profile:manage``。
* ``MyProfileResource``（自助）只需登录，且只能读写自己的资料。
"""

from typing import Any, Dict, Optional

from sanic.request import Request
from sanic.views import HTTPMethodView

from app.api import APIResponse, v1_bp
from app.api.responses import APIError
from app.api.validators import (
    Date,
    Length,
    OneOf,
    extract_whitelisted,
    parse_pagination,
    request_payload,
    validate_fields,
)
from app.auth.authentication import authenticate_request
from app.auth.authorization import check_permissions, has_permission
from app.models import Account, Profile

# 允许写入的资料字段（白名单）；account_id/id 等一律不接受
PROFILE_WRITE_FIELDS = (
    "full_name",
    "nickname",
    "avatar",
    "mobile_phone",
    "tel_phone",
    "gender",
    "birth_date",
    "address",
    "work_start_date",
    "introduction",
    "homepage",
)

# 性别取值
GENDER_CHOICES = ["male", "female", "other", "unknown"]


def profile_info(profile: Profile) -> Dict[str, Any]:
    """资料的对外表示。"""
    return {
        "id": profile.id,
        "account_id": profile.account_id,
        "full_name": profile.full_name,
        "nickname": profile.nickname,
        "avatar": profile.avatar,
        "mobile_phone": profile.mobile_phone,
        "tel_phone": profile.tel_phone,
        "gender": profile.gender,
        "birth_date": profile.birth_date.isoformat() if profile.birth_date else None,
        "address": profile.address,
        "work_start_date": profile.work_start_date.isoformat() if profile.work_start_date else None,
        "introduction": profile.introduction,
        "homepage": profile.homepage,
        "created_at": profile.created_at,
        "updated_at": profile.updated_at,
    }


PROFILE_RULES = {
    "full_name": [Length(max_=64)],
    "nickname": [Length(max_=64)],
    "avatar": [Length(max_=255)],
    "mobile_phone": [Length(max_=32)],
    "tel_phone": [Length(max_=32)],
    "gender": [OneOf(GENDER_CHOICES)],
    "birth_date": [Date()],
    "address": [Length(max_=255)],
    "work_start_date": [Date()],
    "introduction": [Length(max_=2000)],
    "homepage": [Length(max_=255)],
}


async def _get_or_create_profile(account: Account) -> Profile:
    """取得账户的资料；不存在时创建一份空资料。"""
    profile = await Profile.filter(account_id=account.id).first()
    if profile is None:
        profile = await Profile.create(account_id=account.id)
    return profile


def _apply_updates(profile: Profile, data: Dict[str, Any]) -> None:
    """把白名单字段写到资料实例上。"""
    for key, value in data.items():
        setattr(profile, key, value)


class ProfileResource(HTTPMethodView):
    """
    个人资料管理资源（管理他人资料，需要权限）。

    * ``GET /api/v1/profiles``             资料列表
    * ``GET /api/v1/profiles/<id>``       资料详情
    * ``PUT /api/v1/profiles/<id>``       更新资料
    """

    @check_permissions("profile", "read")
    async def get(self, request: Request, profile_id: Optional[int] = None):
        """获取资料列表或单个资料。"""
        if profile_id is not None:
            profile = await Profile.filter(id=profile_id).first()
            if profile is None:
                return APIResponse.error(message="个人资料不存在", error_code="PROFILE_NOT_FOUND",
                                         status_code=404)

            account = request.ctx.authentication_session.bearer
            if account.id != profile.account_id and not await has_permission(account, "profile",
                                                                              "manage"):
                return APIResponse.error(message="无权访问此个人资料",
                                         error_code=APIError.FORBIDDEN, status_code=403)

            return APIResponse.success(data=profile_info(profile), message="获取个人资料成功")

        query = Profile.all()

        keyword = (request.args.get("keyword") or request.args.get("search") or "").strip()
        if keyword:
            from tortoise.expressions import Q
            query = query.filter(
                Q(full_name__contains=keyword)
                | Q(nickname__contains=keyword)
                | Q(mobile_phone__contains=keyword)
                | Q(address__contains=keyword)
            )

        page, page_size = parse_pagination(request)
        total = await query.count()
        profiles = await query.order_by("-created_at").offset((page - 1) * page_size).limit(page_size)

        return APIResponse.list(items=[profile_info(p) for p in profiles], total=total, page=page,
                                page_size=page_size, message="获取个人资料列表成功")

    @check_permissions("profile", "update")
    async def put(self, request: Request, profile_id: int):
        """更新资料；改他人资料还需 ``profile:manage``。"""
        account = request.ctx.authentication_session.bearer

        profile = await Profile.filter(id=profile_id).first()
        if profile is None:
            return APIResponse.error(message="个人资料不存在", error_code="PROFILE_NOT_FOUND",
                                     status_code=404)

        if account.id != profile.account_id and not await has_permission(account, "profile",
                                                                          "manage"):
            return APIResponse.error(message="无权更新此个人资料", error_code=APIError.FORBIDDEN,
                                     status_code=403)

        # account_id 不在白名单内，请求体里的 account_id 会被丢弃
        data = extract_whitelisted(request_payload(request), PROFILE_WRITE_FIELDS)

        if not data:
            return APIResponse.error(message="没有可更新的字段", error_code=APIError.MISSING_PARAMETER,
                                     status_code=400)

        errors = validate_fields(data, PROFILE_RULES)
        if errors:
            return APIResponse.error(message="参数验证失败", error_code=APIError.VALIDATION_ERROR,
                                     status_code=400, details=errors)

        _apply_updates(profile, data)
        await profile.save()

        return APIResponse.success(data=profile_info(profile), message="个人资料更新成功")


class MyProfileResource(HTTPMethodView):
    """
    当前用户的个人资料（自助，只需登录，只能读写自己的资料）。

    * ``GET /api/v1/me/profile``  读取自己的资料
    * ``PUT /api/v1/me/profile``  更新自己的资料
    """

    async def get(self, request: Request):
        """读取自己的个人资料（不存在时自动创建空资料）。"""
        session = await authenticate_request(request)
        account = session.bearer

        profile = await _get_or_create_profile(account)

        return APIResponse.success(data=profile_info(profile), message="获取个人资料成功")

    async def put(self, request: Request):
        """更新自己的个人资料。"""
        session = await authenticate_request(request)
        account = session.bearer

        profile = await _get_or_create_profile(account)

        data = extract_whitelisted(request_payload(request), PROFILE_WRITE_FIELDS)

        if not data:
            return APIResponse.error(message="没有可更新的字段", error_code=APIError.MISSING_PARAMETER,
                                     status_code=400)

        errors = validate_fields(data, PROFILE_RULES)
        if errors:
            return APIResponse.error(message="参数验证失败", error_code=APIError.VALIDATION_ERROR,
                                     status_code=400, details=errors)

        _apply_updates(profile, data)
        await profile.save()

        return APIResponse.success(data=profile_info(profile), message="个人资料更新成功")


# 注册路由
# 显式给出路由名：Sanic 23.6 禁止同名路由，同一个视图注册到多个 URI 时
# 会得到相同的隐式名，必须逐条命名。
profile_resource = ProfileResource()
my_profile_resource = MyProfileResource()

v1_bp.add_route(profile_resource.as_view(), "/profiles/<profile_id:int>",
                methods=["GET", "PUT"], name="profile_detail")
v1_bp.add_route(profile_resource.as_view(), "/profiles", methods=["GET"], name="profile_list")
v1_bp.add_route(my_profile_resource.as_view(), "/me/profile", methods=["GET", "PUT"],
                name="my_profile")
