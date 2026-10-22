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

import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from sanic.request import Request
from sanic.views import HTTPMethodView

from app.api import APIResponse, v1_bp
from app.api.responses import APIError
from app.api.validators import (
    Date,
    Length,
    OneOf,
    Type,
    extract_whitelisted,
    parse_pagination,
    request_payload,
    validate_fields,
)
from app.auth.authentication import authenticate_request
from app.auth.authorization import check_permissions, has_permission
from app.api.resources.route_methods import register_view
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


def _iso_date(value: Any) -> Optional[str]:
    """
    把日期字段序列化成 ISO 字符串。

    防御性：字段类型是 ``DateField``，正常情况下取回来就是 ``datetime.date``；
    但若实例上的值尚未经过 ORM 转换（例如刚被赋成字符串），直接调
    ``.isoformat()`` 会抛 AttributeError → 500。这里同时兼容字符串与日期对象。
    """
    if value is None:
        return None
    if isinstance(value, (datetime.date, datetime.datetime)):
        return value.isoformat()
    return str(value)


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
        "birth_date": _iso_date(profile.birth_date),
        "address": profile.address,
        "work_start_date": _iso_date(profile.work_start_date),
        "introduction": profile.introduction,
        "homepage": profile.homepage,
        "created_at": profile.created_at,
        "updated_at": profile.updated_at,
    }


#: 允许写入的日期字段（校验后转成 ``datetime.date`` 再落库）
DATE_FIELDS = ("birth_date", "work_start_date")

#: URL 字段：只允许 http/https 协议（防 ``javascript:`` / ``data:`` XSS）
URL_FIELDS = ("avatar", "homepage")

#: 字符串字段：拒绝非字符串输入（如列表、字典），避免被字符串化后落库
STRING_FIELDS = (
    "full_name",
    "nickname",
    "avatar",
    "mobile_phone",
    "tel_phone",
    "gender",
    "address",
    "introduction",
    "homepage",
)


def _normalize_date(value: Any) -> Any:
    """
    把日期字符串转成 ``datetime.date``；已经是日期/日期时间对象则只取日期部分。

    转换失败时抛 ``ValueError``（调用方在校验阶段已经拦过非法值，
    这里只是防御性兜底）。
    """
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value

    text = str(value).strip()
    if not text:
        return None

    try:
        return datetime.date.fromisoformat(text)
    except ValueError:
        pass

    try:
        return datetime.datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError as exc:
        raise ValueError(f"不是合法的日期: {text}") from exc


def _validate_url(value: Any) -> bool:
    """
    校验 URL 字段：只允许 http/https 协议。

    AMIS 会把 ``avatar`` / ``homepage`` 直接渲染成链接或图片，
    ``javascript:`` / ``data:`` 方案会造成 XSS，因此这里在写入前拦掉。
    """
    if not isinstance(value, str):
        return False

    text = value.strip()
    if not text:
        return True

    try:
        parsed = urlparse(text)
    except ValueError:
        return False

    return parsed.scheme.lower() in ("http", "https")


def _validate_profile_payload(data: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    在通用规则之外补充两类校验：

    * **字符串字段**：非字符串输入直接拒绝（``Length`` 规则对非字符串会跳过，
      导致 ``full_name=["a"]`` 被字符串化后落库）；
    * **URL 字段**：只允许 http/https 协议。

    Returns:
        Dict[str, List[str]]: ``{字段: [错误信息, ...]}``；无错误时为空字典
    """
    errors: Dict[str, List[str]] = {}

    for field in STRING_FIELDS:
        value = data.get(field)
        if value is None:
            continue
        if not isinstance(value, str):
            errors.setdefault(field, []).append(f"字段{field}必须是字符串")

    for field in URL_FIELDS:
        value = data.get(field)
        if value is None:
            continue
        if isinstance(value, str) and not _validate_url(value):
            errors.setdefault(field, []).append(f"字段{field}必须是 http/https 开头的合法 URL")

    return errors


PROFILE_RULES = {
    "full_name": [Type(str), Length(max_=64)],
    "nickname": [Type(str), Length(max_=64)],
    "avatar": [Type(str), Length(max_=255)],
    "mobile_phone": [Type(str), Length(max_=32)],
    "tel_phone": [Type(str), Length(max_=32)],
    "gender": [Type(str), OneOf(GENDER_CHOICES)],
    "birth_date": [Date()],
    "address": [Type(str), Length(max_=255)],
    "work_start_date": [Date()],
    "introduction": [Type(str), Length(max_=2000)],
    "homepage": [Type(str), Length(max_=255)],
}


async def _get_or_create_profile(account: Account) -> Profile:
    """取得账户的资料；不存在时创建一份空资料。"""
    profile = await Profile.filter(account_id=account.id).first()
    if profile is None:
        profile = await Profile.create(account_id=account.id)
    return profile


def _apply_updates(profile: Profile, data: Dict[str, Any]) -> None:
    """
    把白名单字段写到资料实例上。

    日期字段在这里**转成 ``datetime.date``** 再赋值：模型字段是 ``DateField``，
    若直接把字符串赋上去，ORM 只在落库时转换，而实例上仍是字符串，
    响应序列化时对字符串调 ``.isoformat()`` 会抛 AttributeError → 500
    （数据已改成功但客户端收到 500，是最坏的失败形态）。
    """
    for key, value in data.items():
        if key in DATE_FIELDS:
            value = _normalize_date(value)
        setattr(profile, key, value)


def _prepare_write_data(request: Request) -> tuple:
    """
    解析并校验一次资料写入请求。

    步骤：白名单提取 → 通用规则校验 → 补充校验（字符串类型 / URL 协议）。

    Returns:
        tuple: ``(data, errors)``。``data`` 为空表示请求体没有任何白名单字段；
        ``errors`` 非空表示校验失败，调用方据此返回 400。
    """
    data = extract_whitelisted(request_payload(request), PROFILE_WRITE_FIELDS)

    if not data:
        return {}, {}

    errors = validate_fields(data, PROFILE_RULES)
    for field, messages in _validate_profile_payload(data).items():
        errors.setdefault(field, []).extend(messages)

    return data, errors


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
        account = request.ctx.authentication_session.bearer

        if profile_id is not None:
            profile = await Profile.filter(id=profile_id).first()
            if profile is None:
                return APIResponse.error(message="个人资料不存在", error_code="PROFILE_NOT_FOUND",
                                         status_code=404)

            if account.id != profile.account_id and not await has_permission(account, "profile",
                                                                              "manage"):
                return APIResponse.error(message="无权访问此个人资料",
                                         error_code=APIError.FORBIDDEN, status_code=403)

            return APIResponse.success(data=profile_info(profile), message="获取个人资料成功")

        # 列表：查看**他人**资料需要 ``profile:manage``；没有 manage 的账户
        # 只能看到自己的资料（否则列表会绕过单条接口的 manage 校验，
        # 把手机号、地址、生日等隐私字段批量泄露出去）。
        can_manage = await has_permission(account, "profile", "manage")

        query = Profile.all()
        if not can_manage:
            query = query.filter(account_id=account.id)

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
        data, errors = _prepare_write_data(request)

        if not errors and not data:
            return APIResponse.error(message="没有可更新的字段", error_code=APIError.MISSING_PARAMETER,
                                     status_code=400)

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

        data, errors = _prepare_write_data(request)

        if not errors and not data:
            return APIResponse.error(message="没有可更新的字段", error_code=APIError.MISSING_PARAMETER,
                                     status_code=400)

        if errors:
            return APIResponse.error(message="参数验证失败", error_code=APIError.VALIDATION_ERROR,
                                     status_code=400, details=errors)

        _apply_updates(profile, data)
        await profile.save()

        return APIResponse.success(data=profile_info(profile), message="个人资料更新成功")


# 注册路由
# 显式给出路由名：Sanic 23.6 禁止同名路由，同一个视图注册到多个 URI 时
# 会得到相同的隐式名，必须逐条命名。
#
# 用 ``register_view``（而不是 ``v1_bp.add_route``）：后者遇到
# ``HTTPMethodView`` 处理器时会**忽略传入的 methods**，按视图类反推方法集，
# 导致路径上出现不该有的方法，命中时缺参数 → **500**；而 Sanic 23.6 对
# **动态路径**的方法不匹配会把 ``NoMethod`` 转成 ``NotFound`` → **404**。
# ``register_view`` 用 ``Blueprint.route`` 原样注册方法，并给其余方法挂 405
# 兜底，详见 ``app/api/resources/route_methods.py``。
profile_resource = ProfileResource()
my_profile_resource = MyProfileResource()

register_view(v1_bp, "/profiles/<profile_id:int>", profile_resource,
              ["GET", "PUT"], "profile_detail")
register_view(v1_bp, "/profiles", profile_resource, ["GET"], "profile_list")
register_view(v1_bp, "/me/profile", my_profile_resource, ["GET", "PUT"], "my_profile")
