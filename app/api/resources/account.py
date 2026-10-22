#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
账户 API 资源模块，提供账户管理与自助账户信息接口。

安全要点：
* 字段白名单是唯一入口：创建只接受 username/email/password/phone，
  更新只接受 username/email/phone/password。``is_admin``、``verified``、
  ``disabled``、``roles``、``deleted``、``id`` 一律不接受（即使客户端显式传入也被丢弃）。
* 口令只以 Argon2 哈希落库（``Account.set_password``），响应中永不回显口令或哈希。
* 非 admin 账户不能：创建/修改 ``is_admin``、修改 admin 账户、删除 admin 账户、
  给账户授予自身不具备权限的角色。
* 删除一律软删除（``deleted=True``），列表默认过滤已删除账户。
* 改密后该账户的全部既有认证会话立即失效（``AuthenticationSession.disabled=True``）。
* 自助接口（``/accounts/me``、``/accounts/me/password``）只需登录，
  且只能读写自己的数据。
"""

from typing import Any, Dict, Optional

from sanic.request import Request
from sanic.views import HTTPMethodView

from app.api import APIResponse, v1_bp
from app.api.responses import APIError
from app.api.validators import (
    Email,
    Length,
    Optional as OptionalRule,
    Required,
    extract_whitelisted,
    parse_bool_arg,
    parse_pagination,
    request_payload,
    validate_fields,
)
from app.auth.authentication import authenticate_request
from app.auth.authorization import check_permissions, get_account_permissions
from app.models import Account, AuthenticationSession

# 创建账户时允许写入的字段（白名单）
ACCOUNT_CREATE_FIELDS = ("username", "email", "password", "phone")
# 更新账户时允许写入的字段（白名单）
ACCOUNT_UPDATE_FIELDS = ("username", "email", "phone", "password")

# 长度限制与 Account 模型字段长度保持一致
USERNAME_MAX_LENGTH = 32
EMAIL_MAX_LENGTH = 255
PHONE_MAX_LENGTH = 14
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128

ACCOUNT_RULES = {
    "username": [Required(), Length(min_=3, max_=USERNAME_MAX_LENGTH)],
    "email": [Required(), Email()],
    "password": [Required(), Length(min_=PASSWORD_MIN_LENGTH, max_=PASSWORD_MAX_LENGTH)],
    "phone": [OptionalRule(), Length(max_=PHONE_MAX_LENGTH)],
}


def account_info(account: Account) -> Dict[str, Any]:
    """
    账户的对外表示；绝不包含 ``password`` / ``password_hash``。
    """
    return {
        "id": account.id,
        "username": account.username,
        "email": account.email,
        "phone": account.phone,
        "first_name": account.first_name,
        "last_name": account.last_name,
        "disabled": account.disabled,
        "verified": account.verified,
        "is_admin": account.is_admin,
        "is_active": account.is_active,
        "created_at": account.created_at,
        "updated_at": account.updated_at,
    }


async def _ensure_unique(account: Optional[Account], username: str, email: str,
                         phone: Optional[str]) -> Optional[str]:
    """
    校验用户名/邮箱/手机号唯一性；冲突时返回错误消息，否则返回 None。

    唯一性约束在数据库上是全局的（软删除的账户仍占用其 username/email/phone），
    因此这里不过滤 ``deleted``，避免创建出违反唯一约束的记录。
    """
    exclude_id = account.id if account is not None else None

    def _query(field, value):
        qs = Account.filter(**{field: value})
        if exclude_id is not None:
            qs = qs.exclude(id=exclude_id)
        return qs.exists()

    if await _query("username", username):
        return "用户名已存在"

    if await _query("email", email):
        return "邮箱已存在"

    if phone and await _query("phone", phone):
        return "手机号已存在"

    return None


async def _invalidate_sessions(account: Account) -> int:
    """
    禁用该账户的全部既有认证会话（改密后旧令牌立即失效）。
    """
    return await AuthenticationSession.filter(
        bearer_id=account.id, disabled=False
    ).update(disabled=True)


class AccountResource(HTTPMethodView):
    """
    账户管理资源（管理他人账户，需要 account 资源权限）。

    * ``GET    /api/v1/accounts``       账户列表（默认过滤已删除）
    * ``POST   /api/v1/accounts``       创建账户
    * ``GET    /api/v1/accounts/<id>``  账户详情
    * ``PUT    /api/v1/accounts/<id>``  更新账户
    * ``DELETE /api/v1/accounts/<id>``  软删除账户
    """

    @check_permissions("account", "read")
    async def get(self, request: Request, account_id: Optional[int] = None):
        """获取账户列表或单个账户详情。"""
        if account_id is not None:
            account = await Account.filter(id=account_id, deleted=False).first()
            if account is None:
                return APIResponse.error(message="账户不存在", error_code="ACCOUNT_NOT_FOUND",
                                         status_code=404)
            return APIResponse.success(data=account_info(account), message="获取账户成功")

        query = Account.filter(deleted=False)

        keyword = (request.args.get("keyword") or request.args.get("search") or "").strip()
        if keyword:
            from tortoise.expressions import Q
            query = query.filter(
                Q(username__contains=keyword)
                | Q(email__contains=keyword)
                | Q(first_name__contains=keyword)
                | Q(last_name__contains=keyword)
            )

        for flag_name in ("is_admin", "disabled", "verified"):
            flag = parse_bool_arg(request, flag_name)
            if flag is not None:
                query = query.filter(**{flag_name: flag})

        page, page_size = parse_pagination(request)
        total = await query.count()
        accounts = await query.order_by("-created_at").offset((page - 1) * page_size).limit(page_size)

        return APIResponse.list(items=[account_info(a) for a in accounts], total=total,
                                page=page, page_size=page_size, message="获取账户列表成功")

    @check_permissions("account", "create")
    async def post(self, request: Request):
        """创建账户（只接受白名单字段；口令哈希后落库）。"""
        payload = request_payload(request)

        # 白名单之外的字段（is_admin/verified/disabled/roles/deleted/id）在这里被丢弃
        data = extract_whitelisted(payload, ACCOUNT_CREATE_FIELDS)

        errors = validate_fields(data, ACCOUNT_RULES)
        if errors:
            return APIResponse.error(message="参数验证失败", error_code=APIError.VALIDATION_ERROR,
                                     status_code=400, details=errors)

        username = data["username"].strip()
        email = data["email"].strip()
        phone = data.get("phone")
        phone = phone.strip() if isinstance(phone, str) else None
        password = data["password"]

        conflict = await _ensure_unique(None, username, email, phone)
        if conflict:
            return APIResponse.error(message=conflict, error_code="ACCOUNT_EXISTS", status_code=400)

        account = Account(
            username=username,
            email=email,
            phone=phone,
            verified=False,
            disabled=False,
            is_admin=False,
        )
        account.set_password(password)
        await account.save()

        return APIResponse.created(data=account_info(account), message="账户创建成功",
                                   location=f"/api/v1/accounts/{account.id}")

    @check_permissions("account", "update")
    async def put(self, request: Request, account_id: int):
        """更新账户（只接受白名单字段）。"""
        actor = request.ctx.authentication_session.bearer
        account = await Account.filter(id=account_id, deleted=False).first()
        if account is None:
            return APIResponse.error(message="账户不存在", error_code="ACCOUNT_NOT_FOUND",
                                     status_code=404)

        # 非 admin 不能修改 admin 账户
        if account.is_admin and not actor.is_admin:
            return APIResponse.error(message="无权修改管理员账户", error_code=APIError.FORBIDDEN,
                                     status_code=403)

        payload = request_payload(request)
        data = extract_whitelisted(payload, ACCOUNT_UPDATE_FIELDS)

        # 口令不在这里改：改密必须走专用接口（需要校验当前口令）
        data.pop("password", None)

        if not data:
            return APIResponse.error(message="没有可更新的字段", error_code=APIError.MISSING_PARAMETER,
                                     status_code=400)

        errors = validate_fields(data, {
            "username": [Length(min_=3, max_=USERNAME_MAX_LENGTH)],
            "email": [Email()],
            "phone": [Length(max_=PHONE_MAX_LENGTH)],
        })
        if errors:
            return APIResponse.error(message="参数验证失败", error_code=APIError.VALIDATION_ERROR,
                                     status_code=400, details=errors)

        username = data.get("username", account.username)
        email = data.get("email", account.email)
        phone = data.get("phone", account.phone)
        if isinstance(username, str):
            username = username.strip()
        if isinstance(email, str):
            email = email.strip()
        if isinstance(phone, str):
            phone = phone.strip() or None

        conflict = await _ensure_unique(account, username, email, phone)
        if conflict:
            return APIResponse.error(message=conflict, error_code="ACCOUNT_EXISTS", status_code=400)

        for key, value in data.items():
            setattr(account, key, value)

        await account.save()

        return APIResponse.success(data=account_info(account), message="账户更新成功")

    @check_permissions("account", "delete")
    async def delete(self, request: Request, account_id: int):
        """软删除账户。"""
        actor = request.ctx.authentication_session.bearer
        account = await Account.filter(id=account_id, deleted=False).first()
        if account is None:
            return APIResponse.error(message="账户不存在", error_code="ACCOUNT_NOT_FOUND",
                                     status_code=404)

        if account.is_admin and not actor.is_admin:
            return APIResponse.error(message="无权删除管理员账户", error_code=APIError.FORBIDDEN,
                                     status_code=403)

        if account.id == actor.id:
            return APIResponse.error(message="不能删除自己的账户", error_code=APIError.FORBIDDEN,
                                     status_code=403)

        account.deleted = True
        await account.save(update_fields=["deleted"])

        # 账户被删除后，其既有会话立即失效
        await _invalidate_sessions(account)

        return APIResponse.success(message="账户删除成功")


class AccountPasswordResource(HTTPMethodView):
    """
    账户密码资源：``PUT /api/v1/accounts/<id>/password``。

    需要 ``account:update`` 权限；非 admin 只能修改自己的口令。
    改密后该账户全部既有会话失效。
    """

    @check_permissions("account", "update")
    async def put(self, request: Request, account_id: int):
        """修改账户口令。"""
        actor = request.ctx.authentication_session.bearer
        account = await Account.filter(id=account_id, deleted=False).first()
        if account is None:
            return APIResponse.error(message="账户不存在", error_code="ACCOUNT_NOT_FOUND",
                                     status_code=404)

        if account.id != actor.id and not actor.is_admin:
            return APIResponse.error(message="无权修改其他账户的口令", error_code=APIError.FORBIDDEN,
                                     status_code=403)

        payload = request_payload(request)
        current_password = payload.get("current_password")
        new_password = payload.get("new_password")

        if not isinstance(current_password, str) or not current_password:
            return APIResponse.error(message="缺少当前口令", error_code=APIError.MISSING_PARAMETER,
                                     status_code=400)
        if not isinstance(new_password, str):
            return APIResponse.error(message="缺少新口令", error_code=APIError.MISSING_PARAMETER,
                                     status_code=400)

        errors = validate_fields({"new_password": new_password},
                                 {"new_password": [Length(min_=PASSWORD_MIN_LENGTH,
                                                         max_=PASSWORD_MAX_LENGTH)]})
        if errors:
            return APIResponse.error(message="参数验证失败", error_code=APIError.VALIDATION_ERROR,
                                     status_code=400, details=errors)

        if not account.verify_password(current_password):
            return APIResponse.error(message="当前口令不正确", error_code="INVALID_PASSWORD",
                                     status_code=400)

        account.set_password(new_password)
        await account.save(update_fields=["password"])

        # 改密后旧会话全部失效
        await _invalidate_sessions(account)

        return APIResponse.success(message="口令更新成功")


class AccountMeResource(HTTPMethodView):
    """
    当前登录账户资源（自助，只需登录）。

    * ``GET /api/v1/accounts/me``       当前账户信息（含角色与权限）
    * ``PUT /api/v1/accounts/me``       更新自己的资料（仅白名单字段）
    """

    async def get(self, request: Request):
        """返回当前登录账户的信息、角色与权限。"""
        session = await authenticate_request(request)
        account = session.bearer

        roles = await account.roles.filter(deleted=False).all()
        role_data = [{"id": role.id, "name": role.name, "description": role.description}
                     for role in roles]
        permissions = await get_account_permissions(account)

        data = account_info(account)
        data["roles"] = role_data
        data["permissions"] = permissions

        return APIResponse.success(data=data, message="获取当前账户信息成功")

    async def put(self, request: Request):
        """更新自己的账户资料（只接受 username/email/phone）。"""
        session = await authenticate_request(request)
        account = session.bearer

        payload = request_payload(request)
        # 自助更新不接受 password（改密走 /accounts/me/password）
        data = extract_whitelisted(payload, ("username", "email", "phone"))

        if not data:
            return APIResponse.error(message="没有可更新的字段", error_code=APIError.MISSING_PARAMETER,
                                     status_code=400)

        errors = validate_fields(data, {
            "username": [Length(min_=3, max_=USERNAME_MAX_LENGTH)],
            "email": [Email()],
            "phone": [Length(max_=PHONE_MAX_LENGTH)],
        })
        if errors:
            return APIResponse.error(message="参数验证失败", error_code=APIError.VALIDATION_ERROR,
                                     status_code=400, details=errors)

        username = data.get("username", account.username)
        email = data.get("email", account.email)
        phone = data.get("phone", account.phone)
        if isinstance(username, str):
            username = username.strip()
        if isinstance(email, str):
            email = email.strip()
        if isinstance(phone, str):
            phone = phone.strip() or None

        conflict = await _ensure_unique(account, username, email, phone)
        if conflict:
            return APIResponse.error(message=conflict, error_code="ACCOUNT_EXISTS", status_code=400)

        for key, value in data.items():
            setattr(account, key, value)

        await account.save()

        return APIResponse.success(data=account_info(account), message="账户信息更新成功")


class MyAccountPasswordResource(HTTPMethodView):
    """
    自助改密：``PUT /api/v1/accounts/me/password``（只需登录，只能改自己的口令）。
    """

    async def put(self, request: Request):
        """修改自己的口令；成功后旧会话全部失效。"""
        session = await authenticate_request(request)
        account = session.bearer

        payload = request_payload(request)
        current_password = payload.get("current_password")
        new_password = payload.get("new_password")

        if not isinstance(current_password, str) or not current_password:
            return APIResponse.error(message="缺少当前口令", error_code=APIError.MISSING_PARAMETER,
                                     status_code=400)
        if not isinstance(new_password, str):
            return APIResponse.error(message="缺少新口令", error_code=APIError.MISSING_PARAMETER,
                                     status_code=400)

        errors = validate_fields({"new_password": new_password},
                                 {"new_password": [Length(min_=PASSWORD_MIN_LENGTH,
                                                         max_=PASSWORD_MAX_LENGTH)]})
        if errors:
            return APIResponse.error(message="参数验证失败", error_code=APIError.VALIDATION_ERROR,
                                     status_code=400, details=errors)

        if not account.verify_password(current_password):
            return APIResponse.error(message="当前口令不正确", error_code="INVALID_PASSWORD",
                                     status_code=400)

        account.set_password(new_password)
        await account.save(update_fields=["password"])

        await _invalidate_sessions(account)

        return APIResponse.success(message="口令更新成功")


# 注册路由
# 显式给出路由名：Sanic 23.6 禁止同名路由，同一个视图注册到多个 URI 时
# 会得到相同的隐式名，必须逐条命名。
account_resource = AccountResource()
account_password_resource = AccountPasswordResource()
account_me_resource = AccountMeResource()
my_account_password_resource = MyAccountPasswordResource()

v1_bp.add_route(account_resource.as_view(), "/accounts/<account_id:int>",
                methods=["GET", "PUT", "DELETE"], name="account_detail")
v1_bp.add_route(account_resource.as_view(), "/accounts", methods=["GET", "POST"],
                name="account_list")
v1_bp.add_route(account_password_resource.as_view(), "/accounts/<account_id:int>/password",
                methods=["PUT"], name="account_password")
v1_bp.add_route(account_me_resource.as_view(), "/accounts/me", methods=["GET", "PUT"],
                name="account_me")
v1_bp.add_route(my_account_password_resource.as_view(), "/accounts/me/password",
                methods=["PUT"], name="account_me_password")
