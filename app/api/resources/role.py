#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
角色 API 资源模块，提供角色管理与角色成员管理接口。

安全要点：
* 字段白名单：创建/更新只接受 name/description/permissions。
* 非 admin 不能创建或修改超出自身权限范围的角色（防止"造一个全权限角色再授予自己"）。
* 禁止修改自己拥有的角色（防止通过改角色权限给自己提权）。
* 删除为软删除（``deleted=True``），列表默认过滤已删除角色。
* 授予/回收角色时校验角色权限是否在操作者权限范围内。
"""

from typing import Any, Dict, Optional, Set

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
from app.auth.authorization import check_permissions, get_account_permissions
from app.auth.permissions import (
    all_resources,
    known_actions,
    validate_permissions_dict,
)
from app.api.resources.route_methods import register_view
from app.models import Account, Role

# 创建/更新角色时允许写入的字段（白名单）
ROLE_CREATE_FIELDS = ("name", "description", "permissions")
ROLE_UPDATE_FIELDS = ("name", "description", "permissions")

NAME_MAX_LENGTH = 64
DESCRIPTION_MAX_LENGTH = 255

# 内置角色不可删除
PROTECTED_ROLE_NAMES = ("admin", "user")


def role_info(role: Role) -> Dict[str, Any]:
    """角色的对外表示。"""
    return {
        "id": role.id,
        "name": role.name,
        "description": role.description,
        "permissions": role.permissions,
        "created_at": role.created_at,
        "updated_at": role.updated_at,
    }


async def _granted_permissions(account: Account) -> Dict[str, Set[str]]:
    """
    当前账户实际拥有的权限（资源 -> 操作集合）；admin 账户拥有全部权限。
    """
    if account.is_admin:
        return {"__all__": {"all"}}

    permissions = await get_account_permissions(account)
    return {resource: set(actions) for resource, actions in permissions.items()}


def _permission_allowed(granted: Dict[str, Set[str]], resource: str, action: str) -> bool:
    """判断某资源+操作是否在授权范围内（``all`` 通配）。"""
    if "__all__" in granted:
        return True

    actions = granted.get(resource)
    if not actions:
        return False
    return "all" in actions or action in actions


def _permissions_exceed(granted: Dict[str, Set[str]], permissions: Any) -> Optional[str]:
    """
    检查目标权限是否超出 ``granted`` 范围；超出时返回超出的资源/操作描述。

    返回 None 表示未超出。权限格式非法也返回描述（调用方据此拒绝）。
    """
    if not isinstance(permissions, dict):
        return "permissions 必须是字典"

    for resource, actions in permissions.items():
        if not isinstance(resource, str) or not resource.strip():
            return "permissions 的资源名必须是非空字符串"
        if not isinstance(actions, list):
            return f"资源 '{resource}' 的操作必须是列表"
        for action in actions:
            if not isinstance(action, str) or not action.strip():
                return f"资源 '{resource}' 的操作必须是非空字符串"
            if not _permission_allowed(granted, resource, action):
                return f"权限 '{resource}:{action}' 超出自身权限范围"

    return None


async def _assignable(actor: Account, role: Role) -> Optional[str]:
    """
    actor 是否可以把 ``role`` 授予他人；不可授予时返回原因描述。
    """
    if actor.is_admin:
        return None

    return _permissions_exceed(await _granted_permissions(actor), role.permissions or {})


# ---------------------------------------------------------------------------
# 管理员保护（统一判定）
# ---------------------------------------------------------------------------
#
# 安全要点：受保护的管理员账户不能被非管理员改动。
#
# "管理员"有两种形态，**任一**成立即视为受保护的管理员：
#
# 1. ``Account.is_admin`` 为 True —— 显式管理员标志；
# 2. 持有某个**授予了全部权限的角色**（角色的 permissions 覆盖注册表全部资源）——
#    这种账户在权限上等同于管理员，即使 ``is_admin`` 为 False。
#
# 只看 (1) 是不够的：第 2 类账户同样能改角色、改账户，若不被保护，
# 就能被仅持 ``account:update`` 的非管理员账户撤销 admin 角色 / 改邮箱，
# 形成提权路径。

def _role_grants_all_permissions(role: Role) -> bool:
    """
    该角色是否授予了注册表里的**全部**权限。

    判定口径：角色 permissions 覆盖注册表的每个资源，且每个资源的动作
    为 ``all`` 或该资源的全部已知动作。
    """
    permissions = role.permissions or {}
    if not isinstance(permissions, dict):
        return False

    for resource in all_resources():
        actions = permissions.get(resource)
        if actions is None:
            return False
        if not isinstance(actions, (list, tuple, set)):
            return False

        normalized = {str(action) for action in actions}
        allowed = set(known_actions(resource))
        if "all" not in normalized:
            if not allowed or not allowed.issubset(normalized):
                return False

    return True


async def is_protected_admin(account: Account) -> bool:
    """
    该账户是否是**受保护的管理员**（不允许被非管理员改动）。

    满足任一即返回 True：

    * ``account.is_admin`` 为 True；
    * 账户持有某个授予了全部权限的角色。

    Args:
        account: 目标账户

    Returns:
        bool: 是否为受保护的管理员
    """
    if account.is_admin:
        return True

    roles = await account.roles.filter(deleted=False).all()
    return any(_role_grants_all_permissions(role) for role in roles)


async def actor_may_modify(actor: Account, target: Account) -> bool:
    """
    ``actor`` 是否有权改动 ``target``。

    规则（与"受保护的管理员"判定**对称**）：

    * **管理员**（``is_admin`` 标志 或 持有全权限角色）可以改动任何人；
    * 非管理员**不能**改动受保护的管理员。

    对称性保证"管理员自己可以改动自己"：若 actor 持有全权限角色，
    它本身就是管理员形态，可以像管理员一样操作；若不是，则它不是受保护
    的管理员，改动自己（target=actor）自然放行，不会把自己锁死。
    """
    if await is_protected_admin(actor):
        return True

    return not await is_protected_admin(target)


class RoleResource(HTTPMethodView):
    """
    角色管理资源。

    * ``GET    /api/v1/roles``        角色列表（默认过滤已删除）
    * ``POST   /api/v1/roles``        创建角色
    * ``GET    /api/v1/roles/<id>``   角色详情
    * ``PUT    /api/v1/roles/<id>``   更新角色
    * ``DELETE /api/v1/roles/<id>``   软删除角色
    """

    @check_permissions("role", "read")
    async def get(self, request: Request, role_id: Optional[int] = None):
        """获取角色列表或角色详情。"""
        if role_id is not None:
            role = await Role.filter(id=role_id, deleted=False).first()
            if role is None:
                return APIResponse.error(message="角色不存在", error_code="ROLE_NOT_FOUND",
                                         status_code=404)
            return APIResponse.success(data=role_info(role), message="获取角色成功")

        query = Role.filter(deleted=False)

        keyword = (request.args.get("keyword") or request.args.get("search") or "").strip()
        if keyword:
            from tortoise.expressions import Q
            query = query.filter(Q(name__contains=keyword) | Q(description__contains=keyword))

        page, page_size = parse_pagination(request)
        total = await query.count()
        roles = await query.order_by("name").offset((page - 1) * page_size).limit(page_size)

        return APIResponse.list(items=[role_info(r) for r in roles], total=total, page=page,
                                page_size=page_size, message="获取角色列表成功")

    @check_permissions("role", "create")
    async def post(self, request: Request):
        """创建角色（只接受白名单字段；权限不得超出自身权限范围）。"""
        actor = request.ctx.authentication_session.bearer
        payload = request_payload(request)
        data = extract_whitelisted(payload, ROLE_CREATE_FIELDS)

        errors = validate_fields(data, {
            "name": [Required(), Length(min_=2, max_=NAME_MAX_LENGTH)],
            "description": [Length(max_=DESCRIPTION_MAX_LENGTH)],
            "permissions": [Required(), Type(dict)],
        })
        if errors:
            return APIResponse.error(message="参数验证失败", error_code=APIError.VALIDATION_ERROR,
                                     status_code=400, details=errors)

        name = data["name"].strip()

        if await Role.filter(name=name).exists():
            return APIResponse.error(message="角色名已存在", error_code="ROLE_EXISTS",
                                     status_code=400)

        # 注册表校验：资源/动作必须已登记，避免写入无法生效的权限
        ok, perm_errors = validate_permissions_dict(data["permissions"])
        if not ok:
            return APIResponse.error(message="权限配置无效", error_code=APIError.VALIDATION_ERROR,
                                     status_code=400, details={"permissions": perm_errors})

        exceed = _permissions_exceed(await _granted_permissions(actor), data["permissions"])
        if exceed:
            return APIResponse.error(message=f"无权创建超出自身权限范围的角色：{exceed}",
                                     error_code=APIError.INSUFFICIENT_PERMISSIONS, status_code=403)

        role = await Role.create(
            name=name,
            description=data.get("description"),
            permissions=data["permissions"],
        )

        return APIResponse.created(data=role_info(role), message="角色创建成功",
                                   location=f"/api/v1/roles/{role.id}")

    @check_permissions("role", "update")
    async def put(self, request: Request, role_id: int):
        """更新角色（只接受白名单字段）。"""
        actor = request.ctx.authentication_session.bearer
        role = await Role.filter(id=role_id, deleted=False).first()
        if role is None:
            return APIResponse.error(message="角色不存在", error_code="ROLE_NOT_FOUND",
                                     status_code=404)

        # 禁止修改自己拥有的角色：防止通过改角色权限给自己提权
        if await actor.roles.filter(id=role_id).exists():
            return APIResponse.error(message="不允许修改自己拥有的角色",
                                     error_code=APIError.FORBIDDEN, status_code=403)

        if role.name in PROTECTED_ROLE_NAMES and not actor.is_admin:
            return APIResponse.error(message="不允许修改内置角色",
                                     error_code="CANNOT_MODIFY_BUILTIN_ROLE", status_code=403)

        payload = request_payload(request)
        data = extract_whitelisted(payload, ROLE_UPDATE_FIELDS)

        if not data:
            return APIResponse.error(message="没有可更新的字段", error_code=APIError.MISSING_PARAMETER,
                                     status_code=400)

        errors = validate_fields(data, {
            "name": [Length(min_=2, max_=NAME_MAX_LENGTH)],
            "description": [Length(max_=DESCRIPTION_MAX_LENGTH)],
            "permissions": [Type(dict)],
        })
        if errors:
            return APIResponse.error(message="参数验证失败", error_code=APIError.VALIDATION_ERROR,
                                     status_code=400, details=errors)

        if "name" in data:
            new_name = data["name"].strip()
            if new_name != role.name and await Role.filter(name=new_name).exists():
                return APIResponse.error(message="角色名已存在", error_code="ROLE_EXISTS",
                                         status_code=400)
            data["name"] = new_name

        if "permissions" in data:
            ok, perm_errors = validate_permissions_dict(data["permissions"])
            if not ok:
                return APIResponse.error(message="权限配置无效",
                                         error_code=APIError.VALIDATION_ERROR, status_code=400,
                                         details={"permissions": perm_errors})

            exceed = _permissions_exceed(await _granted_permissions(actor), data["permissions"])
            if exceed:
                return APIResponse.error(
                    message=f"无权设置超出自身权限范围的角色权限：{exceed}",
                    error_code=APIError.INSUFFICIENT_PERMISSIONS, status_code=403)

        for key, value in data.items():
            setattr(role, key, value)

        await role.save()

        return APIResponse.success(data=role_info(role), message="角色更新成功")

    @check_permissions("role", "delete")
    async def delete(self, request: Request, role_id: int):
        """软删除角色。"""
        actor = request.ctx.authentication_session.bearer
        role = await Role.filter(id=role_id, deleted=False).first()
        if role is None:
            return APIResponse.error(message="角色不存在", error_code="ROLE_NOT_FOUND",
                                     status_code=404)

        if await actor.roles.filter(id=role_id).exists():
            return APIResponse.error(message="不允许删除自己拥有的角色",
                                     error_code=APIError.FORBIDDEN, status_code=403)

        if role.name in PROTECTED_ROLE_NAMES:
            return APIResponse.error(message="不允许删除内置角色",
                                     error_code="CANNOT_DELETE_BUILTIN_ROLE", status_code=403)

        in_use = await role.accounts.filter(deleted=False).count()
        if in_use > 0:
            return APIResponse.error(
                message=f"无法删除角色，因为有 {in_use} 个账户正在使用此角色",
                error_code="ROLE_IN_USE", status_code=400)

        role.deleted = True
        await role.save(update_fields=["deleted"])

        return APIResponse.success(message="角色删除成功")


class RoleMembersResource(HTTPMethodView):
    """
    角色成员资源：``/api/v1/roles/<role_id>/members``。
    """

    @check_permissions("role", "read")
    async def get(self, request: Request, role_id: int):
        """查看角色成员。"""
        role = await Role.filter(id=role_id, deleted=False).first()
        if role is None:
            return APIResponse.error(message="角色不存在", error_code="ROLE_NOT_FOUND",
                                     status_code=404)

        page, page_size = parse_pagination(request)
        # 注意：不能先 await 再当 QuerySet 用——await queryset 求值成 list 后，
        # list.count() 是无参方法（统计元素个数），会抛 TypeError 导致 500。
        # 这里保留未求值的 QuerySet，用 SQL COUNT 取总数，再按 id 排序分页。
        query = role.accounts.filter(deleted=False)
        total = await query.count()
        page_items = await query.order_by("id").offset((page - 1) * page_size).limit(page_size)

        from app.api.resources.account import account_info
        items = [account_info(a) for a in page_items]

        return APIResponse.list(items=items, total=total, page=page, page_size=page_size,
                                message=f"获取角色 '{role.name}' 成员成功")

    @check_permissions("role", "update")
    async def post(self, request: Request, role_id: int):
        """给角色添加成员。"""
        actor = request.ctx.authentication_session.bearer
        role = await Role.filter(id=role_id, deleted=False).first()
        if role is None:
            return APIResponse.error(message="角色不存在", error_code="ROLE_NOT_FOUND",
                                     status_code=404)

        exceed = await _assignable(actor, role)
        if exceed:
            return APIResponse.error(message=f"无权授予该角色：{exceed}",
                                     error_code=APIError.INSUFFICIENT_PERMISSIONS, status_code=403)

        payload = request_payload(request)
        account_ids = payload.get("account_ids")
        if not isinstance(account_ids, list) or not account_ids:
            return APIResponse.error(message="account_ids 必须是非空整数列表",
                                     error_code=APIError.INVALID_PARAMETER, status_code=400)
        if not all(isinstance(aid, int) and not isinstance(aid, bool) for aid in account_ids):
            return APIResponse.error(message="account_ids 必须是非空整数列表",
                                     error_code=APIError.INVALID_PARAMETER, status_code=400)

        accounts = await Account.filter(id__in=account_ids, deleted=False).all()
        if len(accounts) != len(set(account_ids)):
            return APIResponse.error(message="部分账户不存在", error_code="ACCOUNTS_NOT_FOUND",
                                     status_code=404)

        # 目标账户检查：非管理员不得把受保护的管理员加入/移出角色
        for account in accounts:
            if not await actor_may_modify(actor, account):
                return APIResponse.error(
                    message=f"无权改动管理员账户 '{account.username}' 的角色",
                    error_code=APIError.FORBIDDEN, status_code=403)

        for account in accounts:
            await role.accounts.add(account)

        return APIResponse.success(message=f"已添加 {len(accounts)} 个账户到角色 '{role.name}'")

    @check_permissions("role", "update")
    async def delete(self, request: Request, role_id: int, account_id: int):
        """从角色中移除成员。"""
        actor = request.ctx.authentication_session.bearer
        role = await Role.filter(id=role_id, deleted=False).first()
        if role is None:
            return APIResponse.error(message="角色不存在", error_code="ROLE_NOT_FOUND",
                                     status_code=404)

        account = await Account.filter(id=account_id, deleted=False).first()
        if account is None:
            return APIResponse.error(message="账户不存在", error_code="ACCOUNT_NOT_FOUND",
                                     status_code=404)

        # 目标账户检查：非管理员不得把受保护的管理员移出角色
        # （否则可借"移除 admin 角色"变相把管理员降权）
        if not await actor_may_modify(actor, account):
            return APIResponse.error(
                message=f"无权改动管理员账户 '{account.username}' 的角色",
                error_code=APIError.FORBIDDEN, status_code=403)

        if not await role.accounts.filter(id=account_id).exists():
            return APIResponse.error(message=f"账户 '{account.username}' 不是角色 '{role.name}' 的成员",
                                     error_code="NOT_ROLE_MEMBER", status_code=400)

        await role.accounts.remove(account)

        return APIResponse.success(message=f"已将账户 '{account.username}' 从角色 '{role.name}' 中移除")


class AccountRolesResource(HTTPMethodView):
    """
    账户角色资源：``/api/v1/accounts/<account_id>/roles``。

    非 admin 只能授予自身已具备全部权限的角色，且不能改动 admin 账户。
    """

    @check_permissions("account", "read")
    async def get(self, request: Request, account_id: int):
        """查看账户拥有的角色。"""
        account = await Account.filter(id=account_id, deleted=False).first()
        if account is None:
            return APIResponse.error(message="账户不存在", error_code="ACCOUNT_NOT_FOUND",
                                     status_code=404)

        roles = await account.roles.filter(deleted=False).all()
        items = [role_info(role) for role in roles]

        return APIResponse.success(data=items, message="获取账户角色成功")

    @check_permissions("account", "update")
    async def post(self, request: Request, account_id: int):
        """给账户授予角色。"""
        actor = request.ctx.authentication_session.bearer
        account = await Account.filter(id=account_id, deleted=False).first()
        if account is None:
            return APIResponse.error(message="账户不存在", error_code="ACCOUNT_NOT_FOUND",
                                     status_code=404)

        if not await actor_may_modify(actor, account):
            return APIResponse.error(message="无权修改管理员账户的角色", error_code=APIError.FORBIDDEN,
                                     status_code=403)

        payload = request_payload(request)
        role_ids = payload.get("role_ids")
        if not isinstance(role_ids, list) or not role_ids:
            return APIResponse.error(message="role_ids 必须是非空整数列表",
                                     error_code=APIError.INVALID_PARAMETER, status_code=400)
        if not all(isinstance(rid, int) and not isinstance(rid, bool) for rid in role_ids):
            return APIResponse.error(message="role_ids 必须是非空整数列表",
                                     error_code=APIError.INVALID_PARAMETER, status_code=400)

        roles = await Role.filter(id__in=role_ids, deleted=False).all()
        if len(roles) != len(set(role_ids)):
            return APIResponse.error(message="部分角色不存在", error_code="ROLES_NOT_FOUND",
                                     status_code=404)

        for role in roles:
            exceed = await _assignable(actor, role)
            if exceed:
                return APIResponse.error(message=f"无权授予角色 '{role.name}'：{exceed}",
                                         error_code=APIError.INSUFFICIENT_PERMISSIONS,
                                         status_code=403)

        for role in roles:
            await account.roles.add(role)

        return APIResponse.success(message=f"已授予 {len(roles)} 个角色")

    @check_permissions("account", "update")
    async def delete(self, request: Request, account_id: int, role_id: int):
        """移除账户的角色。"""
        actor = request.ctx.authentication_session.bearer
        account = await Account.filter(id=account_id, deleted=False).first()
        if account is None:
            return APIResponse.error(message="账户不存在", error_code="ACCOUNT_NOT_FOUND",
                                     status_code=404)

        if not await actor_may_modify(actor, account):
            return APIResponse.error(message="无权修改管理员账户的角色", error_code=APIError.FORBIDDEN,
                                     status_code=403)

        role = await Role.filter(id=role_id, deleted=False).first()
        if role is None:
            return APIResponse.error(message="角色不存在", error_code="ROLE_NOT_FOUND", status_code=404)

        if not await account.roles.filter(id=role_id).exists():
            return APIResponse.error(message=f"账户 '{account.username}' 没有角色 '{role.name}'",
                                     error_code="NO_SUCH_ROLE", status_code=400)

        await account.roles.remove(role)

        return APIResponse.success(message=f"已从账户 '{account.username}' 移除角色 '{role.name}'")


# 注册路由
# 显式给出路由名：Sanic 23.6 禁止同名路由，同一个视图注册到多个 URI 时
# 会得到相同的隐式名，必须逐条命名。
#
# 用 ``register_view``（而不是 ``v1_bp.add_route``）：后者遇到
# ``HTTPMethodView`` 处理器时会**忽略传入的 methods**，按视图类反推方法集，
# 导致 ``POST /roles/<id>`` 命中需要 ``role_id`` 的处理函数 → 缺参数 → **500**；
# 而 Sanic 23.6 对**动态路径**的方法不匹配会把 ``NoMethod`` 转成 ``NotFound``
# → **404**（谎报不存在）。``register_view`` 用 ``Blueprint.route`` 原样注册
# 方法，并给其余方法挂 405 兜底，详见 ``app/api/resources/route_methods.py``。
role_resource = RoleResource()
role_members_resource = RoleMembersResource()
account_roles_resource = AccountRolesResource()

register_view(v1_bp, "/roles/<role_id:int>", role_resource,
              ["GET", "PUT", "DELETE"], "role_detail")
register_view(v1_bp, "/roles", role_resource, ["GET", "POST"], "role_list")
register_view(v1_bp, "/roles/<role_id:int>/members", role_members_resource,
              ["GET", "POST"], "role_members")
register_view(v1_bp, "/roles/<role_id:int>/members/<account_id:int>",
              role_members_resource, ["DELETE"], "role_member_detail")
register_view(v1_bp, "/accounts/<account_id:int>/roles", account_roles_resource,
              ["GET", "POST"], "account_roles")
register_view(v1_bp, "/accounts/<account_id:int>/roles/<role_id:int>",
              account_roles_resource, ["DELETE"], "account_role_detail")
