#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
系统设置 API 资源模块

安全要点：

* **所有接口都需要登录**（CPL 裁定：不再是"未登录可读 public 设置"）。
  读用资源 ``setting`` 的 ``read`` 动作，写用 ``update`` 动作。
* **字段白名单防 mass-assignment**：只接受 ``key`` / ``value`` / ``value_type`` /
  ``description`` / ``category`` / ``is_public`` 六个字段，其余字段一律忽略。
* **设置键白名单**：只接受注册过的设置键（``ALLOWED_SETTING_KEYS``），
  防止通过任意 key 写入系统配置；未注册的键一律 400。
* **错误响应统一走 ``APIResponse.error``**，不把内部异常 ``str(e)`` 透给用户。
* 路由名显式指定（``name=``），避免同一个 view 类注册两次时 Sanic 报
  ``Duplicate route names detected`` 导致应用起不来。
"""

import json
from typing import Any, Dict, List, Optional

from sanic.request import Request
from sanic.views import HTTPMethodView

from app.api import APIResponse, v1_bp
from app.api.responses import APIError
from app.api.resources.route_methods import register_view
from app.api.validators import parse_pagination
from app.auth.authorization import check_permissions
from app.models import SystemSetting

#: 允许写入的设置键白名单（防 mass-assignment / 防写入任意系统配置）
ALLOWED_SETTING_KEYS = frozenset({
    "site_name",
    "site_description",
    "site_logo",
    "site_footer",
    "pagination_size",
    "theme",
    "language",
    "timezone",
})

#: 允许的字段（写入时的白名单；``key`` 只在创建时可用）
WRITABLE_FIELDS = ("key", "value", "value_type", "description", "category", "is_public")

#: 允许的值类型
VALUE_TYPES = ("string", "int", "float", "bool", "json")

#: 分页上限
MAX_PAGE_SIZE = 100

#: ``description`` 字段长度上限（与模型 ``CharField(max_length=255)`` 对齐）
DESCRIPTION_MAX_LENGTH = 255

#: ``category`` 字段长度上限（与模型 ``CharField(max_length=50)`` 对齐）
CATEGORY_MAX_LENGTH = 50

#: ``value`` 落库字符串的长度上限。
#: ``SystemSetting.value`` 是 TextField，数据库层没有长度限制；不设上限时单条
#: 配置可以膨胀到请求体上限（16MB），读接口会把整行原样回传，足以拖垮列表
#: 接口，而没有任何真实配置需要这么长。8192 字符足以容纳一段 JSON 或一段
#: 富文本公告，又只是请求体上限的 1/2048 —— 超过它的 value 只可能是滥用
#: 或客户端 bug，直接 400。
VALUE_MAX_LENGTH = 8192

#: 布尔字段的合法字符串取值（供 ``is_public`` 解析）
_TRUE_STRINGS = ("true", "1", "yes", "on")
_FALSE_STRINGS = ("false", "0", "no", "off")


def _parse_bool(value: Any) -> Optional[bool]:
    """
    解析布尔字段。

    **不能直接用 ``bool(value)``**：``bool("false")`` 是 ``True``（非空字符串为真），
    客户端传 JSON 字符串 ``"false"`` 会被当成 True 写进库。

    支持：真正的布尔值、``"true"/"false"``、``"1"/"0"``、``"yes"/"no"``、
    ``"on"/"off"``（大小写不敏感），以及数值 0/1。

    Args:
        value: 原始值

    Returns:
        Optional[bool]: 解析结果；无法解析时返回 None
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in _TRUE_STRINGS:
            return True
        if text in _FALSE_STRINGS:
            return False
    return None


def _validate_text_fields(data: Dict[str, Any]) -> Optional[str]:
    """
    校验 ``description`` / ``category`` 这类文本字段。

    检查项：

    * 必须是字符串（否则会被字符串化落库，如 dict 变成 ``"{'a': 1}"``）；
    * 长度不超过模型字段上限（超长会被数据库截断或报错）。

    Args:
        data: 白名单提取后的待写入数据

    Returns:
        Optional[str]: 错误描述；校验通过返回 None
    """
    for field, max_length in (("description", DESCRIPTION_MAX_LENGTH),
                              ("category", CATEGORY_MAX_LENGTH)):
        if field not in data:
            continue
        value = data[field]
        if value is None:
            # ``None`` 是**显式提供的非法值**，不是"未提供该字段"：
            # category 的模型字段不允许 null（default="general"），
            # 若放行 None 会在落库时抛 ValidationError → 500。
            # description 允许 null，但"清空说明"与"不修改"无法区分，
            # 统一按非法值拒绝更安全。
            return f"{field} 不能是 null"
        if not isinstance(value, str):
            return f"{field} 必须是字符串"
        if len(value) > max_length:
            return f"{field} 长度不能超过 {max_length} 个字符"
    return None


def _bad_request(message: str, details: Any = None):
    """统一的 400 响应。"""
    return APIResponse.error(
        message=message,
        error_code=APIError.VALIDATION_ERROR,
        status_code=400,
        details=details,
    )


def _forbidden(message: str = "权限不足，无法执行此操作"):
    """统一的 403 响应。"""
    return APIResponse.error(
        message=message,
        error_code=APIError.INSUFFICIENT_PERMISSIONS,
        status_code=403,
    )


def _not_found(message: str = "设置不存在"):
    """统一的 404 响应。"""
    return APIResponse.error(
        message=message,
        error_code=APIError.RESOURCE_NOT_FOUND,
        status_code=404,
    )


def format_setting(setting: SystemSetting) -> Dict[str, Any]:
    """把设置模型格式化为 API 响应字典（按 value_type 解释 value）。"""
    formatted_value: Any = setting.value
    try:
        if setting.value_type == "int":
            formatted_value = int(setting.value)
        elif setting.value_type == "float":
            formatted_value = float(setting.value)
        elif setting.value_type == "bool":
            formatted_value = setting.value.lower() == "true"
        elif setting.value_type == "json":
            formatted_value = json.loads(setting.value)
    except (ValueError, TypeError, json.JSONDecodeError):
        # 解释失败时保留原始字符串，不让读接口整体失败
        formatted_value = setting.value

    return {
        "id": setting.id,
        "key": setting.key,
        "value": formatted_value,
        "raw_value": setting.value,
        "value_type": setting.value_type,
        "description": setting.description,
        "category": setting.category,
        "is_public": setting.is_public,
        "created_at": setting.created_at.isoformat(),
        "updated_at": setting.updated_at.isoformat(),
    }


def validate_value_type(value: Any, value_type: str) -> Optional[str]:
    """
    校验值是否匹配声明的类型，不匹配时返回错误说明，匹配返回 None。
    """
    # null 不是合法值：``str(None)`` 会落库成字面量 "None"，
    # 读回来时又被当作有效配置 —— 配置里出现字符串 "None" 比报错更糟。
    if value is None:
        return "value 不能是 null"
    try:
        if value_type == "int":
            int(value)
        elif value_type == "float":
            float(value)
        elif value_type == "bool":
            if not isinstance(value, bool) and str(value).lower() not in ("true", "false"):
                return "布尔值必须是 true 或 false"
        elif value_type == "json":
            if isinstance(value, (dict, list)):
                pass  # 已经是 JSON 对象
            else:
                json.loads(str(value))
        elif value_type == "string":
            # string 类型此前没有任何校验分支，导致 value=null 穿过校验
            if not isinstance(value, str):
                return "值必须是字符串"
    except (ValueError, TypeError, json.JSONDecodeError):
        return f"值与声明的类型 {value_type} 不匹配"
    return None


def _pick_writable(payload: Dict[str, Any], *, allow_key: bool) -> Dict[str, Any]:
    """按白名单过滤请求体，忽略其余字段（防 mass-assignment）。"""
    fields = WRITABLE_FIELDS if allow_key else tuple(f for f in WRITABLE_FIELDS if f != "key")
    return {name: payload[name] for name in fields if name in payload}


def _store_value(value: Any, value_type: str) -> str:
    """按类型把值转成入库用的字符串。"""
    if value_type == "json" and isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _validate_value_length(value: Any, value_type: str) -> Optional[str]:
    """
    校验 value **落库后的最终字符串**长度，超限返回错误说明，通过返回 None。

    钳制对象必须是 ``_store_value`` 的产物，而不是请求体里 value 的原始形态：
    json 类型的 dict/list 会以 ``json.dumps`` 字符串落库，int/float/bool 也会被
    字符串化，落库长度与请求体里的形态可能不同。以落库产物为准，才能保证
    "库里不会出现超过上限的 value"。
    """
    if len(_store_value(value, value_type)) > VALUE_MAX_LENGTH:
        return f"value 长度不能超过 {VALUE_MAX_LENGTH} 个字符"
    return None


def _read_payload(request: Request) -> Optional[Dict[str, Any]]:
    """读取 JSON 请求体；不是 JSON 对象时返回 None。"""
    body = request.json
    if body is None:
        return {}
    if not isinstance(body, dict):
        return None
    return body


class SettingResource(HTTPMethodView):
    """
    系统设置集合资源

    * ``GET /api/v1/settings`` —— 设置列表（需 ``setting:read``）
    * ``POST /api/v1/settings`` —— 新建设置（需 ``setting:update``）

    注意：``HTTPMethodView.as_view()`` 会用类实现的方法覆盖 ``methods`` 参数，
    因此集合路由与单项路由必须分成两个 view 类，否则两个路径都会注册全部动词。
    """

    @check_permissions("setting", "read")
    async def get(self, request: Request):
        """获取设置列表。"""
        # 用 parse_pagination 而不是自带的 _positive_int：页码被钳制到 MAX_PAGE，
        # 否则超大 page 会让 OFFSET 溢出 SQLite 整数范围 → IntegrityError → 500。
        page, page_size = parse_pagination(request, 20, MAX_PAGE_SIZE)

        query = SystemSetting.filter(deleted=False)
        category = request.args.get("category")
        if category:
            query = query.filter(category=category)
        search = request.args.get("search")
        if search:
            query = query.filter(key__contains=search)

        total = await query.count()
        settings = await query.order_by("key").offset((page - 1) * page_size).limit(page_size)

        return APIResponse.list(
            items=[format_setting(s) for s in settings],
            total=total,
            page=page,
            page_size=page_size,
            message="获取系统设置列表成功",
        )

    @check_permissions("setting", "update")
    async def post(self, request: Request):
        """新建设置（key 必须在白名单内）。"""
        payload = _read_payload(request)
        if payload is None:
            return _bad_request("请求体必须是 JSON 对象")

        data = _pick_writable(payload, allow_key=True)
        key = data.get("key")
        if not key or not isinstance(key, str):
            return _bad_request("key 是必填项")
        if key not in ALLOWED_SETTING_KEYS:
            return _bad_request(
                f"设置键 '{key}' 不在允许的设置键白名单内",
                details={"allowed_keys": sorted(ALLOWED_SETTING_KEYS)},
            )
        if "value" not in data:
            return _bad_request("value 是必填项")

        value_type = data.get("value_type", "string")
        if value_type not in VALUE_TYPES:
            return _bad_request(f"value_type 必须是 {', '.join(VALUE_TYPES)} 之一")

        error = validate_value_type(data["value"], value_type)
        if error:
            return _bad_request(error)

        # value 落库字符串长度上限（四条写路径统一校验）
        length_error = _validate_value_length(data["value"], value_type)
        if length_error:
            return _bad_request(length_error)

        text_error = _validate_text_fields(data)
        if text_error:
            return _bad_request(text_error)

        # is_public 显式解析：bool("false") 是 True，直接 bool() 会把
        # 客户端传的字符串 "false" 存成 True。
        is_public = _parse_bool(data.get("is_public", False))
        if is_public is None:
            return _bad_request("is_public 必须是布尔值，或 'true'/'false'/'1'/'0'/'yes'/'no'/'on'/'off' 字符串（大小写不敏感）")

        # key 在模型上是唯一列，软删除的记录**仍然占用** key。
        # 因此这里不过滤 deleted：
        #   * 未删除的同 key 已存在 → 409（语义正确）；
        #   * 只有软删除的同 key → 把那条记录"复活"（清掉 deleted 并写入新值），
        #     否则新建会撞唯一约束（IntegrityError → 500），
        #     且软删除后同 key 永远无法重建（原先 exists() 不过滤 deleted → 死锁 409）。
        existing = await SystemSetting.filter(key=key).first()
        if existing is not None and not existing.deleted:
            return APIResponse.error(
                message=f"设置键 '{key}' 已存在",
                error_code=APIError.CONFLICT,
                status_code=409,
            )

        if existing is not None:
            # 复活软删除的同 key 记录
            existing.value = _store_value(data["value"], value_type)
            existing.value_type = value_type
            existing.description = data.get("description")
            existing.category = data.get("category", "general")
            existing.is_public = is_public
            existing.deleted = False
            await existing.save()
            setting = existing
        else:
            setting = await SystemSetting.create(
                key=key,
                value=_store_value(data["value"], value_type),
                value_type=value_type,
                description=data.get("description"),
                category=data.get("category", "general"),
                is_public=is_public,
            )
        return APIResponse.created(
            data=format_setting(setting),
            message="创建系统设置成功",
            location=f"/api/v1/settings/{setting.id}",
        )

class SettingItemResource(HTTPMethodView):
    """
    单个系统设置资源

    * ``GET /api/v1/settings/<id>`` —— 获取单个设置（需 ``setting:read``）
    * ``PUT /api/v1/settings/<id>`` —— 更新设置（需 ``setting:update``）
    * ``DELETE /api/v1/settings/<id>`` —— 删除设置（需 ``setting:update``）
    """

    @check_permissions("setting", "read")
    async def get(self, request: Request, setting_id: int):
        """获取单个设置。"""
        setting = await SystemSetting.filter(id=setting_id, deleted=False).first()
        if setting is None:
            return _not_found(f"设置 {setting_id} 不存在")
        return APIResponse.success(data=format_setting(setting), message="获取系统设置成功")

    @check_permissions("setting", "update")
    async def put(self, request: Request, setting_id: int):
        """更新设置（不能改 key）。"""
        payload = _read_payload(request)
        if payload is None:
            return _bad_request("请求体必须是 JSON 对象")

        setting = await SystemSetting.filter(id=setting_id, deleted=False).first()
        if setting is None:
            return _not_found(f"设置 {setting_id} 不存在")

        data = _pick_writable(payload, allow_key=False)
        if "value" not in data:
            return _bad_request("value 是必填项")

        value_type = data.get("value_type", setting.value_type)
        if value_type not in VALUE_TYPES:
            return _bad_request(f"value_type 必须是 {', '.join(VALUE_TYPES)} 之一")

        error = validate_value_type(data["value"], value_type)
        if error:
            return _bad_request(error)

        # value 落库字符串长度上限（四条写路径统一校验）
        length_error = _validate_value_length(data["value"], value_type)
        if length_error:
            return _bad_request(length_error)

        text_error = _validate_text_fields(data)
        if text_error:
            return _bad_request(text_error)

        setting.value = _store_value(data["value"], value_type)
        setting.value_type = value_type
        if "description" in data:
            setting.description = data["description"]
        if "category" in data:
            setting.category = data["category"]
        if "is_public" in data:
            # 显式解析：bool("false") 是 True，会把字符串 "false" 存成 True
            is_public = _parse_bool(data["is_public"])
            if is_public is None:
                return _bad_request("is_public 必须是布尔值，或 'true'/'false'/'1'/'0'/'yes'/'no'/'on'/'off' 字符串（大小写不敏感）")
            setting.is_public = is_public
        await setting.save()

        return APIResponse.success(data=format_setting(setting), message="更新系统设置成功")

    @check_permissions("setting", "update")
    async def delete(self, request: Request, setting_id: int):
        """删除设置（软删除）。"""
        setting = await SystemSetting.filter(id=setting_id, deleted=False).first()
        if setting is None:
            return _not_found(f"设置 {setting_id} 不存在")

        setting.deleted = True
        await setting.save(update_fields=["deleted"])
        return APIResponse.success(message="删除系统设置成功")


class SettingByKeyResource(HTTPMethodView):
    """按键获取 / 更新设置"""

    @check_permissions("setting", "read")
    async def get(self, request: Request, key: str):
        """按 key 获取设置。"""
        setting = await SystemSetting.filter(key=key, deleted=False).first()
        if setting is None:
            return _not_found(f"设置键 '{key}' 不存在")
        return APIResponse.success(data=format_setting(setting), message="获取系统设置成功")

    @check_permissions("setting", "update")
    async def put(self, request: Request, key: str):
        """按 key 更新设置值。"""
        payload = _read_payload(request)
        if payload is None:
            return _bad_request("请求体必须是 JSON 对象")

        setting = await SystemSetting.filter(key=key, deleted=False).first()
        if setting is None:
            return _not_found(f"设置键 '{key}' 不存在")

        data = _pick_writable(payload, allow_key=False)
        if "value" not in data:
            return _bad_request("value 是必填项")

        value_type = data.get("value_type", setting.value_type)
        if value_type not in VALUE_TYPES:
            return _bad_request(f"value_type 必须是 {', '.join(VALUE_TYPES)} 之一")

        error = validate_value_type(data["value"], value_type)
        if error:
            return _bad_request(error)

        # value 落库字符串长度上限（四条写路径统一校验）
        length_error = _validate_value_length(data["value"], value_type)
        if length_error:
            return _bad_request(length_error)

        text_error = _validate_text_fields(data)
        if text_error:
            return _bad_request(text_error)

        setting.value = _store_value(data["value"], value_type)
        setting.value_type = value_type
        if "description" in data:
            setting.description = data["description"]
        if "category" in data:
            setting.category = data["category"]
        if "is_public" in data:
            # 显式解析：bool("false") 是 True，会把字符串 "false" 存成 True
            is_public = _parse_bool(data["is_public"])
            if is_public is None:
                return _bad_request("is_public 必须是布尔值，或 'true'/'false'/'1'/'0'/'yes'/'no'/'on'/'off' 字符串（大小写不敏感）")
            setting.is_public = is_public
        await setting.save()

        return APIResponse.success(data=format_setting(setting), message="更新系统设置成功")


class SettingBulkResource(HTTPMethodView):
    """批量获取 / 更新设置"""

    @check_permissions("setting", "read")
    async def get(self, request: Request):
        """按 keys 批量获取设置（逗号分隔）。"""
        raw_keys = request.args.get("keys", "")
        keys = [k.strip() for k in raw_keys.split(",") if k.strip()]
        if not keys:
            return _bad_request("必须提供设置键列表（keys，逗号分隔）")

        settings = await SystemSetting.filter(key__in=keys, deleted=False).all()
        found = {s.key: s for s in settings}
        missing = [k for k in keys if k not in found]

        return APIResponse.success(
            data={
                "settings": {k: format_setting(found[k]) for k in keys if k in found},
                "missing_keys": missing,
            },
            message="批量获取系统设置成功",
        )

    @check_permissions("setting", "update")
    async def put(self, request: Request):
        """批量更新设置（只更新已存在的键，逐条返回结果）。"""
        payload = _read_payload(request)
        if payload is None:
            return _bad_request("请求体必须是 JSON 对象")

        settings_data = payload.get("settings")
        if not isinstance(settings_data, dict) or not settings_data:
            return _bad_request("settings 必须是非空的 JSON 对象")

        existing = await SystemSetting.filter(key__in=list(settings_data.keys()), deleted=False).all()
        known = {s.key: s for s in existing}

        # value 长度整体预检：任一 value 超限 → 400，整批不落库（四条写路径
        # 统一返回 400 VALIDATION_ERROR）。不做"跳过超限项、继续更新其余项"，
        # 避免部分成功掩盖超限写入；不存在的 key 仍走下方逐条错误路径。
        for key, value in settings_data.items():
            known_setting = known.get(key)
            if known_setting is None:
                continue
            length_error = _validate_value_length(value, known_setting.value_type)
            if length_error:
                return _bad_request(f"{length_error}（key: {key}）")

        updated: List[Dict[str, Any]] = []
        errors: List[Dict[str, str]] = []

        for key, value in settings_data.items():
            if key not in known:
                errors.append({"key": key, "error": "设置不存在"})
                continue

            setting = known[key]
            value_type = setting.value_type
            error = validate_value_type(value, value_type)
            if error:
                errors.append({"key": key, "error": error})
                continue

            setting.value = _store_value(value, value_type)
            await setting.save(update_fields=["value", "updated_at"])
            updated.append(format_setting(setting))

        return APIResponse.success(
            data={"updated": updated, "errors": errors},
            message=f"已成功更新 {len(updated)} 项设置，{len(errors)} 项失败",
        )


# 注册路由（显式指定路由名：同一个 view 类注册两次时 Sanic 会报路由名重复）
# 用 ``register_view``（而不是 ``v1_bp.add_route``）：后者遇到 ``HTTPMethodView``
# 处理器时会**忽略传入的 methods**，按视图类反推方法集；而 Sanic 23.6 对
# **动态路径**的方法不匹配会把 ``NoMethod`` 转成 ``NotFound`` → **404**
# （谎报资源不存在）。``register_view`` 用 ``Blueprint.route`` 原样注册方法，
# 并给其余方法挂 405 兜底，详见 ``app/api/resources/route_methods.py``。
setting_resource = SettingResource()
setting_item_resource = SettingItemResource()
setting_by_key_resource = SettingByKeyResource()
setting_bulk_resource = SettingBulkResource()

register_view(v1_bp, "/settings", setting_resource, ["GET", "POST"], "setting_collection")
register_view(v1_bp, "/settings/<setting_id:int>", setting_item_resource,
              ["GET", "PUT", "DELETE"], "setting_item")
register_view(v1_bp, "/settings/key/<key:str>", setting_by_key_resource,
              ["GET", "PUT"], "setting_by_key")
register_view(v1_bp, "/settings/bulk", setting_bulk_resource, ["GET", "PUT"], "setting_bulk")
