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
        "created_at": str(setting.created_at),
        "updated_at": str(setting.updated_at),
    }


def validate_value_type(value: Any, value_type: str) -> Optional[str]:
    """
    校验值是否匹配声明的类型，不匹配时返回错误说明，匹配返回 None。
    """
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
        page = _positive_int(request.args.get("page"), 1)
        page_size = min(_positive_int(request.args.get("page_size"), 20), MAX_PAGE_SIZE)

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

        if await SystemSetting.filter(key=key).exists():
            return APIResponse.error(
                message=f"设置键 '{key}' 已存在",
                error_code=APIError.CONFLICT,
                status_code=409,
            )

        setting = await SystemSetting.create(
            key=key,
            value=_store_value(data["value"], value_type),
            value_type=value_type,
            description=data.get("description"),
            category=data.get("category", "general"),
            is_public=bool(data.get("is_public", False)),
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

        setting.value = _store_value(data["value"], value_type)
        setting.value_type = value_type
        if "description" in data:
            setting.description = data["description"]
        if "category" in data:
            setting.category = data["category"]
        if "is_public" in data:
            setting.is_public = bool(data["is_public"])
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

        setting.value = _store_value(data["value"], value_type)
        setting.value_type = value_type
        if "description" in data:
            setting.description = data["description"]
        if "category" in data:
            setting.category = data["category"]
        if "is_public" in data:
            setting.is_public = bool(data["is_public"])
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


def _positive_int(value: Any, default: int) -> int:
    """把请求参数解析为正整数，非法时回落到默认值。"""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


# 注册路由（显式指定路由名：同一个 view 类注册两次时 Sanic 会报路由名重复）
setting_resource = SettingResource()
setting_item_resource = SettingItemResource()
setting_by_key_resource = SettingByKeyResource()
setting_bulk_resource = SettingBulkResource()

v1_bp.add_route(setting_resource.as_view(), "/settings", methods=["GET", "POST"], name="setting_collection")
v1_bp.add_route(setting_item_resource.as_view(), "/settings/<setting_id:int>", methods=["GET", "PUT", "DELETE"], name="setting_item")
v1_bp.add_route(setting_by_key_resource.as_view(), "/settings/key/<key:str>", methods=["GET", "PUT"], name="setting_by_key")
v1_bp.add_route(setting_bulk_resource.as_view(), "/settings/bulk", methods=["GET", "PUT"], name="setting_bulk")
