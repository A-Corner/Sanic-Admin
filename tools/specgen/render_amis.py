# -*- coding: utf-8 -*-
"""
AMIS 渲染层（可替换）：规格 -> AMIS 页面 JSON 与 site.json 菜单项。

AMIS 语法只允许出现在本模块；规格里不得出现。换渲染层 = 换掉本模块。
"""

import json
from typing import Dict, List

from .render_py import MARK
from .schema import CORE_TARGETS, BelongsToSpec, FieldSpec, ResourceSpec

ADAPTOR = "return { status: payload.success ? 0 : 1, msg: payload.message, data: payload.data }"
LIST_ADAPTOR = (
    "return { status: payload.success ? 0 : 1, msg: payload.message, "
    "data: { items: payload.data.items, total: payload.data.pagination.total } }"
)
REQ_ADAPTOR = "return { ...api, url: api.url + '&page_size=' + (api.query && api.query.perPage || api.query && api.query.page_size || 20) }"
# 空串 -> null，避免可选数值/文本字段被写成 ""
CLEAN_ADAPTOR = "Object.keys(api.data).forEach(function (k) { if (api.data[k] === '') { api.data[k] = null; } }); return api;"
MARK_KEY = "x-specgen"


def _display_field(spec: ResourceSpec) -> str:
    for f in spec.fields:
        if f.searchable and f.type == "string":
            return f.name
    for f in spec.fields:
        if f.type == "string":
            return f.name
    return "id"


def _control(f, specs: Dict[str, ResourceSpec]) -> dict:
    if isinstance(f, BelongsToSpec):
        base = {"name": f.column, "label": f.title, "required": f.required}
        if f.target in CORE_TARGETS:
            return {"type": "input-number", "precision": 0, "min": 1, **base}
        t = specs[f.target]
        disp = _display_field(t)
        return {
            "type": "select",
            **base,
            "clearable": not f.required,
            "source": {
                "method": "get",
                "url": f"/api/v1/{t.plural}?page_size=100",
                "adaptor": "return { status: 0, data: { options: ((payload.data && payload.data.items) || []).map(function (i) { return { label: i."
                + disp
                + " + ' #' + i.id, value: i.id }; }) } }",
            },
        }
    c: dict = {"name": f.name, "label": f.title, "required": f.required}
    if f.choices is not None:
        c["type"] = "select"
        c["options"] = [{"label": str(v), "value": v} for v in f.choices]
        c["clearable"] = not f.required
    elif f.type == "string":
        c["type"] = "input-email" if f.format == "email" else "input-text"
        c["maxLength"] = f.max_length
    elif f.type == "text":
        c["type"] = "textarea"
    elif f.type == "int":
        c.update({"type": "input-number", "precision": 0})
    elif f.type == "float":
        c["type"] = "input-number"
    elif f.type == "bool":
        c["type"] = "switch"
    if f.default is not None:
        c["value"] = f.default
    return c


def _api(method: str, url: str, extra: dict = None) -> dict:
    d = {"method": method, "url": url, "dataType": "json", "adaptor": ADAPTOR}
    d.update(extra or {})
    return d


def render_page(spec: ResourceSpec, specs: Dict[str, ResourceSpec]) -> str:
    url = f"/api/v1/{spec.plural}"
    controls = [_control(f, specs) for f in [*spec.fields, *spec.belongs_to]]
    columns: List[dict] = [{"type": "text", "label": "ID", "name": "id", "width": 60}]
    for f in [*spec.fields, *spec.belongs_to]:
        if not f.list:
            continue
        name = f.column if isinstance(f, BelongsToSpec) else f.name
        col = {"type": "text", "label": f.title, "name": name, "placeholder": "-"}
        if isinstance(f, FieldSpec) and f.type == "bool":
            col = {"type": "status", "label": f.title, "name": name}
        columns.append(col)
    columns.append({"type": "date", "label": "创建时间", "name": "created_at"})
    columns.append(
        {
            "type": "operation",
            "label": "操作",
            "buttons": [
                {
                    "type": "button",
                    "label": "编辑",
                    "level": "link",
                    "actionType": "dialog",
                    "dialog": {
                        "title": f"编辑{spec.label}",
                        "body": {
                            "type": "form",
                            "initApi": _api("get", f"{url}/${{id}}"),
                            "dataType": "json",
                            "adaptor": ADAPTOR,
                            "api": _api("put", f"{url}/${{id}}", {"requestAdaptor": CLEAN_ADAPTOR}),
                            "body": controls,
                        },
                    },
                },
                {
                    "type": "button",
                    "label": "删除",
                    "level": "danger",
                    "actionType": "ajax",
                    "confirmText": f"确定要删除该{spec.label}吗？",
                    "api": _api("delete", f"{url}/${{id}}"),
                },
            ],
        }
    )
    page: dict = {
        "_generated": MARK,
        "_spec": f"{spec.source} (sha256:{spec.digest})",
        "type": "crud",
        "id": f"{spec.resource}-list",
        "name": spec.resource,
        "syncLocation": False,
        "api": {"method": "get", "url": url, "dataType": "json", "adaptor": LIST_ADAPTOR, "requestAdaptor": REQ_ADAPTOR},
        "columns": columns,
    }
    if any(f.searchable for f in spec.fields):
        page["filter"] = {
            "submitText": "",
            "controls": [{"type": "text", "name": "keyword", "label": "搜索", "placeholder": "关键字"}],
        }
    page["bulkActions"] = []
    page["headerToolbar"] = [
        {
            "type": "button",
            "label": f"新增{spec.label}",
            "level": "primary",
            "actionType": "dialog",
            "dialog": {
                "title": f"新增{spec.label}",
                "body": {"type": "form", "api": _api("post", url, {"requestAdaptor": CLEAN_ADAPTOR}), "body": controls},
            },
        }
    ]
    page["footerToolbar"] = [{"type": "statistics"}, {"type": "pagination"}]
    page["perPage"] = 20
    page["alwaysShowPagination"] = True
    return json.dumps(page, ensure_ascii=False, indent=2) + "\n"


def menu_entry(spec: ResourceSpec) -> dict:
    icon = spec.menu.icon
    icon = icon if icon.startswith("fa ") else f"fa {icon}"
    return {
        "label": spec.menu.label or f"{spec.label}管理",
        "url": f"/{spec.resource}",
        "redirect": f"/{spec.resource}/list",
        "icon": icon,
        "children": [
            {
                "label": f"{spec.label}列表",
                "url": f"/{spec.resource}/list",
                "icon": "fa fa-list",
                "schemaApi": f"get:pages/{spec.resource}-list.json?v={spec.digest}",
            }
        ],
        MARK_KEY: spec.resource,
    }


def merge_site(site_text: str, specs: Dict[str, ResourceSpec]) -> str:
    """把生成的菜单项并入 site.json：先剔除全部带 x-specgen 标记的项，再按 (order, resource) 追加。"""
    site = json.loads(site_text)
    pages = [p for p in site["data"]["pages"] if MARK_KEY not in p]
    pages += [menu_entry(s) for s in sorted(specs.values(), key=lambda s: (s.menu.order, s.resource))]
    site["data"]["pages"] = pages
    return json.dumps(site, ensure_ascii=False, indent=2) + "\n"
