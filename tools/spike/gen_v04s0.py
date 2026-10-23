#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
SA-v04-S0 spike：最小规格生成器。

读取一份资源规格 YAML，产出四类工件：
  1. app/models/<resource>.py        —— Tortoise 模型
  2. app/api/resources/<resource>.py —— CRUD API（register_view + requires_permission）
  3. amis/pages/<resource>-list.json —— AMIS CRUD 页面
  4. tests/test_<resource>_spike.py  —— 契约测试

刻意保留的「手工接线」边界（见 gen 输出末尾的 WIRING 清单）：
  - app/models/__init__.py 的 import 与 __all__
  - app/api/resources/__init__.py 的模块 import（触发路由注册）
  - app/auth/permissions.py 的 ALL_PERMISSIONS 注册
  - amis/pages/site.json 的菜单 schemaApi
每处接线都只是一个单行/小块编辑——S0 结论之一就是量化这些边的自动化成本。

用法：python tools/spike/gen_v04s0.py spike/customer.yaml
"""
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent

MODEL_TPL = '''#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""{label}模型（由 SA-v04-S0 spike 生成器产出，规格：spike/{spec}）。"""
from tortoise import fields
from app.models.base import BaseModel


class {Class}(BaseModel):
    """
    {description}

    Attributes:
{attr_docs}
    """
{field_defs}

    class Meta:
        table = "{table}"

    @property
    def json(self) -> dict:
        return {{
            "id": self.id,
{json_fields}
            "created_at": str(self.created_at),
            "updated_at": str(self.updated_at),
        }}

    def validate(self) -> None:
        """{label}没有额外的状态约束。"""
'''

RESOURCE_TPL = '''#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
{label} API 资源模块（由 SA-v04-S0 spike 生成器产出）。

CRUD 全部走 ``requires_permission("{resource}:<action>")``，字段白名单与
规格（spike/{spec}）一致。
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
from app.models import {Class}

{upper} = "{resource}"

FIELD_RULES = {{
{field_rules}
}}

#: 允许写入的字段（白名单，来自规格）
WRITE_FIELDS = ({write_fields})


def {resource}_info(obj: {Class}) -> dict:
    """对外表示（模型 json 属性透传）。"""
    return obj.json


class {Class}Resource(HTTPMethodView):
    """{label} 列表 / 详情 / 创建 / 更新 / 删除。"""

    @requires_permission("{resource}:read")
    async def get(self, request: Request, {resource}_id: int = None):
        """获取{label}列表或详情。"""
        if {resource}_id is not None:
            obj = await {Class}.filter(id={resource}_id).first()
            if obj is None:
                return APIResponse.error(
                    message="{label}不存在", error_code="{upper}_NOT_FOUND",
                    status_code=404)
            return APIResponse.success(data={resource}_info(obj),
                                       message="获取{label}成功")

        query = {Class}.all()
        keyword = (request.args.get("keyword") or "").strip()
        if keyword:
            from tortoise.expressions import Q
            conds = Q()
            for f in {searchable}:
                conds |= Q(**{{f + "__contains": keyword}})
            query = query.filter(conds)

        page, page_size = parse_pagination(request)
        total = await query.count()
        rows = await query.order_by("-id").offset((page - 1) * page_size).limit(page_size)
        return APIResponse.list(items=[{resource}_info(r) for r in rows],
                                total=total, page=page, page_size=page_size,
                                message="获取{label}列表成功")

    @requires_permission("{resource}:create")
    async def post(self, request: Request):
        """创建{label}。"""
        # 与 role.py 同款两步：先白名单提取，再对提取结果做规则校验
        payload = extract_whitelisted(request_payload(request), WRITE_FIELDS)
        errors = validate_fields(payload, FIELD_RULES)
        if errors:
            return APIResponse.error(message="参数验证失败",
                                     error_code=APIError.VALIDATION_ERROR,
                                     status_code=400, details=errors)
        obj = await {Class}.create(**payload)
        return APIResponse.created(data={resource}_info(obj),
                                   message="创建{label}成功",
                                   location=f"/api/v1/{resource}s/{{obj.id}}")

    @requires_permission("{resource}:update")
    async def put(self, request: Request, {resource}_id: int):
        """更新{label}。"""
        obj = await {Class}.filter(id={resource}_id).first()
        if obj is None:
            return APIResponse.error(message="{label}不存在",
                                     error_code="{upper}_NOT_FOUND",
                                     status_code=404)
        payload = extract_whitelisted(request_payload(request), WRITE_FIELDS)
        if not payload:
            return APIResponse.error(message="没有可更新的字段",
                                     error_code=APIError.MISSING_PARAMETER,
                                     status_code=400)
        for name, value in payload.items():
            setattr(obj, name, value)
        await obj.save()
        return APIResponse.success(data={resource}_info(obj), message="{label}更新成功")

    @requires_permission("{resource}:delete")
    async def delete(self, request: Request, {resource}_id: int):
        """删除{label}（spike 为物理删除；生产化应评估软删除）。"""
        obj = await {Class}.filter(id={resource}_id).first()
        if obj is None:
            return APIResponse.error(message="{label}不存在",
                                     error_code="{upper}_NOT_FOUND",
                                     status_code=404)
        await obj.delete()
        return APIResponse.success(message="删除{label}成功")


# 路由注册（register_view 会为未实现的方法挂 405 兜底）
register_view(v1_bp, "/{resource}s/<{resource}_id:int>", {Class}Resource,
              ["GET", "PUT", "DELETE"], "{resource}_detail")
register_view(v1_bp, "/{resource}s", {Class}Resource, ["GET", "POST"],
              "{resource}_list")
'''

PAGE_TPL = """{
    "type": "crud",
    "id": "__RESOURCE__-list",
    "name": "__RESOURCE__",
    "syncLocation": false,
    "api": {
        "method": "get",
        "url": "/api/v1/__RESOURCE__s",
        "dataType": "json",
        "adaptor": "return { status: payload.success ? 0 : 1, msg: payload.message, data: { items: payload.data.items, total: payload.data.pagination.total } }",
        "requestAdaptor": "return { ...api, url: api.url + '&page_size=' + (api.query && api.query.perPage || api.query && api.query.page_size || 20) }"
    },
    "columns": __COLUMNS__,
    "filter": {"submitText": "", "controls": [
        {"type": "text", "name": "keyword", "label": "搜索", "placeholder": "按名称搜索"}
    ]}
}"""


TEST_TPL = '''#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""__LABEL__ CRUD 契约测试（由 SA-v04-S0 spike 生成器产出）。"""

import pytest


async def test___RESOURCE___requires_auth(client):
    """未登录访问必须 401。"""
    response = await client.get("/api/v1/__RESOURCE__s")
    assert response.status_code == 401


async def test___RESOURCE___create_requires_permission(client, normal_auth_headers):
    """低权账户无 `__RESOURCE__:create` 权限 → 403（RBAC 生效）。"""
    response = await client.post(
        "/api/v1/__RESOURCE__s", headers=normal_auth_headers,
        json={{"name": "x", "email": "x@example.com"}})
    assert response.status_code == 403, f"应 403，实际 {{response.status_code}}"


async def test___RESOURCE___crud_roundtrip(client, auth_headers):
    """管理员：创建 → 列表 → 详情 → 更新 → 删除 全链路。"""
    created = await client.post(
        "/api/v1/__RESOURCE__s", headers=auth_headers,
        json={{"name": "客户A", "email": "a@example.com", "status": "active"}})
    assert created.status_code == 201, created.text[:200]
    body = created.json()
    assert body["data"]["name"] == "客户A"
    assert body["data"]["status"] == "active"

    listing = await client.get("/api/v1/__RESOURCE__s", headers=auth_headers)
    assert listing.status_code == 200
    items = listing.json()["data"]["items"]
    assert any(i["email"] == "a@example.com" for i in items)

    obj_id = body["data"]["id"]
    updated = await client.put(
        f"/api/v1/__RESOURCE__s/{{obj_id}}", headers=auth_headers,
        json={{"status": "archived"}})
    assert updated.status_code == 200
    assert updated.json()["data"]["status"] == "archived"

    detail = await client.get(f"/api/v1/__RESOURCE__s/{{obj_id}}", headers=auth_headers)
    assert detail.status_code == 200, "更新后取详情应 200"

    missing = await client.get(f"/api/v1/__RESOURCE__s/999999", headers=auth_headers)
    assert missing.status_code == 404

    deleted = await client.delete(f"/api/v1/__RESOURCE__s/{{obj_id}}", headers=auth_headers)
    assert deleted.status_code == 200

    refetch = await client.get(f"/api/v1/__RESOURCE__s/{{obj_id}}", headers=auth_headers)
    assert refetch.status_code == 404, "删除后复查应 404"


async def test___RESOURCE___create_requires_fields(client, auth_headers):
    """缺必填字段 → 400。"""
    response = await client.post("/api/v1/__RESOURCE__s", headers=auth_headers, json={})
    assert response.status_code == 400
'''


def render(spec: dict, spec_name: str) -> dict:
    resource = spec["resource"]
    Class = resource.capitalize()
    fields = spec["fields"]
    table = spec.get("table", resource)
    label = spec.get("label", resource)

    attr_docs, field_defs, json_fields, rules, write_fields = [], [], [], [], []
    searchable, list_cols = [], []
    for f in fields:
        name, ftype = f["name"], f["type"]
        if ftype == "string":
            args = f"max_length={f.get('max_length', 255)}"
            if f.get("required"):
                field_defs.append(f"    {name}: str = fields.CharField({args})")
            else:
                field_defs.append(
                    f"    {name}: str = fields.CharField({args}, null=True, default=None)")
        elif ftype == "text":
            field_defs.append(f"    {name}: str = fields.TextField(null=True, default=None)")
        elif ftype == "fk":
            field_defs.append(
                f"    {name} = fields.ForeignKeyField("
                f"'models.{f['target'].capitalize()}', null=True, related_name='{resource}s')")
        rules_entry = None
        if f.get("required"):
            conds = ["Required()"]
            if ftype == "string":
                conds.append(f"Length(max_={f.get('max_length', 255)})")
            rules_entry = f'    "{name}": [{", ".join(conds)}],'
        if rules_entry:
            rules.append(rules_entry)
        # FK 字段在 Tortoise 里以 <name>_id 写入
        write_fields.append(f"{name}_id" if ftype == "fk" else name)
        if f.get("list"):
            list_cols.append({"name": name, "label": f.get("label", name)})
        if f.get("searchable"):
            searchable.append(f'"{name}"')
    # json 字段：fk 输出 *_id
    json_parts = []
    for f in fields:
        name, ftype = f["name"], f["type"]
        expr = f"self.{name}_id" if ftype == "fk" else f"self.{name}"
        json_parts.append(f'            "{name}": {expr},')
    json_fields_block = "\n".join(json_parts)

    attr_docs = "\n".join(f"        {f['name']}: {f.get('label', f['name'])}" for f in fields)
    field_defs_block = "\n".join(field_defs)
    rules_block = "\n".join(rules) or "    pass"
    write_fields_block = ", ".join(f'"{w}"' for w in write_fields)
    searchable_block = "[" + ", ".join(searchable) + "]"
    columns_json = json.dumps(list_cols, ensure_ascii=False, indent=8)

    return {
        "model": MODEL_TPL.format(
            label=label, spec=spec_name, Class=Class, description=spec.get("description", ""),
            attr_docs=attr_docs, field_defs=field_defs_block, table=table,
            json_fields=json_fields_block),
        "resource": RESOURCE_TPL.format(
            label=label, spec=spec_name, Class=Class, resource=resource,
            upper=resource.upper(), field_rules=rules_block,
            write_fields=write_fields_block, searchable=searchable_block,
            description=spec.get("description", "")),
        "page": json.dumps(
            json.loads(PAGE_TPL
                       .replace("__RESOURCE__", resource)
                       .replace("__COLUMNS__", columns_json)),
            ensure_ascii=False, indent=2),
        "test": TEST_TPL.replace("__RESOURCE__", resource).replace("__LABEL__", label)
                      .replace("{{", "{").replace("}}", "}"),
    }


def main() -> int:
    spec_path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "spike/customer.yaml"
    spec = yaml.safe_load(spec_path.read_text())
    spec_name = spec_path.name
    out = render(spec, spec_name)
    resource = spec["resource"]

    targets = {
        ROOT / f"app/models/{resource}.py": out["model"],
        ROOT / f"app/api/resources/{resource}.py": out["resource"],
        ROOT / f"amis/pages/{resource}-list.json": out["page"] + "\n",
        ROOT / f"tests/test_{resource}_spike.py": out["test"],
    }
    for path, content in targets.items():
        if path.exists():
            print(f"  跳过（已存在）: {path.relative_to(ROOT)}")
            continue
        path.write_text(content)
        print(f"  生成: {path.relative_to(ROOT)}")

    print(
        "\nWIRING（生成器刻意不做的 4 条手工接线，每条都是单行/小块编辑）:\n"
        f"  1. app/models/__init__.py: from app.models.{resource} import {resource.capitalize()}"
        f" + __all__ 追加\n"
        f"  2. app/api/resources/__init__.py: from app.api.resources.{resource} import {resource.capitalize()}Resource\n"
        f"  3. app/auth/permissions.py: ALL_PERMISSIONS[\"{resource}\"] = "
        f"{spec.get('permissions', {}).get('actions', ['read'])}\n"
        f"  4. amis/pages/site.json: 菜单追加 schemaApi \"get:pages/{resource}-list.json?v1\"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
