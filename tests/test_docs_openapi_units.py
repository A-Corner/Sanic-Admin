#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
``app/docs`` 装饰器与模型注册的单元测试（v0.3 P6 覆盖率）。

装饰器与 OpenAPI 模型构建都是纯函数：往视图函数的 ``__api_spec__`` 字典里
写属性 / 往注册表里写 schema，不需要起应用。逐个钉住属性契约，
``/swagger.json`` 的生成质量依赖它们。
"""

from pydantic import BaseModel

from app.docs import decorators as dec
from app.docs import models as doc_models


class _P6Item(BaseModel):
    """测试用响应模型：装饰器内部会读模型类名与 schema。"""

    id: int
    name: str


def _dummy():
    def dummy():
        return None
    return dummy


def _spec(fn):
    return getattr(fn, "__api_spec__", {})


def test_api_tags_attaches_tags():
    fn = dec.api_tags("账户", "管理")(_dummy())
    assert _spec(fn)["tags"] == ["账户", "管理"]


def test_api_exclude_marks_excluded():
    fn = dec.api_exclude()(_dummy())
    assert _spec(fn)["exclude"] is True


def test_api_summary_and_description():
    fn = dec.api_summary("摘要")(_dummy())
    assert _spec(fn)["summary"] == "摘要"
    desc_fn = dec.api_description("描述文本")(fn)
    assert _spec(desc_fn)["description"] == "描述文本"


def test_api_body_attaches_request_body():
    fn = dec.api_body(model=_P6Item, description="请求体")(_dummy())
    spec = _spec(fn)
    body = spec.get("requestBody", {})
    content = body.get("content", {}).get("application/json", {})
    assert content.get("schema", {}).get("$ref", "").endswith("_P6Item"), (
        f"请求体应引用模型 schema: {body}"
    )


def test_api_response_attaches_response_model():
    fn = dec.api_response(model=_P6Item, description="成功", status_code=200)(_dummy())
    spec = _spec(fn)
    assert spec.get("responses", {}).get("200"), f"应登记 200 响应: {list(spec)}"


def test_api_response_list_and_pagination():
    fn = dec.api_response_list(model=_P6Item, description="列表", status_code=200)(_dummy())
    assert _spec(fn).get("responses", {}).get("200")

    paged = dec.api_response_pagination(model=_P6Item)(_dummy())
    assert _spec(paged).get("responses", {}).get("200")


def test_api_param_registers_parameter():
    fn = dec.api_param(name="page", param_type="integer", description="页码")(_dummy())
    params = _spec(fn)["parameters"]
    assert params[-1]["name"] == "page"


def test_api_paginated_params_registers_page_and_size():
    paged = dec.api_paginated_params()(_dummy())
    names = {p["name"] for p in _spec(paged)["parameters"]}
    assert {"page", "page_size"} <= names


def test_api_security_attaches_scheme():
    fn = dec.api_security("sessionAuth")(_dummy())
    assert "sessionAuth" in str(_spec(fn)["security"])


def test_register_and_get_schemas_roundtrip():
    doc_models.register_schemas({"P6Schema": {"type": "object"}})
    schemas = doc_models.get_schemas()
    assert schemas.get("P6Schema") == {"type": "object"}


def test_register_error_and_pagination_schemas():
    doc_models.register_error_schemas()
    doc_models.register_pagination_schemas()
    schemas = doc_models.get_schemas()
    assert any("Error" in name for name in schemas), "应注册错误 schema"
    assert any("Page" in name or "Pagination" in name for name in schemas), (
        "应注册分页 schema"
    )
