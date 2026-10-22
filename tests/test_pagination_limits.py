#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
分页边界测试：超大页码不再 500、钳制语义一致、正常分页未回归。

背景
====
``GET /api/v1/settings`` 与 ``GET /api/v1/files`` 早期各自用自带的整数解析器，
**页码没有上限**。分页查询用 ``offset((page - 1) * page_size)`` 计算 OFFSET，
页码无上限时 OFFSET 可以超过 SQLite 的 64 位 INTEGER 上限，ORM 拼参数时抛
``IntegrityError: datatype mismatch`` → **500**（服务端错误）。

现在两个资源统一走 ``app.api.validators.parse_pagination``，页码被钳制到
``MAX_PAGE``（10^6），与 ``account`` / ``role`` / ``profile`` / ``logs``
等既有资源的语义一致：**超大页码返回 200 + 空列表，而不是 400，也不是 500**。

被测断言
========
1. 超大页码（17 位）→ 200，``pagination.page`` 等于 ``MAX_PAGE``，items 为空；
2. ``page`` 恰好等于 ``MAX_PAGE`` 与 ``MAX_PAGE + 1`` 的行为一致且可预期；
3. 正常分页的 items 数量、total、pagination 字段未回归；
4. 两个资源的默认 page_size 保持不变（setting 20 / files 20），上限都是 100。
"""

import pytest

from app.api.validators import MAX_PAGE

#: 超出 SQLite 64 位整数范围的页码 —— 修复前会触发 500。
HUGE_PAGE = 99_999_999_999_999_999

#: 被测的两个分页接口：``(路径, 默认每页条数, 每页上限)``。
PAGINATED_ENDPOINTS = [
    ("/api/v1/settings", 20, 100),
    ("/api/v1/files", 20, 100),
]


@pytest.mark.parametrize("path,default_size,max_size", PAGINATED_ENDPOINTS)
async def test_huge_page_returns_200_not_500(
    client, auth_headers, path, default_size, max_size
):
    """
    超大页码 → 200（钳制），绝不是 500。

    修复前：``?page=99999999999999999`` 让 OFFSET 溢出 SQLite 整数范围，
    抛 ``IntegrityError: datatype mismatch`` → 500。
    """
    response = await client.get(path, headers=auth_headers, params={"page": HUGE_PAGE})

    assert response.status_code == 200, (
        f"GET {path}?page={HUGE_PAGE} 返回 {response.status_code}，"
        f"应为 200（页码被钳制到 MAX_PAGE）：{response.text}"
    )

    body = response.json()
    assert body["success"] is True, f"响应 success=false：{response.text}"

    data = body["data"]
    pagination = data["pagination"]

    # 钳制语义：页码被压到 MAX_PAGE，而不是原样回显那个 17 位大数。
    assert pagination["page"] == MAX_PAGE, (
        f"pagination.page 应为 MAX_PAGE({MAX_PAGE})，"
        f"实际 {pagination['page']}：{response.text}"
    )
    # 钳制后的页码远超实际数据量 → 空列表（而不是报错）。
    assert data["items"] == [], (
        f"钳制后的页码应返回空列表：{response.text}"
    )
    # page_size 未被这次请求影响，仍走各自的默认值。
    assert pagination["page_size"] == default_size, (
        f"pagination.page_size 应为 {default_size}：{response.text}"
    )


@pytest.mark.parametrize("path,default_size,max_size", PAGINATED_ENDPOINTS)
async def test_page_size_unchanged_by_huge_page(
    client, auth_headers, path, default_size, max_size
):
    """钳制页码时不应连带改动 page_size 的默认值与上限。"""
    response = await client.get(path, headers=auth_headers, params={"page": HUGE_PAGE})
    pagination = response.json()["data"]["pagination"]

    assert pagination["page_size"] == default_size
    assert pagination["page_size"] <= max_size


@pytest.mark.parametrize("path,default_size,max_size", PAGINATED_ENDPOINTS)
async def test_page_exactly_at_max_page(
    client, auth_headers, path, default_size, max_size
):
    """
    ``page`` 恰好等于 ``MAX_PAGE`` → 不钳制，原样使用。

    这是钳制的边界内侧：OFFSET = (10^6 - 1) × page_size，仍在安全范围内。
    """
    response = await client.get(path, headers=auth_headers, params={"page": MAX_PAGE})

    assert response.status_code == 200, (
        f"GET {path}?page={MAX_PAGE} 返回 {response.status_code}，应为 200：{response.text}"
    )

    pagination = response.json()["data"]["pagination"]
    assert pagination["page"] == MAX_PAGE, (
        f"page 恰好等于 MAX_PAGE 时不应被改动，实际 {pagination['page']}"
    )
    assert pagination["page_size"] == default_size


@pytest.mark.parametrize("path,default_size,max_size", PAGINATED_ENDPOINTS)
async def test_page_one_past_max_page_is_clamped(
    client, auth_headers, path, default_size, max_size
):
    """
    ``page`` 等于 ``MAX_PAGE + 1`` → 钳制到 ``MAX_PAGE``。

    与超大页码（17 位）行为完全一致：都是"压到 MAX_PAGE 然后返回空列表"。
    """
    response = await client.get(
        path, headers=auth_headers, params={"page": MAX_PAGE + 1}
    )

    assert response.status_code == 200, (
        f"GET {path}?page={MAX_PAGE + 1} 返回 {response.status_code}，应为 200：{response.text}"
    )

    pagination = response.json()["data"]["pagination"]
    assert pagination["page"] == MAX_PAGE, (
        f"page=MAX_PAGE+1 应被钳制到 MAX_PAGE，实际 {pagination['page']}"
    )


@pytest.mark.parametrize("path,default_size,max_size", PAGINATED_ENDPOINTS)
async def test_negative_and_invalid_page_fall_back_to_one(
    client, auth_headers, path, default_size, max_size
):
    """负数 / 非数字页码回落到第 1 页（parse_pagination 的既有语义）。"""
    for raw in ("-1", "0", "abc", ""):
        response = await client.get(path, headers=auth_headers, params={"page": raw})

        assert response.status_code == 200, (
            f"GET {path}?page={raw!r} 返回 {response.status_code}，应为 200：{response.text}"
        )

        pagination = response.json()["data"]["pagination"]
        assert pagination["page"] == 1, (
            f"page={raw!r} 应回落到 1，实际 {pagination['page']}"
        )


@pytest.mark.parametrize("path,default_size,max_size", PAGINATED_ENDPOINTS)
async def test_page_size_is_clamped_to_max(
    client, auth_headers, path, default_size, max_size
):
    """``page_size`` 超过上限时被压到上限（两个资源的 page_size 上限都是 100）。"""
    response = await client.get(
        path, headers=auth_headers, params={"page_size": max_size + 500}
    )

    assert response.status_code == 200
    pagination = response.json()["data"]["pagination"]
    assert pagination["page_size"] == max_size, (
        f"page_size 应被压到 {max_size}，实际 {pagination['page_size']}"
    )


async def test_settings_pagination_normal_behavior_not_regressed(
    client, auth_headers
):
    """
    设置列表的正常分页行为未回归。

    建 3 条设置 → 第 1 页取 2 条 → 第 2 页取剩余 1 条，
    并核对 items 数量、total、page、page_size、total_pages。
    """
    # 先清掉可能残留的同名设置（软删除的同 key 会被复活，见 F7 修复）
    for key in ("theme", "language", "timezone"):
        await client.delete(f"/api/v1/settings/key/{key}", headers=auth_headers)

    for key, value in (("theme", "dark"), ("language", "zh-CN"), ("timezone", "UTC")):
        created = await client.post(
            "/api/v1/settings",
            headers=auth_headers,
            json={"key": key, "value": value, "value_type": "string"},
        )
        assert created.status_code == 201, (
            f"创建设置 {key} 返回 {created.status_code}：{created.text}"
        )

    first = await client.get(
        "/api/v1/settings", headers=auth_headers, params={"page": 1, "page_size": 2}
    )
    assert first.status_code == 200, f"第 1 页返回 {first.status_code}：{first.text}"

    data = first.json()["data"]
    pagination = data["pagination"]

    assert len(data["items"]) == 2, (
        f"第 1 页应有 2 条，实际 {len(data['items'])}：{first.text}"
    )
    assert pagination["page"] == 1
    assert pagination["page_size"] == 2
    assert pagination["total"] >= 3, (
        f"total 应至少为 3，实际 {pagination['total']}：{first.text}"
    )
    assert pagination["total_pages"] == (
        (pagination["total"] + pagination["page_size"] - 1) // pagination["page_size"]
    ), f"total_pages 计算不对：{first.text}"

    second = await client.get(
        "/api/v1/settings", headers=auth_headers, params={"page": 2, "page_size": 2}
    )
    assert second.status_code == 200

    second_data = second.json()["data"]
    assert second_data["pagination"]["page"] == 2

    # 两页不能有重复项
    first_keys = {item["key"] for item in data["items"]}
    second_keys = {item["key"] for item in second_data["items"]}
    assert not (first_keys & second_keys), (
        f"两页出现重复设置：{first_keys & second_keys}"
    )

    # 清理
    for key in ("theme", "language", "timezone"):
        await client.delete(f"/api/v1/settings/key/{key}", headers=auth_headers)


async def test_files_pagination_normal_behavior_not_regressed(
    client, auth_headers
):
    """文件列表的正常分页行为未回归（items 数量 / total / pagination 字段）。"""
    response = await client.get(
        "/api/v1/files", headers=auth_headers, params={"page": 1, "page_size": 5}
    )
    assert response.status_code == 200, f"文件列表返回 {response.status_code}：{response.text}"

    data = response.json()["data"]
    pagination = data["pagination"]

    assert pagination["page"] == 1
    assert pagination["page_size"] == 5
    assert len(data["items"]) <= 5, (
        f"items 数量不应超过 page_size：{response.text}"
    )
    assert pagination["total"] == len(data["items"]) or pagination["total"] >= len(
        data["items"]
    ), f"total 与 items 不自洽：{response.text}"
    assert pagination["total_pages"] == (
        (pagination["total"] + pagination["page_size"] - 1) // pagination["page_size"]
    ), f"total_pages 计算不对：{response.text}"


async def test_settings_wrong_method_returns_405_not_404(
    client, auth_headers
):
    """
    未注册的方法 → 405（不是 404）。

    ``DELETE /api/v1/settings/key/<key>`` 这个 URI 只注册了 GET / PUT。
    修复前用 ``v1_bp.add_route`` 注册动态路径，Sanic 23.6 把方法不匹配的
    ``NoMethod`` 吞成 ``NotFound`` → **404**（谎报资源不存在）。
    """
    response = await client.delete("/api/v1/settings/key/site_name", headers=auth_headers)

    assert response.status_code == 405, (
        f"DELETE /api/v1/settings/key/site_name 返回 {response.status_code}，"
        f"应为 405：{response.text}"
    )

    body = response.json()
    assert body["success"] is False
    assert body["error"] == "METHOD_NOT_ALLOWED"


async def test_settings_collection_wrong_method_returns_405_not_404(
    client, auth_headers
):
    """集合 URI 上未注册的方法（PATCH）→ 405。"""
    response = await client.patch("/api/v1/settings", headers=auth_headers)

    assert response.status_code == 405, (
        f"PATCH /api/v1/settings 返回 {response.status_code}，应为 405：{response.text}"
    )


async def test_settings_item_wrong_method_returns_405_not_404(
    client, auth_headers
):
    """动态路径 ``/settings/<id>`` 上未注册的方法（POST）→ 405。"""
    response = await client.post("/api/v1/settings/1", headers=auth_headers)

    assert response.status_code == 405, (
        f"POST /api/v1/settings/1 返回 {response.status_code}，应为 405：{response.text}"
    )


async def test_settings_bulk_wrong_method_returns_405_not_404(
    client, auth_headers
):
    """``/settings/bulk`` 上未注册的方法（POST）→ 405。"""
    response = await client.post("/api/v1/settings/bulk", headers=auth_headers)

    assert response.status_code == 405, (
        f"POST /api/v1/settings/bulk 返回 {response.status_code}，应为 405：{response.text}"
    )


#: upload 资源上「URI 存在但方法未注册」的用例：``(方法, 路径)``。
#:
#: 这些 URI 全部是**动态路径**或**只注册了单个方法**的 URI，修复前
#: 用 ``v1_bp.add_route`` 注册时，Sanic 23.6 把方法不匹配的 ``NoMethod``
#: 吞成 ``NotFound`` → **404**。
UPLOAD_WRONG_METHOD_CASES = [
    ("DELETE", "/api/v1/upload/general"),
    ("PUT", "/api/v1/upload/general"),
    ("DELETE", "/api/v1/upload"),
    ("GET", "/api/v1/upload/avatar"),
    ("DELETE", "/api/v1/upload/avatar"),
    ("POST", "/api/v1/files/1/download"),
    ("GET", "/api/v1/files/1"),
]


@pytest.mark.parametrize("method,path", UPLOAD_WRONG_METHOD_CASES)
async def test_upload_wrong_method_returns_405_not_404(
    client, auth_headers, method, path
):
    """upload 资源的方法不匹配 → 405（不是 404）。"""
    response = await client.request(method, path, headers=auth_headers, json={})

    assert response.status_code == 405, (
        f"{method} {path} 返回 {response.status_code}，应为 405：{response.text}"
    )

    body = response.json()
    assert body["success"] is False
    assert body["error"] == "METHOD_NOT_ALLOWED"
