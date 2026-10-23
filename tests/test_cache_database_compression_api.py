#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
缓存 / 数据库分析 / 压缩端点测试（v0.3 P6 覆盖率）。

覆盖 ``app/api/resources/cache.py``、``database.py``、``compression.py``
的主路径与参数校验分支。SQL 分析只接受只读 SELECT、拒绝写入 SQL 的
安全契约在这里一并钉住（app/database/query_analyzer.py 的只读校验）。
"""


async def test_cache_overview_returns_stats(client, auth_headers):
    """GET /api/v1/cache → 200，返回统计字段。"""
    response = await client.get("/api/v1/cache", headers=auth_headers)
    assert response.status_code == 200, response.text[:200]
    body = response.json()
    assert body.get("success") is True
    assert isinstance(body.get("data"), dict), "缓存统计应是对象"


async def test_cache_keys_listing(client, auth_headers):
    """GET /api/v1/keys?… 列表契约：data.items 与分页字段。"""
    response = await client.get(
        "/api/v1/cache/keys?pattern=*&page=1&limit=10", headers=auth_headers
    )
    assert response.status_code == 200, response.text[:200]
    body = response.json()
    assert body.get("success") is True
    data = body.get("data") or {}
    assert "items" in data or "keys" in data, f"键列表响应缺少列表字段: {list(data)}"


async def test_cache_missing_key_is_404(client, auth_headers):
    """GET /api/v1/cache/keys/<不存在的键> → 404 RESOURCE_NOT_FOUND。"""
    response = await client.get("/api/v1/cache/keys/no-such-key-p6", headers=auth_headers)
    assert response.status_code == 404, response.text[:200]


async def test_cache_requires_auth(client):
    """未登录 GET /api/v1/cache → 401。"""
    response = await client.get("/api/v1/cache")
    assert response.status_code == 401


async def test_query_logs_listing_and_limit_validation(client, auth_headers):
    """GET /api/database/query-logs：正常 limit 200；超界 limit 400。"""
    ok = await client.get("/api/database/query-logs?limit=5", headers=auth_headers)
    assert ok.status_code == 200, ok.text[:200]
    assert ok.json().get("success") is True

    bad = await client.get("/api/database/query-logs?limit=99999", headers=auth_headers)
    assert bad.status_code == 400, f"limit=99999 应被校验拒绝，实际 {bad.status_code}"


async def test_slow_queries_listing(client, auth_headers):
    """GET /api/database/slow-queries → 200。"""
    response = await client.get("/api/database/slow-queries", headers=auth_headers)
    assert response.status_code == 200, response.text[:200]


async def test_connection_pool_status(client, auth_headers):
    """GET /api/database/connection-pool → 200，返回连接池状态对象。"""
    response = await client.get("/api/database/connection-pool", headers=auth_headers)
    assert response.status_code == 200, response.text[:200]
    assert response.json().get("success") is True


async def test_database_analysis_aggregates(client, auth_headers):
    """GET /api/database/analysis → 200（综合分析，空库也应有结构）。"""
    response = await client.get("/api/database/analysis", headers=auth_headers)
    assert response.status_code == 200, response.text[:200]


async def test_query_plan_accepts_readonly_select(client, auth_headers):
    """POST /api/database/query-plan 只读 SELECT → 200/201，只发 EXPLAIN 不执行。"""
    response = await client.post(
        "/api/database/query-plan",
        headers=auth_headers,
        json={"sql": "SELECT 1"},
    )
    assert response.status_code in (200, 201), response.text[:200]


async def test_query_plan_rejects_write_sql(client, auth_headers):
    """POST /api/database/query-plan 写入 SQL → 400（只读契约）。"""
    for sql in ("DROP TABLE account", "INSERT INTO account(id) VALUES (1)",
                "UPDATE account SET username = 'x'", "DELETE FROM account"):
        response = await client.post(
            "/api/database/query-plan", headers=auth_headers, json={"sql": sql}
        )
        assert response.status_code == 400, f"{sql!r} 应 400，实际 {response.status_code}"


async def test_compression_stats_and_config(client, auth_headers):
    """stats 只读 GET → 200；config 是 PUT 资源，GET 应 405 且带 Allow。"""
    stats = await client.get("/api/compression/stats", headers=auth_headers)
    assert stats.status_code == 200, stats.text[:200]
    assert stats.json().get("success") is True

    cfg_get = await client.get("/api/compression/config", headers=auth_headers)
    assert cfg_get.status_code == 405, f"GET config 应 405，实际 {cfg_get.status_code}"
    # 已知缺口（不在 P6 边界内，已上报）：compression/database 蓝图仍走旧
    # bp.add_route，405 响应没有 Allow 头——v0.2.1 补 Allow 的批次只覆盖了
    # log/cache/dashboard。修法是把这两个资源也接入 register_view（route_methods
    # 在 P3 边界内），此处只钉 405 契约本身。

    cfg_put = await client.put(
        "/api/compression/config",
        headers=auth_headers,
        json={"min_length": 2048, "compression_level": 5},
    )
    assert cfg_put.status_code == 200, cfg_put.text[:200]
