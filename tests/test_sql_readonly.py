#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SQL 查询分析只读性测试。

覆盖 CPL 验收口径第 8 项：写入类 SQL 一律拒绝（400），只读 SELECT 正常返回执行计划。

只读断言
========
本文件**不修改任何数据**。写入类 SQL 在到达数据库之前就被
``validate_readonly_sql`` 拒绝；只读 SELECT 只发 ``EXPLAIN``，不执行查询本身
（SQLite 下是 ``EXPLAIN QUERY PLAN``）。

``validate_readonly_sql`` 的规则（见 ``app/database/query_analyzer.py``）：
非空；去掉结尾分号后不得再含分号（禁止多语句）；不得含注释标记；
必须以 SELECT/WITH 开头；不得包含写入/DDL/管理类关键字；
不得调用有副作用的函数。
"""

import pytest

WRITE_SQL_CASES = [
    ("DELETE FROM account", "DELETE"),
    ("UPDATE account SET username='x' WHERE id=1", "UPDATE"),
    ("DROP TABLE account", "DROP"),
    ("INSERT INTO role (name) VALUES ('x')", "INSERT"),
    ("TRUNCATE TABLE account", "TRUNCATE"),
    ("ALTER TABLE account ADD COLUMN x TEXT", "ALTER"),
    ("CREATE TABLE t (id INT)", "CREATE"),
    ("REPLACE INTO role (name) VALUES ('x')", "REPLACE"),
]


@pytest.mark.parametrize("sql,keyword", WRITE_SQL_CASES)
async def test_write_sql_is_rejected(client, auth_headers, sql, keyword):
    """写入类 SQL → 400 拒绝。"""
    response = await client.post(
        "/api/database/query-plan", headers=auth_headers, json={"sql": sql}
    )

    assert response.status_code == 400, (
        f"{keyword} 语句没有被拒绝，返回 {response.status_code}：{response.text}"
    )
    body = response.json()
    assert body["success"] is False
    assert body["error"] == "VALIDATION_ERROR"
    assert "拒绝分析" in body["message"]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1",
        "SELECT * FROM account",
        "SELECT id, username FROM account WHERE id = 1",
        "WITH t AS (SELECT 1 AS x) SELECT x FROM t",
        "SELECT * FROM account LIMIT 1",
    ],
)
async def test_readonly_sql_returns_plan(client, auth_headers, sql):
    """只读 SELECT → 200，返回执行计划。"""
    response = await client.post(
        "/api/database/query-plan", headers=auth_headers, json={"sql": sql}
    )

    assert response.status_code == 200, (
        f"只读查询返回 {response.status_code}：{response.text}"
    )
    body = response.json()
    assert body["success"] is True
    data = body["data"]
    assert "dialect" in data
    assert "plan" in data


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1; DROP TABLE account",
        "DELETE FROM account; SELECT 1",
        "SELECT 1 -- comment",
        "SELECT 1 /* comment */",
        "SELECT * FROM account WHERE id = 1; UPDATE role SET name='x'",
    ],
)
async def test_multi_statement_and_comment_injection_rejected(client, auth_headers, sql):
    """多语句与注释注入 → 400 拒绝。"""
    response = await client.post(
        "/api/database/query-plan", headers=auth_headers, json={"sql": sql}
    )
    assert response.status_code == 400, (
        f"注入型 SQL 没有被拒绝，返回 {response.status_code}：{response.text}"
    )


async def test_empty_sql_rejected(client, auth_headers):
    """空 SQL → 400。"""
    response = await client.post(
        "/api/database/query-plan", headers=auth_headers, json={"sql": "   "}
    )
    assert response.status_code == 400, response.text


async def test_missing_sql_rejected(client, auth_headers):
    """缺少 sql 字段 → 400。"""
    response = await client.post(
        "/api/database/query-plan", headers=auth_headers, json={}
    )
    assert response.status_code == 400, response.text


async def test_query_plan_requires_authentication(client):
    """分析接口未认证 → 401。"""
    response = await client.post("/api/database/query-plan", json={"sql": "SELECT 1"})
    assert response.status_code == 401, response.text


async def test_query_plan_requires_permission(client, normal_auth_headers):
    """权限不足 → 403。"""
    response = await client.post(
        "/api/database/query-plan",
        headers=normal_auth_headers,
        json={"sql": "SELECT 1"},
    )
    assert response.status_code == 403, response.text


async def test_validate_readonly_sql_unit():
    """
    直接单测 ``validate_readonly_sql``（纯函数，无需应用与数据库）。

    这条断言不依赖 HTTP 层，能把"只读校验"本身的边界钉死。
    """
    from app.database.query_analyzer import validate_readonly_sql

    # 合法的只读语句会被规范化（去空白、去结尾分号）
    assert validate_readonly_sql("  SELECT 1;  ") == "SELECT 1"
    assert validate_readonly_sql("SELECT * FROM account").startswith("SELECT")

    for bad in (
        "DELETE FROM account",
        "UPDATE account SET username='x'",
        "DROP TABLE account",
        "INSERT INTO role (name) VALUES ('x')",
        "SELECT 1; DELETE FROM account",
        "SELECT 1 -- x",
        "",
        "   ",
    ):
        with pytest.raises(ValueError):
            validate_readonly_sql(bad)
