#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
单元层测试（v0.3 P6 覆盖率）三件套：

* ``app/cache/memory.py`` —— 内存缓存后端全生命周期（同步方法，不起应用）；
* ``app/api/base.py`` —— BaseResource 的类助手（响应信封 / 分页 / 排序参数）；
* ``app/database/query_analyzer.py`` —— ``validate_readonly_sql`` 只读 SQL 矩阵，
  钉住「只接受单条只读 SELECT，拒绝多语句 / 写入 / 注释」的安全契约。
"""

import pytest

from app.api.base import BaseResource
from app.cache.memory import MemoryCache
from app.database.query_analyzer import validate_readonly_sql


# ---------------------------------------------------------------------------
# MemoryCache
# ---------------------------------------------------------------------------

def test_memory_cache_set_get_delete_roundtrip():
    cache = MemoryCache()
    assert cache.get("missing") is None
    assert cache.set("k", {"v": 1}) is True
    assert cache.get("k") == {"v": 1}
    assert cache.exists("k") is True
    assert cache.delete("k") is True
    assert cache.exists("k") is False
    assert cache.delete("k") is False, "删除不存在的键应返回 False"


def test_memory_cache_ttl_expiry():
    cache = MemoryCache()
    cache.set("short", "x", timeout=1)
    assert cache.ttl("short") >= 0, "存在的键 ttl 应 >= 0"
    assert cache.ttl("missing") < 0, "不存在的键 ttl 应为负"
    # 把过期时间拨到过去，模拟过期（内部用 time.time() 纪元的 _expires 表）
    cache._expires["short"] = 0
    cache._clean_expired()
    assert cache.exists("short") is False, "过期键应被清除"


def test_memory_cache_expire_and_persist():
    cache = MemoryCache()
    cache.set("k", 1)
    assert cache.expire("k", 100) is True
    assert cache.expire("missing", 100) is False
    assert cache.get("k") == 1, "expire 不应改变值"


def test_memory_cache_keys_pattern_and_clear():
    cache = MemoryCache()
    for key in ("user:1", "user:2", "role:1"):
        cache.set(key, key)
    assert sorted(cache.keys("user:*")) == ["user:1", "user:2"]
    assert cache.clear() is True
    assert cache.keys() == [], "clear 后不应有键"


def test_memory_cache_increment_decrement():
    cache = MemoryCache()
    assert cache.increment("counter") == 1
    assert cache.increment("counter", 4) == 5
    assert cache.decrement("counter") == 4
    assert cache.decrement("counter", 4) == 0


def test_memory_cache_many_and_stats():
    cache = MemoryCache()
    cache.set_many({"a": 1, "b": 2})
    got = cache.get_many(["a", "b", "gone"])
    assert got.get("a") == 1 and got.get("b") == 2
    assert cache.delete_many(["a", "gone"]) == 1, "只应删除存在的那一个"
    stats = cache.get_stats()
    assert isinstance(stats, dict) and stats, "统计应是 NonEmpty dict"


# ---------------------------------------------------------------------------
# BaseResource 类助手
# ---------------------------------------------------------------------------

class _FakeArgs:
    def __init__(self, data):
        self._data = data

    def get(self, key, default=None):
        return self._data.get(key, default)


class _FakeRequest:
    def __init__(self, args=None):
        self.args = _FakeArgs(args or {})


class _Stub(BaseResource):
    """只为调用类助手；default_* 类属性按需覆盖。"""

    default_page_size = 20
    default_sort_field = "id"
    default_sort_direction = "desc"


def test_base_resource_success_and_error_envelope():
    ok = BaseResource.success_response({"x": 1}, message="好")
    assert ok.status == 200

    bad = BaseResource.error_response("参数错误", status=400, error_code="VALIDATION_ERROR")
    assert bad.status == 400


def test_base_resource_list_response():
    resp = BaseResource.list_response(items=[{"id": 1}], total=1, page=1, page_size=20)
    assert resp.status == 200


def test_base_resource_pagination_params_default_and_custom():
    default_page, default_size = _Stub().get_pagination_params(_FakeRequest())
    assert (default_page, default_size) == (1, 20)

    page, size = _Stub().get_pagination_params(
        _FakeRequest({"page": "3", "page_size": "50"})
    )
    assert (page, size) == (3, 50)

    bad_page, bad_size = _Stub().get_pagination_params(
        _FakeRequest({"page": "abc", "page_size": "-5"})
    )
    assert (bad_page, bad_size) == (1, 20), "非法分页参数应回落默认值"


def test_base_resource_sort_params_sanitised():
    field, direction = _Stub().get_sort_params(
        _FakeRequest({"sort_by": "created_at", "sort_dir": "ASC"})
    )
    assert direction == "asc", "sort_dir 应被小写化"
    assert field == "created_at"


# ---------------------------------------------------------------------------
# validate_readonly_sql 只读矩阵
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("sql", [
    "SELECT 1",
    "SELECT * FROM account WHERE id = 1;",
    "  with t as (select 1 as x) select x from t  ",
])
def test_validate_readonly_sql_accepts_single_select(sql):
    normalized = validate_readonly_sql(sql)
    assert normalized.strip().upper().startswith(("SELECT", "WITH")), normalized


@pytest.mark.parametrize("sql", [
    "SELECT 1; SELECT 2",                      # 多语句
    "DROP TABLE account",                      # DDL
    "DELETE FROM account",                     # 写入
    "UPDATE account SET username = 'x'",       # 写入
    "INSERT INTO account(id) VALUES (1)",      # 写入
    "SELECT 1 -- comment",                     # 注释
    "/* block */ SELECT 1",                    # 块注释
    "",                                        # 空语句
    "   ",                                     # 空白
])
def test_validate_readonly_sql_rejects(sql):
    with pytest.raises(Exception):
        validate_readonly_sql(sql)
