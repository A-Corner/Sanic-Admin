#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
``app/services/utils.py`` 纯函数单元测试（v0.3 P6 覆盖率）。

全部为无副作用的纯函数，用最小桩对象直接测，不经过 HTTP。
``app/web/routes.py`` 不在本文件范围：``frontend/templates/`` 不存在，
那批路由是渲染必败的死代码（architecture.md 已记录）——不为凑覆盖率
把 500 钉成预期行为，该模块的处置属产品决策。
"""

import datetime
import re

from app.services.utils import (
    ensure_aware,
    format_datetime,
    get_code,
    get_expiration_date,
    get_ip,
    get_request_value,
    json as json_response_of,
    parse_datetime,
    utcnow,
)


class _FakeRequest:
    """get_ip / get_request_value 需要的最小请求桩。"""

    def __init__(self, headers=None, ip="10.1.2.3", form=None, payload=None,
                 json_raises=False):
        self.headers = headers or {}
        self.ip = ip
        self.form = form
        self._payload = payload
        self._json_raises = json_raises

    @property
    def json(self):
        if self._json_raises:
            raise ValueError("not json")
        return self._payload


def test_get_ip_prefers_xff_first_hop():
    req = _FakeRequest(headers={"X-Forwarded-For": "203.0.113.7, 10.0.0.1"})
    assert get_ip(req) == "203.0.113.7"


def test_get_ip_falls_back_to_x_real_ip():
    req = _FakeRequest(headers={"X-Real-IP": "198.51.100.9"})
    assert get_ip(req) == "198.51.100.9"


def test_get_ip_falls_back_to_direct_ip():
    assert get_ip(_FakeRequest(ip="192.0.2.1")) == "192.0.2.1"


def test_get_code_length_and_alphabet():
    for length in (6, 12):
        code = get_code(length)
        assert len(code) == length
        assert re.fullmatch(r"[A-Z0-9]+", code), f"验证码含非法字符: {code!r}"
    assert get_code(32) != get_code(32), "两次生成不应相同（secrets 随机）"


def test_get_request_value_form_takes_priority():
    req = _FakeRequest(form={"k": ["form-value"]}, payload={"k": "json-value"})
    assert get_request_value(req, "k") == ["form-value"]


def test_get_request_value_reads_json_body():
    req = _FakeRequest(payload={"name": "alice"})
    assert get_request_value(req, "name") == "alice"
    assert get_request_value(req, "missing") is None


def test_get_request_value_survives_non_json_body():
    req = _FakeRequest(json_raises=True)
    assert get_request_value(req, "k") is None


def test_get_request_value_non_dict_json_returns_none():
    req = _FakeRequest(payload=[1, 2, 3])
    assert get_request_value(req, "k") is None


def test_ensure_aware_naive_becomes_utc():
    naive = datetime.datetime(2026, 10, 23, 8, 0, 0)
    aware = ensure_aware(naive)
    assert aware.tzinfo is datetime.timezone.utc
    assert ensure_aware(aware) is aware, "已是 aware 的时间应原样返回"


def test_get_expiration_date_is_future_utc():
    before = utcnow()
    exp = get_expiration_date(600)
    after = utcnow()
    assert exp.tzinfo is not None
    assert before <= exp <= after + datetime.timedelta(seconds=600)


def test_format_datetime_and_parse_roundtrip():
    dt = datetime.datetime(2026, 10, 23, 7, 30, 5)
    text = format_datetime(dt)
    assert text == "2026-10-23 07:30:05"
    parsed = parse_datetime(text)
    assert parsed == dt
    assert format_datetime(None) == ""
    assert parse_datetime("not-a-date") is None


def test_json_response_helper_shapes_envelope():
    resp = json_response_of("ok", {"a": 1}, status=200)
    assert resp.status == 200
    assert resp.content_type == "application/json"
    body = __import__("json").loads(resp.body)
    assert body == {"status": 0, "msg": "ok", "data": {"a": 1}}

    err = json_response_of("bad", status=400)
    assert err.status == 400
    body = __import__("json").loads(err.body)
    assert body["status"] == 1 and body["msg"] == "bad"
