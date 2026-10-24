#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Tortoise 时区探针模型。

**为什么单独一个模块**：Tortoise 通过 ``modules`` 参数按**模块路径**发现模型，
定义在 ``__main__`` 里的局部类不会被注册（实测报
``default_connection ... cannot be None``）。本模块只被
``scripts/check_timezone_dialects.py`` 使用，不进生产代码。

字段只保留验证时区契约所需的最小集合。
"""
from tortoise import fields
from tortoise.models import Model


class TzProbe(Model):
    """时区契约验证用的最小表。"""

    id = fields.IntField(pk=True)
    ts = fields.DatetimeField(null=True)

    class Meta:
        table = "tz_probe"
