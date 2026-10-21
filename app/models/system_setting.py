#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
系统设置模型模块（字段以 app/api/resources/setting.py 的使用为准）
"""
from tortoise import fields
from app.models.base import BaseModel


class SystemSetting(BaseModel):
    """
    系统参数配置：值统一以字符串存储，``value_type`` 指明如何解释
    （string / int / float / bool / json）。

    Attributes:
        key (str): 设置键，唯一
        value (str): 设置值（字符串形式）
        value_type (str): 值类型
        description (str): 说明
        category (str): 分类
        is_public (bool): 是否对未登录用户公开
    """
    key: str = fields.CharField(max_length=50, unique=True)
    value: str = fields.TextField()
    value_type: str = fields.CharField(max_length=16, default="string")
    description: str = fields.CharField(max_length=255, null=True)
    category: str = fields.CharField(max_length=50, default="general")
    is_public: bool = fields.BooleanField(default=False)

    class Meta:
        table = "system_setting"

    @property
    def json(self) -> dict:
        return {
            "id": self.id,
            "key": self.key,
            "value": self.value,
            "value_type": self.value_type,
            "description": self.description,
            "category": self.category,
            "is_public": self.is_public,
            "created_at": str(self.created_at),
            "updated_at": str(self.updated_at),
        }

    def validate(self) -> None:
        """系统设置没有额外的状态约束。"""
