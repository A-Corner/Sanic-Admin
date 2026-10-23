#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""客户模型（由 SA-v04-S0 spike 生成器产出，规格：spike/customer.yaml）。"""
from tortoise import fields
from app.models.base import BaseModel


class Customer(BaseModel):
    """
    AI-Native spike 示例资源：客户档案（关联账户）

    Attributes:
        name: 名称
        email: 邮箱
        status: 状态
        notes: 备注
        account: 所属账户
    """
    name: str = fields.CharField(max_length=128)
    email: str = fields.CharField(max_length=255)
    status: str = fields.CharField(max_length=16, null=True, default=None)
    notes: str = fields.TextField(null=True, default=None)
    account = fields.ForeignKeyField('models.Account', null=True, related_name='customers')

    class Meta:
        table = "customer"

    @property
    def json(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "status": self.status,
            "notes": self.notes,
            "account": self.account_id,
            "created_at": str(self.created_at),
            "updated_at": str(self.updated_at),
        }

    def validate(self) -> None:
        """客户没有额外的状态约束。"""
