#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
用户个人资料模型模块（字段以 app/api/resources/profile.py 的使用为准）
"""
from tortoise import fields
from app.models.base import BaseModel


class Profile(BaseModel):
    """
    用户个人资料，与账户一对一；所有资料字段均可为空
    """
    account = fields.OneToOneField("models.Account", related_name="profile", on_delete=fields.CASCADE)
    full_name: str = fields.CharField(max_length=64, null=True)
    nickname: str = fields.CharField(max_length=64, null=True)
    avatar: str = fields.CharField(max_length=255, null=True)
    mobile_phone: str = fields.CharField(max_length=32, null=True)
    tel_phone: str = fields.CharField(max_length=32, null=True)
    gender: str = fields.CharField(max_length=16, null=True)
    birth_date = fields.DateField(null=True)
    address: str = fields.CharField(max_length=255, null=True)
    work_start_date = fields.DateField(null=True)
    introduction: str = fields.TextField(null=True)
    homepage: str = fields.CharField(max_length=255, null=True)

    class Meta:
        table = "profile"

    @property
    def json(self) -> dict:
        return {
            "id": self.id,
            "account_id": self.account_id,
            "full_name": self.full_name,
            "nickname": self.nickname,
            "avatar": self.avatar,
            "mobile_phone": self.mobile_phone,
            "tel_phone": self.tel_phone,
            "gender": self.gender,
            "birth_date": self.birth_date.isoformat() if self.birth_date else None,
            "address": self.address,
            "work_start_date": self.work_start_date.isoformat() if self.work_start_date else None,
            "introduction": self.introduction,
            "homepage": self.homepage,
            "created_at": str(self.created_at),
            "updated_at": str(self.updated_at),
        }

    def validate(self) -> None:
        """个人资料没有额外的状态约束。"""
