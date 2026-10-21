#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
角色模型模块
"""
from tortoise import fields
from app.models.base import BaseModel
from app.services.exceptions import DeletedError


class Role(BaseModel):
    """
    角色模型，定义用户权限组

    Attributes:
        name (str): 角色名称，唯一
        description (str): 角色描述
        permissions (dict): 角色权限，格式 ``{资源: [操作, ...]}``，操作含 ``"all"`` 表示该资源全部权限
        accounts: 反向关系，拥有该角色的账户（由 Account.roles 的 related_name 生成）
    """
    name: str = fields.CharField(max_length=64, unique=True)
    description: str = fields.CharField(max_length=255, null=True)
    permissions: dict = fields.JSONField(default=dict)

    @property
    def json(self) -> dict:
        """
        生成角色的JSON表示

        Returns:
            dict: 角色数据的字典表示
        """
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "permissions": self.permissions,
            "created_at": str(self.created_at),
            "updated_at": str(self.updated_at),
        }

    def validate(self) -> None:
        """
        验证角色状态

        Raises:
            DeletedError: 如果角色已被删除
        """
        if self.deleted:
            raise DeletedError("角色已被删除")

    class Meta:
        table = "role"
