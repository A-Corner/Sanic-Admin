#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
用户相关模型模块，包含Account和Role模型
"""
from tortoise import fields
from tortoise.exceptions import DoesNotExist
from app.models.base import BaseModel
from app.services.exceptions import DeletedError, UnverifiedError, DisabledError, NotFoundError


class Role(BaseModel):
    """
    角色模型，定义用户权限组
    
    Attributes:
        name (str): 角色名称，唯一
        description (str): 角色描述
        permissions (str): 角色权限，JSON格式字符串
    """
    name: str = fields.CharField(max_length=64, unique=True)
    description: str = fields.CharField(max_length=255, null=True)
    permissions: str = fields.JSONField(default={})
    
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
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
        }
    
    def validate(self) -> None:
        """
        验证角色状态
        
        Raises:
            DeletedError: 如果角色已被删除
        """
        if self.deleted:
            raise DeletedError("角色已被删除")


class AccountRole(BaseModel):
    """
    账户与角色的多对多关系模型
    """
    account = fields.ForeignKeyField("models.Account", related_name="account_roles")
    role = fields.ForeignKeyField("models.Role", related_name="role_accounts")
    
    @property
    def json(self) -> dict:
        """JSON表示"""
        return {
            "id": self.id,
            "account_id": self.account_id,
            "role_id": self.role_id,
        }
    
    def validate(self) -> None:
        """验证状态"""
        if self.deleted:
            raise DeletedError("账户角色关系已被删除")
    
    class Meta:
        table = "account_role"


class Account(BaseModel):
    """
    用户账户模型，包含所有可识别用户信息
    
    Attributes:
        username (str): 公共标识符，唯一
        email (str): 私有标识符，用于验证，唯一
        phone (str): 包含国家代码的手机号，可用于验证，可为空
        password (str): 用于保护账户的密码，使用Argon2哈希
        disabled (bool): 是否禁用账户
        verified (bool): 账户是否已验证
        roles (ManyToManyRelation[Role]): 与此账户关联的角色
    """
    username: str = fields.CharField(unique=True, max_length=32)
    email: str = fields.CharField(unique=True, max_length=255)
    phone: str = fields.CharField(unique=True, max_length=14, null=True)
    password: str = fields.CharField(max_length=255)
    disabled: bool = fields.BooleanField(default=False)
    verified: bool = fields.BooleanField(default=False)
    roles: fields.ManyToManyRelation["Role"] = fields.ManyToManyField(
        "models.Role", through="account_role"
    )

    @property
    def json(self) -> dict:
        """
        生成账户的JSON表示
        
        Returns:
            dict: 账户数据的字典表示
        """
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "email": self.email,
            "username": self.username,
            "phone": self.phone,
            "disabled": self.disabled,
            "verified": self.verified,
        }

    def validate(self) -> None:
        """
        验证账户状态是否合法
        
        Raises:
            DeletedError: 如果账户已被删除
            UnverifiedError: 如果账户未经验证
            DisabledError: 如果账户已禁用
        """
        if self.deleted:
            raise DeletedError("账户已被删除")
        elif not self.verified:
            raise UnverifiedError()
        elif self.disabled:
            raise DisabledError()

    async def disable(self):
        """
        禁用账户
        
        Raises:
            DisabledError: 如果账户已被禁用
        """
        if self.disabled:
            raise DisabledError("账户已被禁用")
        self.disabled = True
        await self.save(update_fields=["disabled"])

    @staticmethod
    async def get_via_email(email: str):
        """
        通过电子邮件获取账户
        
        Args:
            email (str): 与要检索的账户关联的电子邮件
            
        Returns:
            Account: 匹配的账户实例
            
        Raises:
            NotFoundError: 如果找不到与给定电子邮件相关联的账户
        """
        try:
            return await Account.filter(email=email, deleted=False).get()
        except DoesNotExist as e:
            raise NotFoundError("找不到使用此电子邮件的账户") from e

    @staticmethod
    async def get_via_username(username: str):
        """
        通过用户名获取账户
        
        Args:
            username (str): 与要检索的账户关联的用户名
            
        Returns:
            Account: 匹配的账户实例
            
        Raises:
            NotFoundError: 如果找不到与给定用户名相关联的账户
        """
        try:
            return await Account.filter(username=username, deleted=False).get()
        except DoesNotExist as e:
            raise NotFoundError("找不到使用此用户名的账户") from e

    @staticmethod
    async def get_via_phone(phone: str):
        """
        通过电话号码获取账户
        
        Args:
            phone (str): 与要检索的账户关联的电话号码
            
        Returns:
            Account: 匹配的账户实例
            
        Raises:
            NotFoundError: 如果找不到与给定电话号码相关联的账户
        """
        try:
            return await Account.filter(phone=phone, deleted=False).get()
        except DoesNotExist as e:
            raise NotFoundError("找不到使用此电话号码的账户") from e 