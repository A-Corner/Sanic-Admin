#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
账户模型模块
"""
from typing import TYPE_CHECKING
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from tortoise import fields
from tortoise.exceptions import DoesNotExist
from app.models.base import BaseModel
from app.services.exceptions import DeletedError, DisabledError, NotFoundError, UnverifiedError

if TYPE_CHECKING:
    from app.models.role import Role

# 口令哈希工具（Argon2id，盐由库自动生成并编码进哈希串）
password_hasher = PasswordHasher()
# 账户不存在时用于等成本校验的哑哈希（防止通过响应时间枚举账户）
_DUMMY_HASH = password_hasher.hash("dummy-password-for-timing-equalization")


class Account(BaseModel):
    """
    用户账户模型，包含所有可识别用户信息

    Attributes:
        username (str): 公共标识符，唯一
        email (str): 私有标识符，用于验证，唯一
        phone (str): 包含国家代码的手机号，可用于验证，可为空
        first_name (str): 名
        last_name (str): 姓
        password (str): 用于保护账户的密码，使用Argon2哈希
        disabled (bool): 是否禁用账户
        verified (bool): 账户是否已验证
        is_admin (bool): 是否为管理员（拥有全部权限）
        roles (ManyToManyRelation[Role]): 与此账户关联的角色
    """
    username: str = fields.CharField(unique=True, max_length=32)
    email: str = fields.CharField(unique=True, max_length=255)
    phone: str = fields.CharField(unique=True, max_length=14, null=True)
    first_name: str = fields.CharField(max_length=64, null=True)
    last_name: str = fields.CharField(max_length=64, null=True)
    password: str = fields.CharField(max_length=255)
    disabled: bool = fields.BooleanField(default=False)
    verified: bool = fields.BooleanField(default=False)
    is_admin: bool = fields.BooleanField(default=False)
    roles: fields.ManyToManyRelation["Role"] = fields.ManyToManyField(
        "models.Role", through="account_role", related_name="accounts"
    )

    class Meta:
        table = "account"

    @property
    def is_active(self) -> bool:
        """账户是否可用：已验证、未禁用、未删除"""
        return self.verified and not self.disabled and not self.deleted

    @property
    def json(self) -> dict:
        """
        生成账户的JSON表示（不含口令哈希）

        Returns:
            dict: 账户数据的字典表示
        """
        return {
            "id": self.id,
            "created_at": str(self.created_at),
            "updated_at": str(self.updated_at),
            "email": self.email,
            "username": self.username,
            "phone": self.phone,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "disabled": self.disabled,
            "verified": self.verified,
            "is_admin": self.is_admin,
        }

    def set_password(self, raw_password: str) -> None:
        """
        设置口令（仅修改内存中的字段，调用方负责 save）

        Args:
            raw_password (str): 明文口令
        """
        self.password = password_hasher.hash(raw_password)

    def verify_password(self, raw_password: str) -> bool:
        """
        校验口令

        Args:
            raw_password (str): 明文口令

        Returns:
            bool: 口令正确返回 True，否则 False
        """
        try:
            return password_hasher.verify(self.password, raw_password)
        except (VerifyMismatchError, InvalidHashError, VerificationError):
            return False

    @staticmethod
    def verify_dummy_password(raw_password: str) -> None:
        """对哑哈希执行一次与真实校验同等成本的 argon2 校验，结果丢弃。"""
        try:
            password_hasher.verify(_DUMMY_HASH, raw_password)
        except (VerifyMismatchError, InvalidHashError, VerificationError):
            pass

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

        Raises:
            NotFoundError: 如果找不到与给定电话号码相关联的账户
        """
        try:
            return await Account.filter(phone=phone, deleted=False).get()
        except DoesNotExist as e:
            raise NotFoundError("找不到使用此电话号码的账户") from e
