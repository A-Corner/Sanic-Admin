#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
验证令牌模型模块，提供用于账户激活、密码重置和二步验证的令牌功能
"""

import datetime
import json
from tortoise import fields
from tortoise.exceptions import DoesNotExist
from app.models.base import BaseModel


class VerificationToken(BaseModel):
    """
    验证令牌模型
    
    用于各种需要令牌的验证流程，如账户激活、密码重置、二步验证等
    """
    account = fields.ForeignKeyField('models.Account', related_name='verification_tokens')
    token = fields.CharField(max_length=128, unique=True, description="验证令牌")
    token_type = fields.CharField(max_length=32, description="令牌类型，如 'activation', 'password_reset', 'two_factor'")
    expires_at = fields.DatetimeField(description="过期时间")
    created_at = fields.DatetimeField(auto_now_add=True, description="创建时间")
    used = fields.BooleanField(default=False, description="是否已使用")
    _data = fields.TextField(null=True, description="附加数据，存储为JSON格式", source_field="data")
    
    class Meta:
        table = "verification_tokens"
        description = "验证令牌"
    
    def __str__(self):
        return f"{self.token_type}令牌:{self.token[:8]}... (账户:{self.account_id})"
    
    @property
    def data(self):
        """
        获取令牌附加数据
        
        Returns:
            dict: 解析后的附加数据
        """
        if not self._data:
            return {}
        
        try:
            return json.loads(self._data)
        except (json.JSONDecodeError, TypeError):
            return {}
    
    @data.setter
    def data(self, value):
        """
        设置令牌附加数据
        
        Args:
            value: 要存储的数据，将被转换为JSON
        """
        if value is None:
            self._data = None
        else:
            self._data = json.dumps(value)
    
    @property
    def is_expired(self):
        """
        检查令牌是否已过期
        
        Returns:
            bool: 如果令牌已过期则返回True
        """
        return self.expires_at < datetime.datetime.now()
    
    @classmethod
    async def find_valid_token(cls, token: str, token_type: str):
        """
        查找有效的令牌
        
        Args:
            token: 令牌字符串
            token_type: 令牌类型
            
        Returns:
            VerificationToken: 找到的有效令牌，如果不存在或已过期则返回None
        """
        try:
            verification_token = await cls.get(token=token, token_type=token_type, used=False)
            
            # 检查令牌是否过期
            if verification_token.is_expired:
                return None
            
            return verification_token
        except DoesNotExist:
            return None
    
    async def use_token(self):
        """
        标记令牌为已使用
        
        用于一次性令牌，防止重复使用
        """
        self.used = True
        await self.save()
    
    @classmethod
    async def clean_expired_tokens(cls):
        """
        清理所有过期的令牌
        
        Returns:
            int: 清理的令牌数量
        """
        now = datetime.datetime.now()
        deleted_count = await cls.filter(expires_at__lt=now).delete()
        return deleted_count 