#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
基础模型模块，定义所有模型的基类
"""
import datetime
from tortoise import fields
from tortoise.models import Model
from app.services.exceptions import SecurityError

class BaseModel(Model):
    """
    基础模型类，所有模型的基类。
    
    定义了一些共有的字段和方法，所有模型都可以继承它。
    包括常见的数据库字段，例如id，创建时间，更新时间，删除标记等。
    
    Attributes:
        id (int): 模型的主键。
        date_created (datetime): 记录在数据库中创建的时间。
        date_updated (datetime): 记录在数据库中更新的时间。
        deleted (bool): 记录是否被标记为删除。
    """

    id: int = fields.IntField(pk=True)
    date_created: datetime.datetime = fields.DatetimeField(
        auto_now_add=True, description="创建时间")
    date_updated: datetime.datetime = fields.DatetimeField(
        auto_now=True, description="更新时间")
    deleted: bool = fields.BooleanField(default=False, description="删除标记")

    def validate(self) -> None:
        """
        验证模型的状态是否合法。子类可以覆盖这个方法来实现特定的验证逻辑。
        
        Raises:
            SecurityError: 如果验证失败，会引发此异常。
        """
        raise NotImplementedError("子类必须实现此方法")

    @property
    def json(self) -> dict:
        """
        生成一个JSON可序列化的字典，用于在HTTP请求或响应中使用。
        
        Returns:
            dict: 包含模型数据的字典。
            
        Note:
            这个方法可以将模型的数据转换为JSON格式，以便在HTTP请求和响应中传递数据。
            子类必须实现此方法以提供自定义的JSON序列化。
        """
        raise NotImplementedError("子类必须实现此方法")
    
    @classmethod
    async def get_or_none(cls, **kwargs):
        """
        获取单个记录，如果不存在则返回None
        
        Args:
            **kwargs: 查询条件
            
        Returns:
            模型实例或None
        """
        try:
            return await cls.get(**kwargs)
        except:
            return None
            
    @classmethod
    async def safe_delete(cls, **kwargs):
        """
        安全删除记录(软删除)
        
        Args:
            **kwargs: 查询条件
            
        Returns:
            被删除的记录数量
        """
        obj = await cls.get(**kwargs)
        if obj:
            obj.deleted = True
            await obj.save()
            return 1
        return 0
    
    class Meta:
        abstract = True  # 标记为抽象类 