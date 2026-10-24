#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
上传文件模型模块（字段以 app/api/resources/upload.py 的使用为准）
"""
from tortoise import fields
from app.models.base import BaseModel


class UploadedFile(BaseModel):
    """
    上传文件记录

    Attributes:
        filename (str): 原始文件名
        stored_filename (str): 存储文件名
        file_path (str): 相对上传目录的存储路径
        file_type (str): MIME 类型
        file_size (float): 文件大小（KB）
        category (str): 文件分类
        account: 上传者
        download_count (int): 下载次数
    """
    filename: str = fields.CharField(max_length=255)
    stored_filename: str = fields.CharField(max_length=255)
    file_path: str = fields.CharField(max_length=512, index=True)
    file_type: str = fields.CharField(max_length=128, null=True)
    file_size: float = fields.FloatField(default=0)
    category: str = fields.CharField(max_length=64, null=True)
    account = fields.ForeignKeyField(
        "models.Account", related_name=False, null=True, on_delete=fields.SET_NULL
    )
    download_count: int = fields.IntField(default=0)

    class Meta:
        table = "uploaded_file"

    @property
    def json(self) -> dict:
        return {
            "id": self.id,
            "filename": self.filename,
            "file_path": self.file_path,
            "file_type": self.file_type,
            "file_size": self.file_size,
            "category": self.category,
            "account_id": self.account_id,
            "download_count": self.download_count,
            "created_at": self.created_at.isoformat(),
        }

    def validate(self) -> None:
        """上传文件记录没有额外的状态约束。"""
