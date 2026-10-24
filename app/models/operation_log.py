#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
操作日志模型模块（字段以 app/api/resources/log.py 及 dashboard 统计的使用为准）
"""
from tortoise import fields
from app.models.base import BaseModel


class OperationLog(BaseModel):
    """
    操作日志

    Attributes:
        account: 操作账户（账户被删除后日志保留，account_id 置空）
        account_name (str): 操作时的账户名快照
        operation (str): 操作名称，如 login
        operation_type (str): 操作类型/资源类型，如 auth
        detail (str): 详情
        status (str): 结果，success / failure
        ip_address (str): 客户端 IP
        user_agent (str): 客户端 User-Agent
    """
    account = fields.ForeignKeyField(
        "models.Account", related_name=False, null=True, on_delete=fields.SET_NULL
    )
    account_name: str = fields.CharField(max_length=64, null=True)
    operation: str = fields.CharField(max_length=128)
    operation_type: str = fields.CharField(max_length=64, index=True)
    detail: str = fields.TextField(null=True)
    status: str = fields.CharField(max_length=16, default="success", index=True)
    ip_address: str = fields.CharField(max_length=45, null=True)
    user_agent: str = fields.CharField(max_length=255, null=True)

    class Meta:
        table = "operation_log"

    @property
    def json(self) -> dict:
        return {
            "id": self.id,
            "account_id": self.account_id,
            "account_name": self.account_name,
            "operation": self.operation,
            "operation_type": self.operation_type,
            "detail": self.detail,
            "status": self.status,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat(),
        }

    def validate(self) -> None:
        """操作日志没有额外的状态约束。"""
