#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
投递渠道抽象（AUTH-03）。

本模块只定义「怎么把一封消息送出去」，不关心消息内容是什么。

**为什么需要这一层**：项目当前没有接入任何真实投递渠道（SMTP / 短信 / 推送）。
如果没有这层抽象，密码重置这类功能就无法验证——「发重置邮件」这条完成定义
在本地根本跑不起来。有了 `LoggingBackend` 作为默认实现，测试可以断言「消息
被投递了、收件人是谁、正文里有没有 token」，而生产部署可以替换为真实后端。

**默认实现不发送任何东西**：`LoggingBackend` 只写一条日志。这是**有意的**——
在未配置真实渠道时，宁可什么都不发，也不要把 token 打到未经审计的外部通道。
生产部署必须显式替换 `backend`，否则重置请求不会真正送达用户。

用法：

    from app.services.delivery import Backend, LoggingBackend, set_backend, deliver

    deliver(Backend)   # 默认已被 set_backend(LoggingBackend()) 初始化
    await deliver(to="user@example.com", subject="重置口令", body="...")

替换为真实后端（部署侧）：

    from app.services.delivery import Backend, set_backend

    class SMTPBackend(Backend):
        async def send(self, to: str, subject: str, body: str) -> None:
            ...

    set_backend(SMTPBackend())
"""

from __future__ import annotations

import abc
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class Backend(abc.ABC):
    """
    投递后端接口。实现只需保证「不抛异常即视为送达」。

    实现方注意：
    - `send()` 是 async 的，不要在内部做阻塞调用（阻塞 IO 请用线程池）
    - 不要在日志里打印正文全文——正文可能含重置 token。只记长度或摘要
    """

    @abc.abstractmethod
    async def send(self, to: str, subject: str, body: str) -> None:
        """
        投递一条消息。

        Args:
            to: 收件人标识（邮箱 / 手机号 / 设备标识，由后端自行解释）
            subject: 主题
            body: 正文
        """


class LoggingBackend(Backend):
    """
    默认后端：只写日志，不真正投递。

    **这是刻意的「不做」**：未配置真实渠道时，任何「以为发出去了」行为都是
    安全隐患（token 可能进入不可控的日志汇聚点）。开发与测试用它验证流程，
    生产必须替换。

    日志里**不打印 body**——密码重置的 body 含一次性 token。只记收件人与
    正文长度，足够证明「投递发生了」而不泄露凭据。
    """

    async def send(self, to: str, subject: str, body: str) -> None:
        logger.info(
            "delivery(noop): to=%s subject=%r body_len=%d (LoggingBackend 不实际发送；生产需替换 backend)",
            to,
            subject,
            len(body),
        )


_backend: Optional[Backend] = None


def set_backend(backend: Backend) -> None:
    """替换投递后端。部署侧在启动时调用一次。"""
    global _backend
    if not isinstance(backend, Backend):
        raise TypeError(f"backend 必须是 Backend 实例，实际 {type(backend).__name__}")
    _backend = backend


def get_backend() -> Backend:
    """当前后端；未设置时惰性初始化为 `LoggingBackend`。"""
    global _backend
    if _backend is None:
        _backend = LoggingBackend()
    return _backend


async def deliver(*, to: str, subject: str, body: str) -> bool:
    """
    投递一条消息。**永不抛出**——投递失败不应让调用方（如密码重置请求）暴露
    内部状态，也不应让请求失败。

    Returns:
        True 表示后端调用正常返回；False 表示后端抛了异常（已记 warning）。
    """
    try:
        await get_backend().send(to=to, subject=subject, body=body)
        return True
    except Exception:
        logger.warning("投递失败（已忽略）: to=%s subject=%r", to, subject, exc_info=True)
        return False


def reset_backend() -> None:
    """测试用：恢复为未初始化状态（下次 get_backend 会重建 LoggingBackend）。"""
    global _backend
    _backend = None
