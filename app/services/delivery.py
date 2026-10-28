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

**「未配置」必须在启动期可见（AUTH-13）**：`LoggingBackend.send()` 正常返回，
所以 `deliver()` 会返回 True、审计记 success、用户看到「已发送」——「忘了配」
与「配好了且投递成功」在运行期**完全同形**。`check_backend_configured()` 是唯一
能把两者区分开的地方，由 `app/__init__.py` 的 `before_server_start` 监听器调用：
非生产只打 warning，生产直接拒绝启动，除非显式声明 `ALLOW_NOOP_DELIVERY=1`。

用法：

    from app.services.delivery import LoggingBackend, set_backend, deliver

    set_backend(LoggingBackend())  # 未调用时 get_backend() 会惰性初始化同一个默认后端
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


class DeliveryNotConfigured(RuntimeError):
    """生产环境未配置真实投递后端，拒绝启动（AUTH-13）。

    这不是「投递失败」——投递从未发生。抛出它的是启动期检查
    :func:`check_backend_configured`，不是运行期的 :func:`deliver`。
    """


def is_backend_configured() -> bool:
    """
    当前后端是否为**真实投递**实现。

    判定标准是「不是 `LoggingBackend`」而不是「已被 `set_backend()` 」：
    显式 `set_backend(LoggingBackend())` 仍然不投递任何东西，等于没配——
    用它当生产后端照样会让重置请求永远收不到。
    """
    backend = _backend
    if backend is None:
        return False
    return not isinstance(backend, LoggingBackend)


def check_backend_configured(*, env: str, allow_noop: bool = False) -> bool:
    """
    启动期检查投递后端是否已配置真实实现（AUTH-13）。

    **为什么需要这个函数**：`LoggingBackend.send()` 正常返回，所以未配置时
    `deliver()` 返回 True、审计记 success、用户看到「已发送」——与「配好了且
    投递成功」在运行期完全同形。唯一的区分点是启动期。

    **为什么非生产只 warning**：本地开发与测试本来就没有真实渠道，fail-fast
    会让所有现有开发/测试环境起不来，而它们的问题并不是安全问题。

    **为什么生产 fail-fast**：生产漏配后端 = 密码重置功能静默失效且无从发现。
    对安全相关功能宁可起不来，也不要带着「看起来能用、实际发不出」的状态运行。

    Args:
        env: 当前环境名（取自 ``app.config`` 的 ``ENV``，即 ``SANIC_ENV`` 的归一结果）
        allow_noop: 生产环境是否显式放行未配置后端（``ALLOW_NOOP_DELIVERY=1``）。

    Returns:
        True 表示真实投递可用；False 表示预期不会真正投递（非生产，或生产已放行）。

    Raises:
        DeliveryNotConfigured: 生产环境未配置后端且未放行。
    """
    if is_backend_configured():
        return True

    if env != "production":
        logger.warning(
            "投递后端未配置，当前使用 LoggingBackend（只写日志、不实际发送）——"
            "环境=%s。密码重置等消息不会真正送达；仅适用于开发/测试。",
            env,
        )
        return False

    if allow_noop:
        # 逃生阀：语义是「本部署确认不依赖邮件投递」，不是「懒得配」。
        logger.warning(
            "生产环境投递后端未配置并发依赖 ALLOW_NOOP_DELIVERY=1 放行："
            "所有消息都只会写入日志，不会送达任何收件人。"
            "仅当本部署确认不依赖投递功能时才可这样。"
        )
        return False

    raise DeliveryNotConfigured(
        "生产环境必须通过 set_backend() 配置真实投递后端；"
        "当前会退化为 LoggingBackend（只写日志、不实际发送），密码重置等消息将静默失效。"
        "若本部署确认不依赖消息投递，请显式设置 ALLOW_NOOP_DELIVERY=1。"
    )
