#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
认证路径的操作审计日志（SA-v034-L1）。

**背景**：`OperationLog` 模型、只读 API 与仪表盘统计此前都已存在，但**全仓没有任何
写入点**——`app/api/resources/log.py` 的注释声称「写入由认证/管理路径负责」，而那些
路径实际上从未写入。本模块补上认证侧的写入，范围严格限定为：

    login_success / login_failure / logout / change_password（成功 / 失败 / 2FA 未完成）
    / two_step_success / two_step_failure

管理类 CRUD 的审计不在这里（会由生成器统一处理，属另一项任务）。

三条硬性约束：

1. **绝不写入敏感值**：口令、JWT token、2FA 验证码一律不进日志。调用方只传
   「发生了什么」，不传凭据；本模块也不读请求体。
2. **写日志不能拖垮主请求**：任何异常都被吞掉并记一条 warning——审计是旁路，
   不是主路径的一部分。
3. **IP 采信沿用登录限流的口径**：复用 `app.auth.rate_limit.LoginRateLimiter`
   的 TRUSTED_PROXIES 判定（可信代理下才采信 X-Forwarded-For，否则用 socket 直连
   对端）。该逻辑已存在，不另起一套。
"""

import logging
from typing import Optional

from sanic.request import Request

logger = logging.getLogger(__name__)

#: 允许写入的操作名（白名单，防止调用方手滑写入任意字符串）
OPERATIONS = frozenset(
    {
        "login_success",
        "login_failure",
        "logout",
        "change_password_success",
        "change_password_failure",
        "change_password_2fa_pending",
        "two_step_success",
        "two_step_failure",
        # GET /auth/whoami（SA-v042-SPECWRITE）：MCP 写入路径的身份校验端点。
        # 每次调用都留痕——它是权限清单的出口，谁在什么时候查过要可归因。
        "whoami",
    }
)


def _client_ip(request: Request) -> Optional[str]:
    """取客户端 IP，采信口径与登录限流一致（TRUSTED_PROXIES 下才信 XFF）。"""
    try:
        from app.auth.rate_limit import LoginRateLimiter

        limiter = LoginRateLimiter.from_request(request)
        return limiter._client_ip(request)
    except Exception:
        # 限流器不可用时退回 socket 对端。
        # 限制：若部署在反向代理之后，这里记录到的会是代理的地址，而不是真实客户端
        # ——所以 TRUSTED_PROXIES 未配置时，IP 字段仅供粗略参考。
        return getattr(request, "remote_addr", None)


async def record_auth_event(
    request: Request,
    operation: str,
    *,
    account=None,
    status: str = "success",
    detail: Optional[str] = None,
) -> None:
    """记录一条认证审计日志。

    Args:
        request: 当前请求（用于取 IP / User-Agent）
        operation: 操作名，必须是 :data:`OPERATIONS` 之一
        account: 相关账户（可为 None，例如登录失败时账户不存在）
        status: ``success`` / ``failure``
        detail: 非敏感补充说明（例如失败原因分类）。**调用方不得传入口令、
            token 或验证码**——此参数只用于「口令错误」这类固定短语。

    本函数**永不抛出**：审计失败只记 warning，不影响主请求结果。
    """
    if operation not in OPERATIONS:
        logger.warning("审计操作名不在白名单内，已忽略: %r", operation)
        return

    try:
        from app.models import OperationLog

        await OperationLog.create(
            account=account,
            account_name=getattr(account, "username", None) if account else None,
            operation=operation,
            operation_type="auth",
            detail=detail,
            status=status,
            ip_address=_client_ip(request),
            user_agent=(request.headers.get("User-Agent") or "")[:255] or None,
        )
    except Exception:
        # 审计是旁路：模型未迁移、库不可写等都不能让登录/改密失败。
        logger.warning("写入认证审计日志失败（已忽略）: operation=%s", operation, exc_info=True)
