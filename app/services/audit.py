#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
认证路径的操作审计日志（SA-v034-L1）。

**背景**：`OperationLog` 模型、只读 API 与仪表盘统计此前都已存在，但**全仓没有任何
写入点**——`app/api/resources/log.py` 的注释声称「写入由认证/管理路径负责」，而那些
路径实际上从未写入。本模块补上认证侧的写入，范围严格限定为：

    login_success / login_failure / logout / change_password（成功 / 失败 / 2FA 未完成）
    / two_step_success / two_step_failure

管理类 CRUD 的审计见本模块的 :func:`record_resource_event`（SA-v042-AUDIT）：
生成器在产出 create / update / delete 时统一调用它。

三条硬性约束：

1. **绝不写入敏感值**：口令、JWT token、2FA 验证码一律不进日志。调用方只传
   「发生了什么」，不传凭据；本模块也不读请求体。
2. **写日志不能拖垮主请求**：任何异常都被吞掉并记一条 warning——审计是旁路，
   不是主路径的一部分。
3. **IP 采信沿用登录限流的口径**：复用 `app.auth.rate_limit.LoginRateLimiter`
   的 TRUSTED_PROXIES 判定（可信代理下才采信 X-Forwarded-For，否则用 socket 直连
   对端）。该逻辑已存在，不另起一套。
"""

import json
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
        # 密码重置（AUTH-03）：两阶段流程，各自留痕。
        # request 阶段不记邮箱（防枚举——不存在的邮箱和存在的邮箱写同样的日志
        # 就没意义了，但记了会变成「谁能查哪些邮箱注册过」的侧信道）；
        # confirm 阶段记账户与失败原因（令牌无效 / 过期）。
        "password_reset_request",
        "password_reset_confirm",
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


#: 允许写入的资源动作（白名单）。与 :data:`OPERATIONS` 分开，避免认证操作名
#: 与 CRUD 动作名互相污染。
RESOURCE_ACTIONS = frozenset({"create", "update", "delete"})


async def record_resource_event(
    request: Request,
    *,
    resource: str,
    action: str,
    object_id,
    account=None,
    fields: Optional[list] = None,
    status: str = "success",
) -> None:
    """记录一条生成资源的 CRUD 审计日志（SA-v042-AUDIT）。

    生成器产出 create / update / delete 时调用。**只记字段名，不记字段值**——
    资源里可能有手机号、邮箱、金额等，值进了日志就等于绕过了脱敏。

    Args:
        request: 当前请求（用于取 IP / User-Agent）
        resource: 资源名（如 ``ticket``），写入 ``operation_type``（该列有索引）
        action: 必须是 :data:`RESOURCE_ACTIONS` 之一
        object_id: 被操作的记录 id；删除后该行仍可追溯
        account: 操作者账户
        fields: **仅字段名**，如 ``["title", "status"]``；调用方不得传值
        status: ``success`` / ``failure``

    本函数**永不抛出**：审计失败只记 warning，不影响主请求结果。
    """
    if action not in RESOURCE_ACTIONS:
        logger.warning("资源审计动作不在白名单内，已忽略: %r", action)
        return

    # detail 只拼 id 与字段名，不含任何字段值。
    #
    # 字段名用 JSON 数组编码而不是逗号拼接：规格允许字段名含任意字符（见
    # specgen 的字段名校验），``",".join`` 会让 ``["a,b", "c"]`` 编码成
    # ``a,b,c``，读回时无法区分是 2 个字段还是 3 个（缺陷池 BL-01）。
    # JSON 数组是自定界的，任何字段名都能无损往返。
    parts = [f"id={object_id}"]
    if fields:
        parts.append("fields=" + json.dumps([str(f) for f in fields], ensure_ascii=False))
    detail = " ".join(parts)

    try:
        from app.models import OperationLog

        await OperationLog.create(
            account=account,
            account_name=getattr(account, "username", None) if account else None,
            operation=action,
            operation_type=str(resource)[:64],
            detail=detail,
            status=status,
            ip_address=_client_ip(request),
            user_agent=(request.headers.get("User-Agent") or "")[:255] or None,
        )
    except Exception:
        # 审计是旁路：日志表写不进去不能让业务写请求失败。
        logger.warning(
            "写入资源审计日志失败（已忽略）: resource=%s action=%s",
            resource,
            action,
            exc_info=True,
        )
