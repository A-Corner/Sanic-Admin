#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
MCP 写入路径的身份校验（SA-v042-SPECWRITE）。

设计见 ``docs/mcp-write-path.md`` §10（CPL 已裁定）。核心契约（fail-closed）：

- token 从环境变量 :data:`TOKEN_ENV` 读取（现有会话 JWT，**不新增** token 类型；
  过期后重新签发并重启进程，吊销靠作废会话）；
- 校验 = ``GET {API}/auth/whoami``（Authorization: Bearer），返回 account_id
  与合并权限；MCP 只做 ``spec:write`` 的集合判断，不复制 RBAC 归一化规则；
- 回调目标默认只允许本机回环，可用 :data:`API_URL_ENV` 显式覆盖——防止 token
  被发到非预期主机（CPL 约束 3）；
- 超时 5s（CPL 上限）；任何失败（未配置/无效/过期/2FA pending/需改密/无权限/
  服务不可达）一律拒绝，不重试；
- 不打印 token：token 不进异常消息、不进审计、不进返回值。

只依赖标准库（urllib）——不把 httpx 设为硬依赖，纯单元测试环境无需安装 mcp。
"""

from __future__ import annotations

import http.client
import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from tools.mcp_server import ToolError

#: 环境变量名：MCP 进程持有的会话 JWT。
TOKEN_ENV = "SANIC_ADMIN_MCP_TOKEN"
#: 环境变量名：whoami 服务地址（显式配置才允许指向非回环主机）。
API_URL_ENV = "SANIC_ADMIN_MCP_API_URL"
#: 环境变量名：非回环地址的显式放行开关（值为 "1" 时生效）。
ALLOW_REMOTE_ENV = "SANIC_ADMIN_MCP_ALLOW_REMOTE"
#: 默认回调地址：本机回环（token 默认不出本机）。
DEFAULT_API_URL = "http://127.0.0.1:22222"

#: 默认允许的回调主机：仅本机回环。
#: 注意按**完整 host 串精确匹配**——``127.0.0.1.evil.com`` 这类后缀域名
#: 不以任何形式命中此表（审核整改：URL 形态攻击面）。
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

#: 回调超时上限（CPL 约束 3：5s 以内）。
TIMEOUT_SECONDS = 5.0

#: 写入工具要求的权限点。
SPEC_RESOURCE = "spec"
SPEC_ACTION = "write"


class IdentityError(ToolError):
    """
    身份/权限校验失败。消息可安全展示（结构性不含 token）。

    ``reason`` 供审计使用，取值：

    - ``identity_not_configured``：env 未配置 token；
    - ``identity_invalid``：token 无效/过期/会话不可用（whoami 401）；
    - ``permission_denied``：需要改密或没有 spec:write（whoami 403 / 集合判断）；
    - ``identity_unavailable``：校验服务不可达/超时（fail-closed）。
    """

    def __init__(self, message: str, *, reason: str = "identity_invalid"):
        super().__init__(message)
        self.reason = reason


def get_token() -> Optional[str]:
    """读环境变量里的 token。缺失/空白返回 None（进程启动后不变）。"""
    token = os.environ.get(TOKEN_ENV, "")
    return token.strip() or None


def get_api_url() -> str:
    """回调地址：env 显式配置优先，否则本机回环默认。"""
    return os.environ.get(API_URL_ENV, "").strip() or DEFAULT_API_URL


def _guard_api_url(url: str) -> str:
    """
    回调目标约束（审核整改后的完整形态）：

    - 必须是 http(s) URL 且有主机名；
    - **拒绝携带 userinfo**（``http://127.0.0.1@evil.com`` 的真实 host 是
      ``evil.com``——userinfo 是经典的 URL 混淆攻击面）；
    - host 必须**精确命中** :data:`LOOPBACK_HOSTS`（回环）；
    - 非回环必须显式设 :data:`ALLOW_REMOTE_ENV` ``=1`` 且强制 https。

    默认 :data:`DEFAULT_API_URL` 是回环；指向内网服务实例（容器部署等）
    是显式配置行为，风险由部署方承担（§10.4）。
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise IdentityError(
            f"{API_URL_ENV} 不合法（需要带主机名的 http(s) URL）",
            reason="identity_not_configured",
        )
    # urlsplit 对 `http://user@host/` 会把 user 归入 username；任何 userinfo 都拒
    if parts.username is not None or parts.password is not None:
        raise IdentityError(
            f"{API_URL_ENV} 不允许携带 userinfo（user:pass@host 形态）",
            reason="identity_not_configured",
        )
    # query / fragment 不属于服务地址本身，一律拒绝——防止经 `?next=` 一类
    # 参数把语义带偏，也让 URL 校验面保持最小
    if parts.query or parts.fragment:
        raise IdentityError(
            f"{API_URL_ENV} 不允许携带 query 或 fragment",
            reason="identity_not_configured",
        )
    host = parts.hostname.lower()
    if host in LOOPBACK_HOSTS:
        return url
    # 非回环：双重显式放行（开关 + https）
    if os.environ.get(ALLOW_REMOTE_ENV, "").strip() != "1":
        raise IdentityError(
            f"{API_URL_ENV} 只允许回环地址（{', '.join(sorted(LOOPBACK_HOSTS))}）；"
            f"要指向其他主机必须显式设置 {ALLOW_REMOTE_ENV}=1，且使用 https",
            reason="identity_not_configured",
        )
    if parts.scheme != "https":
        raise IdentityError(
            f"非回环地址必须使用 https（当前 {parts.scheme}://），token 不允许明文出本机",
            reason="identity_not_configured",
        )
    return url


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """
    禁止跟随重定向：``redirect_request`` 返回 None 时，urllib 会把 3xx
    作为 :class:`urllib.error.HTTPError` 抛出，而不是带着 Authorization 头
    打向 Location 指向的第二台主机（审核整改：重定向外泄面）。
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


#: 专用 opener：禁重定向（上面的 handler）+ 禁代理。
#: 默认 opener 会读 HTTP_PROXY/HTTPS_PROXY/ALL_PROXY 环境变量——
#: ``ProxyHandler({})`` 强制直连，token 永不经代理转发。
_OPENER = urllib.request.build_opener(_NoRedirect(), urllib.request.ProxyHandler({}))


def fetch_whoami(token: str, api_url: str) -> Dict[str, Any]:
    """
    调 ``GET /auth/whoami``，返回 ``{"account_id", "permissions"}``。

    失败分类（全部抛 :class:`IdentityError`，reason 供审计）：

    - HTTP 401 → ``identity_invalid``（token 无效、过期、会话被禁用、
      2FA 未完成——服务端 ``requires_authentication`` 统一拒绝）；
    - HTTP 403 → ``permission_denied``（改密拦截或权限不足）；
    - 3xx（重定向被禁） / 其他状态码 / 连接失败 / 超时 →
      ``identity_unavailable``（fail-closed）。
    """
    url = _guard_api_url(api_url).rstrip("/") + "/auth/whoami"
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    try:
        # 用专用 opener（禁重定向、禁代理），不用全局 urlopen
        with _OPENER.open(req, timeout=TIMEOUT_SECONDS) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # HTTPError 的消息不含请求头（token 不会进异常链）；
        # 异常对象被丢弃（from None），只保留分类后的文案。
        if exc.code == 401:
            raise IdentityError(
                "身份校验未通过（token 无效、过期或 2FA 未完成）",
                reason="identity_invalid",
            ) from None
        if exc.code == 403:
            raise IdentityError(
                "访问被拒绝（需要先完成改密，或没有所需权限）",
                reason="permission_denied",
            ) from None
        raise IdentityError(
            f"无法校验权限：whoami 返回 HTTP {exc.code}",
            reason="identity_unavailable",
        ) from None
    except (
        urllib.error.URLError,
        http.client.HTTPException,
        ValueError,
        OSError,
    ) as exc:
        # URLError：连接拒绝/DNS 失败；socket.timeout 是 OSError 子类；
        # http.client.HTTPException：协议层异常（IncompleteRead/BadStatusLine 等）；
        # ValueError：JSON 解析失败与头编码错误。都按「服务不可达」fail-closed。
        _ = exc  # 异常消息可能含 URL，不进入错误文案
        raise IdentityError(
            "无法校验权限（服务不可达）——按 fail-closed 拒绝",
            reason="identity_unavailable",
        ) from None
    if not isinstance(body, dict):
        raise IdentityError("whoami 响应不是 JSON 对象", reason="identity_unavailable")
    if "account_id" not in body or "permissions" not in body:
        raise IdentityError("whoami 响应缺少 account_id/permissions", reason="identity_unavailable")
    return body


def has_spec_write(permissions: Any) -> bool:
    """集合判断：``permissions["spec"]`` 含 ``"write"`` 或 ``"all"``。"""
    if not isinstance(permissions, dict):
        return False
    actions = permissions.get(SPEC_RESOURCE)
    if not isinstance(actions, list):
        return False
    return SPEC_ACTION in actions or "all" in actions


def require_spec_write() -> Any:
    """
    写入工具的前置校验入口，返回 ``account_id``（供审计关联）。

    校验顺序即失败矩阵（§10.5）：未配置 → 401 → 403 → 集合判断。
    任何一步不过都抛 :class:`IdentityError`；调用方必须让它向上传播，
    不得捕获后继续执行写操作。
    """
    token = get_token()
    if not token:
        raise IdentityError(
            f"需要配置 {TOKEN_ENV}（MCP 会话 JWT）才能使用写入工具；用登录接口签发会话后，以环境变量传入并重启本进程",
            reason="identity_not_configured",
        )
    whoami = fetch_whoami(token, get_api_url())
    if not has_spec_write(whoami.get("permissions")):
        raise IdentityError(
            f"当前账户（account_id={whoami.get('account_id')}）没有 spec:write 权限；请联系管理员为所属角色显式授予",
            reason="permission_denied",
        )
    return whoami.get("account_id")
