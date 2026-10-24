# -*- coding: utf-8 -*-
"""
spec:write 账户级权限测试（SA-v042-SPECWRITE，docs/mcp-write-path.md §10.8.1）。

对应 CPL 约束 4 的测试矩阵，分两层：

- **HTTP 侧**：``/auth/whoami`` 端点语义——真实 ASGI 客户端 + 真实登录会话，
  覆盖 token 缺失/无效/过期/2FA pending/需要改密/普通用户无权限。
- **MCP 侧**：``identity`` + ``write_tools`` 的 fail-closed 行为——七种拒绝
  情形逐一对应（whoami 的服务端语义由 HTTP 侧用例证明，MCP 侧按响应分类
  mock），每条拒绝用例都断言**零副作用**（用户仓库分支列表不变）。

破坏实验（CPL 约束 4）：去掉 ``on_whoami`` 的 ``must_change_password``
显式检查，:func:`test_whoami_rejects_must_change_password_handler_level`
必须变红；还原后复绿。此实验的原始输出存于交付回报。
"""

from __future__ import annotations

import json as _json
import os
from datetime import timedelta
from pathlib import Path

import pytest

from app.models import Account, AuthenticationSession
from app.middleware.auth_middleware import PASSWORD_CHANGE_EXEMPT_PREFIXES
from app.services.utils import utcnow
from tools.mcp_server.identity import (
    ALLOW_REMOTE_ENV,
    API_URL_ENV,
    DEFAULT_API_URL,
    TOKEN_ENV,
    IdentityError,
    _guard_api_url,
    fetch_whoami,
    get_api_url,
    get_token,
    has_spec_write,
)
from tools.mcp_server.write_tools import (
    discard_proposal_tool,
    list_proposals,
    propose_spec_change,
)

#: 测试用假 token：审计与错误消息里**不得**出现该子串（结构性不打印的断言锚点）。
#: 必须纯 ASCII——HTTP 头只接受 latin-1 可编码值，真实 JWT 亦为 ASCII。
SECRET_TOKEN = "test-secret-token-XYZ-leak-canary"

#: 一个可用的最小规格（resource 合法、含一个必填 string 字段）
DEMO_SPEC = "resource: demo\nlabel: 演示\nplural: demos\nfields:\n  - name: title\n    type: string\n    required: true\n"


# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------


def _run(cwd: Path, *args: str) -> str:
    import subprocess

    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _branch_list(repo: Path) -> list:
    """用户仓库的全部分支短名（零副作用断言的基线）。"""
    return [b for b in _run(repo, "branch", "--format=%(refname:short)").splitlines() if b]


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _run(r, "init", "-q")
    _run(r, "config", "user.email", "t@example.invalid")
    _run(r, "config", "user.name", "t")
    (r / "specs").mkdir()
    (r / "specs" / "demo.yaml").write_text("name: demo\n", encoding="utf-8")
    _run(r, "add", "-A")
    _run(r, "commit", "-q", "-m", "init")
    head = _run(r, "rev-parse", "HEAD").strip()
    _run(r, "update-ref", "refs/heads/master", head)
    return r


@pytest.fixture()
def token_env(monkeypatch):
    """给 MCP 侧用例配置一个假 token（配合 mock 的 whoami 使用）。"""
    monkeypatch.setenv(TOKEN_ENV, SECRET_TOKEN)
    monkeypatch.delenv(API_URL_ENV, raising=False)
    return SECRET_TOKEN


def _mock_whoami(monkeypatch, *, account_id=7, permissions=None, http_error=None):
    """
    替换 ``identity.fetch_whoami``：

    - ``http_error=401/403/500`` 时抛对应分类的 IdentityError（模拟真实 HTTP 状态）；
    - 否则返回 ``{"account_id", "permissions"}``。
    """
    from tools.mcp_server import identity

    if http_error == 401:

        def fake(token, api_url):
            raise IdentityError("身份校验未通过", reason="identity_invalid")
    elif http_error == 403:

        def fake(token, api_url):
            raise IdentityError("访问被拒绝", reason="permission_denied")
    elif http_error is not None:

        def fake(token, api_url):
            raise IdentityError(f"HTTP {http_error}", reason="identity_unavailable")
    else:

        def fake(token, api_url):
            return {"account_id": account_id, "permissions": permissions or {}}

    monkeypatch.setattr(identity, "fetch_whoami", fake)


def _tmp_proposal_dirs() -> set:
    """系统临时区里本工具的 clone 目录（``mcp-proposal-*`` 前缀，git_isolation.mkdtemp）。"""
    import tempfile

    return {p.name for p in Path(tempfile.gettempdir()).glob("mcp-proposal-*")}


def _assert_zero_side_effect(repo: Path, baseline: list, tmp_baseline: set | None = None):
    """拒绝后：分支列表逐字节不变（没建 proposal/ 分支，也没动别的分支），
    且系统临时区没有残留的 clone 目录。"""
    assert _branch_list(repo) == baseline
    if tmp_baseline is not None:
        assert _tmp_proposal_dirs() == tmp_baseline, "临时 clone 目录集合发生变化（残留或误删）"


# ---------------------------------------------------------------------------
# HTTP 侧：/auth/whoami 端点语义
# ---------------------------------------------------------------------------


async def test_whoami_returns_account_id_and_permissions_for_admin(client, auth_headers):
    """有效 admin 会话 → 200，data 只有 account_id 与 permissions；spec 含 all。"""
    response = await client.get("/auth/whoami", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()["data"]
    assert set(data.keys()) == {"account_id", "permissions"}, f"返回必须最小化：{data.keys()}"
    admin = await Account.filter(is_admin=True).first()
    assert data["account_id"] == admin.id
    # admin_all_permissions()：每个资源都是 ["all"]，spec:write 以 all 覆盖
    assert data["permissions"]["spec"] == ["all"]


async def test_whoami_rejects_missing_token(client):
    """无 token → 401（CPL 矩阵情形 1）。"""
    response = await client.get("/auth/whoami")
    assert response.status_code == 401


async def test_whoami_rejects_invalid_token(client):
    """无效 token → 401（CPL 矩阵情形 2）。"""
    response = await client.get("/auth/whoami", headers={"Authorization": "Bearer not-a-real-token"})
    assert response.status_code == 401


async def test_whoami_rejects_expired_session(client, auth_headers):
    """会话过期 → 401（CPL 矩阵情形 3）。有效性以服务端会话表为准。"""
    past = utcnow() - timedelta(seconds=10)
    await AuthenticationSession.all().update(expires=past)
    response = await client.get("/auth/whoami", headers=auth_headers)
    assert response.status_code == 401


async def test_whoami_rejects_2fa_pending_session(client, auth_headers):
    """2FA 未完成（second_factor_pending）→ 401（CPL 矩阵情形 4）。

    ``second_factor_pending`` 是 property（requires_second_factor 且未验证），
    测试直接置 ``requires_second_factor=True``（verified 保持默认 False）。
    """
    await AuthenticationSession.all().update(requires_second_factor=True)
    response = await client.get("/auth/whoami", headers=auth_headers)
    assert response.status_code == 401


async def test_whoami_rejects_must_change_password(client, auth_headers):
    """
    需要改密的账户 → 403（CPL 矩阵情形 5）。

    走真实 ASGI 栈：``enforce_password_change`` 中间件 fail-closed 拦截——
    ``/auth/whoami`` 不在豁免白名单里，改密前拿不到权限清单。
    """
    await Account.filter(is_admin=True).update(must_change_password=True)
    response = await client.get("/auth/whoami", headers=auth_headers)
    assert response.status_code == 403
    assert "PASSWORD_CHANGE_REQUIRED" in response.text


async def test_whoami_rejects_must_change_password_handler_level(app, client, auth_headers):
    """
    破坏实验锚点（CPL 约束 4）：handler 内的显式 must_change_password 检查。

    直接调 handler（绕过强制改密中间件）也必须拒绝——去掉 on_whoami 里的
    显式检查，本用例必须变红。
    """
    from app.auth.authentication import authenticate_request
    from app.auth.routes import on_whoami
    from app.services.exceptions import PasswordChangeRequiredError

    await Account.filter(is_admin=True).update(must_change_password=True)

    class _Req:
        """最小请求桩：只实现 whoami 链路读到的属性。"""

        def __init__(self, bearer_token, application):
            self.token = bearer_token  # get_session_token 的回退路径
            self.cookies = {}
            self.remote_addr = "127.0.0.1"
            self.app = application
            self.ctx = type("Ctx", (), {})()

    req = _Req(auth_headers["Authorization"].removeprefix("Bearer "), app)
    req.ctx.authentication_session = await authenticate_request(req, True)

    # on_whoami 被 @requires_authentication() 包装，其 find_request 只认 Sanic
    # Request；经 __wrapped__ 直接调原始 handler，单独锚定 handler 体内的
    # must_change_password 显式检查（去掉它本用例必须变红）。
    with pytest.raises(PasswordChangeRequiredError):
        await on_whoami.__wrapped__(req)


async def test_whoami_normal_user_has_no_spec_permission(client, normal_auth_headers):
    """普通用户（reader 角色，permissions={}）→ 200 但 permissions 无 spec（CPL 矩阵情形 6 的服务端侧）。"""
    response = await client.get("/auth/whoami", headers=normal_auth_headers)
    assert response.status_code == 200
    data = response.json()["data"]
    assert "spec" not in data["permissions"]


async def test_whoami_is_not_in_password_change_exempt_prefixes():
    """白名单回归守卫：/auth/whoami 绝不允许进强制改密豁免前缀。"""
    for prefix in PASSWORD_CHANGE_EXEMPT_PREFIXES:
        assert not prefix.startswith("/auth/whoami"), prefix


async def test_whoami_writes_audit(client, auth_headers):
    """whoami 成功留审计（操作名 whoami），不写 token。"""
    from app.models import OperationLog

    response = await client.get("/auth/whoami", headers=auth_headers)
    assert response.status_code == 200
    log = await OperationLog.filter(operation="whoami").order_by("-id").first()
    assert log is not None, "whoami 必须写审计"
    assert log.account_id is not None


# ---------------------------------------------------------------------------
# MCP 侧：identity 模块单元行为
# ---------------------------------------------------------------------------


def test_get_token_reads_env(monkeypatch):
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    assert get_token() is None
    monkeypatch.setenv(TOKEN_ENV, "  x  ")
    assert get_token() == "x"
    monkeypatch.setenv(TOKEN_ENV, "   ")
    assert get_token() is None


def test_get_api_url_defaults_to_loopback(monkeypatch):
    monkeypatch.delenv(API_URL_ENV, raising=False)
    assert get_api_url() == DEFAULT_API_URL
    assert DEFAULT_API_URL.startswith("http://127.0.0.1"), "默认必须回环"


def test_guard_api_url_rejects_malformed():
    for bad in ("", "ftp://x", "http://", "/no/scheme", "not a url"):
        with pytest.raises(IdentityError):
            _guard_api_url(bad)


def test_has_spec_write_variants():
    assert has_spec_write({"spec": ["all"]}) is True  # admin 形态
    assert has_spec_write({"spec": ["write"]}) is True  # 显式授予形态
    assert has_spec_write({"spec": ["read"]}) is False
    assert has_spec_write({}) is False
    assert has_spec_write({"other": ["all"]}) is False
    assert has_spec_write(None) is False
    assert has_spec_write("spec:write") is False


def test_fetch_whoami_rejects_when_unreachable(monkeypatch):
    """Sanic 不可达 → 真实连接失败 → identity_unavailable（CPL 矩阵情形 7，不 mock）。"""
    monkeypatch.setenv(API_URL_ENV, "http://127.0.0.1:1")  # 端口 1：本机必然拒绝连接
    with pytest.raises(IdentityError) as exc_info:
        fetch_whoami(SECRET_TOKEN, get_api_url())
    assert exc_info.value.reason == "identity_unavailable"
    # 异常消息不含 token
    assert SECRET_TOKEN not in str(exc_info.value)


# ---------------------------------------------------------------------------
# MCP 侧：写入工具的七种拒绝 + 零副作用（CPL 约束 4 矩阵）
# ---------------------------------------------------------------------------

_WRITE_CALLS = {
    "propose": lambda repo: propose_spec_change("demo", DEMO_SPEC, repo_root=repo),
    "list": lambda repo: list_proposals(repo_root=repo),
    "discard": lambda repo: discard_proposal_tool("proposal/x", repo_root=repo),
}


def test_write_tools_reject_without_token(repo, monkeypatch):
    """情形 1：token 缺失 → identity_not_configured，三个工具全部拒绝且零副作用。"""
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    baseline = _branch_list(repo)
    tmp_baseline = _tmp_proposal_dirs()
    for name, call in _WRITE_CALLS.items():
        with pytest.raises(IdentityError) as exc_info:
            call(repo)
        assert exc_info.value.reason == "identity_not_configured", name
    _assert_zero_side_effect(repo, baseline, tmp_baseline)


def test_write_tools_reject_invalid_token(repo, token_env, monkeypatch):
    """情形 2：token 无效（whoami 401）→ identity_invalid，零副作用。"""
    _mock_whoami(monkeypatch, http_error=401)
    baseline = _branch_list(repo)
    tmp_baseline = _tmp_proposal_dirs()
    for name, call in _WRITE_CALLS.items():
        with pytest.raises(IdentityError) as exc_info:
            call(repo)
        assert exc_info.value.reason == "identity_invalid", name
    _assert_zero_side_effect(repo, baseline, tmp_baseline)


def test_write_tools_reject_expired_session(repo, token_env, monkeypatch):
    """情形 3：会话过期（服务端 401；语义由 HTTP 侧用例证明）→ 拒绝，零副作用。"""
    _mock_whoami(monkeypatch, http_error=401)
    baseline = _branch_list(repo)
    tmp_baseline = _tmp_proposal_dirs()
    for name, call in _WRITE_CALLS.items():
        with pytest.raises(IdentityError):
            call(repo)
    _assert_zero_side_effect(repo, baseline, tmp_baseline)


def test_write_tools_reject_2fa_pending(repo, token_env, monkeypatch):
    """情形 4：2FA pending（服务端 401；语义由 HTTP 侧用例证明）→ 拒绝，零副作用。"""
    _mock_whoami(monkeypatch, http_error=401)
    baseline = _branch_list(repo)
    tmp_baseline = _tmp_proposal_dirs()
    for name, call in _WRITE_CALLS.items():
        with pytest.raises(IdentityError):
            call(repo)
    _assert_zero_side_effect(repo, baseline, tmp_baseline)


def test_write_tools_reject_must_change_password(repo, token_env, monkeypatch):
    """情形 5：需要改密（whoami 403 PASSWORD_CHANGE_REQUIRED）→ 拒绝，零副作用。"""
    _mock_whoami(monkeypatch, http_error=403)
    baseline = _branch_list(repo)
    tmp_baseline = _tmp_proposal_dirs()
    for name, call in _WRITE_CALLS.items():
        with pytest.raises(IdentityError) as exc_info:
            call(repo)
        assert exc_info.value.reason == "permission_denied", name
    _assert_zero_side_effect(repo, baseline, tmp_baseline)


def test_write_tools_reject_without_spec_write(repo, token_env, monkeypatch):
    """情形 6：有效会话但没有 spec:write → 集合判断拒绝，零副作用。"""
    _mock_whoami(monkeypatch, account_id=7, permissions={"other": ["read"]})
    baseline = _branch_list(repo)
    tmp_baseline = _tmp_proposal_dirs()
    for name, call in _WRITE_CALLS.items():
        with pytest.raises(IdentityError) as exc_info:
            call(repo)
        assert exc_info.value.reason == "permission_denied", name
    _assert_zero_side_effect(repo, baseline, tmp_baseline)


def test_write_tools_reject_when_sanic_unreachable(repo, token_env, monkeypatch):
    """情形 7：Sanic 不可达（真实连接失败）→ identity_unavailable，零副作用，不重试。"""
    monkeypatch.setenv(API_URL_ENV, "http://127.0.0.1:1")
    baseline = _branch_list(repo)
    tmp_baseline = _tmp_proposal_dirs()
    for name, call in _WRITE_CALLS.items():
        with pytest.raises(IdentityError) as exc_info:
            call(repo)
        assert exc_info.value.reason == "identity_unavailable", name
    _assert_zero_side_effect(repo, baseline, tmp_baseline)


# ---------------------------------------------------------------------------
# MCP 侧：放行路径与审计
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "permissions,account",
    [
        ({"spec": ["all"]}, 1),  # admin 形态
        ({"spec": ["write"]}, 7),  # 显式授予的普通角色
    ],
)
def test_write_tools_allow_with_spec_write(repo, token_env, monkeypatch, permissions, account):
    """有效 token 且有 spec:write → 正常产出提案分支。"""
    _mock_whoami(monkeypatch, account_id=account, permissions=permissions)
    result = propose_spec_change("demo", DEMO_SPEC, repo_root=repo)
    assert result["branch"].startswith("proposal/")
    assert result["commit"]
    branches = _branch_list(repo)
    assert result["branch"] in branches


def test_audit_records_account_and_never_token(repo, token_env, monkeypatch, capsys):
    """审计含账户标识；成功与失败的审计输出都**不含** token 子串。"""
    _mock_whoami(monkeypatch, account_id=7, permissions={"spec": ["write"]})
    propose_spec_change("demo", DEMO_SPEC, repo_root=repo)

    # 失败路径：无权限（token 在 env 里，若泄露进审计即会被抓到）
    _mock_whoami(monkeypatch, account_id=7, permissions={})
    with pytest.raises(IdentityError):
        propose_spec_change("demo", DEMO_SPEC, repo_root=repo)

    err = capsys.readouterr().err
    records = [_json.loads(line) for line in err.splitlines() if line.startswith("{")]
    propose_records = [r for r in records if r.get("operation") == "propose_spec_change"]
    assert len(propose_records) >= 2, f"应有成功与失败两条审计：{propose_records}"
    success = [r for r in propose_records if r["status"] == "success"]
    failure = [r for r in propose_records if r["status"] == "failure"]
    assert success and failure
    # _audit 的 detail 是**展开**进记录的（不是嵌套 detail 键）
    assert success[0].get("account_id") == 7
    assert failure[0].get("reason") == "permission_denied"
    assert SECRET_TOKEN not in err, "token 绝不允许出现在任何审计输出里"


def test_reject_audit_records_reason(repo, monkeypatch, capsys):
    """拒绝路径的审计有细分 reason（identity_not_configured），且无 token 可泄露。"""
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    with pytest.raises(IdentityError):
        propose_spec_change("demo", DEMO_SPEC, repo_root=repo)
    err = capsys.readouterr().err
    records = [_json.loads(line) for line in err.splitlines() if line.startswith("{")]
    failure = [r for r in records if r.get("operation") == "propose_spec_change" and r["status"] == "failure"]
    assert failure and failure[0].get("reason") == "identity_not_configured"


# ---------------------------------------------------------------------------
# 审核整改（ChangesRequested 2026-10-24）：URL/传输安全面 + 回归 + 正例
# ---------------------------------------------------------------------------


def test_guard_rejects_userinfo_url():
    """``http://127.0.0.1@evil.com`` 的真实 host 是 evil.com——任何 userinfo 一律拒绝。"""
    with pytest.raises(IdentityError):
        _guard_api_url("http://127.0.0.1@evil.com")
    with pytest.raises(IdentityError):
        _guard_api_url("http://user:pass@127.0.0.1:22222")


def test_guard_rejects_suffix_domain():
    """``127.0.0.1.evil.com`` 不是回环——后缀域名不得命中回环白名单（精确匹配）。"""
    with pytest.raises(IdentityError):
        _guard_api_url("http://127.0.0.1.evil.com:22222")


def test_guard_requires_explicit_opt_in_and_https_for_remote(monkeypatch):
    """非回环：默认拒绝；ALLOW_REMOTE=1 后仅 https 放行；回环不受开关影响。"""
    monkeypatch.delenv(ALLOW_REMOTE_ENV, raising=False)
    with pytest.raises(IdentityError):
        _guard_api_url("http://evil.com")
    with pytest.raises(IdentityError):
        _guard_api_url("https://evil.com")
    monkeypatch.setenv(ALLOW_REMOTE_ENV, "1")
    with pytest.raises(IdentityError):
        _guard_api_url("http://evil.com")  # 开了开关但明文 http，仍拒
    assert _guard_api_url("https://evil.com") == "https://evil.com"
    for loopback in ("http://127.0.0.1:22222", "http://localhost:22222", "http://[::1]:22222"):
        assert _guard_api_url(loopback)


@pytest.fixture()
def fake_services():
    """
    回环三服务：``A``＝正常 whoami（200）；``B``＝记录 Authorization 的黑洞；
    ``C``＝302 跳向 B。用于重定向与代理两条外泄面的测试。
    """
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    received_b = []
    holder = {}

    class _A(BaseHTTPRequestHandler):
        def do_GET(self):
            body = _json.dumps({"account_id": 1, "permissions": {"spec": ["all"]}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    class _Recorder(BaseHTTPRequestHandler):
        def do_GET(self):
            received_b.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    class _Redirect(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{holder['b']}/steal")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    sa = ThreadingHTTPServer(("127.0.0.1", 0), _A)
    sb = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    sc = ThreadingHTTPServer(("127.0.0.1", 0), _Redirect)
    holder["b"] = sb.server_address[1]
    for s in (sa, sb, sc):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    yield {
        "a": f"http://127.0.0.1:{sa.server_address[1]}",
        "b": sb.server_address[1],
        "c": f"http://127.0.0.1:{sc.server_address[1]}",
        "received_b": received_b,
    }
    for s in (sa, sb, sc):
        s.shutdown()
        s.server_close()


def test_whoami_redirect_is_not_followed(fake_services, token_env):
    """302 → 禁止跟随：拒绝且跳转目标端口收不到任何请求（Authorization 未外带）。"""
    with pytest.raises(IdentityError) as exc_info:
        fetch_whoami(SECRET_TOKEN, fake_services["c"])
    assert exc_info.value.reason == "identity_unavailable"
    assert fake_services["received_b"] == [], "重定向目标不应收到任何请求"


def test_whoami_never_goes_through_proxy(fake_services, token_env, monkeypatch):
    """设置 HTTP(S)_PROXY 后 token 仍不经过代理（ProxyHandler({}) 强制直连）。"""
    # 先清空环境里既有的代理与绕过名单（本机可能自带 http_proxy 与含回环的
    # no_proxy），保证「若实现不禁代理，请求必走代理」——单因素证明防护有效
    for _var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "no_proxy", "NO_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.delenv(_var, raising=False)
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{fake_services['b']}")
    monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{fake_services['b']}")
    body = fetch_whoami(SECRET_TOKEN, fake_services["a"])
    assert body["account_id"] == 1, "应直连命中真实 whoami 服务"
    assert fake_services["received_b"] == [], "token 不允许经过代理"


def test_redact_strips_token(monkeypatch):
    """``_redact`` 出口兜底抹除 token 值（审核低项 4：补实现）。"""
    from tools.mcp_server import _redact

    monkeypatch.setenv(TOKEN_ENV, "leaky-token-abc")
    out = _redact("unexpected error mentions leaky-token-abc from a third-party lib")
    assert "leaky-token-abc" not in out
    # 无 token 配置时不影响正常文本
    monkeypatch.delenv(TOKEN_ENV)
    assert _redact("plain text") == "plain text"


def test_full_permission_role_without_spec_stays_protected():
    """
    回归（审核中项 2）：存量自建的全权限角色没有 ``spec`` 键，仍必须判为
    「授予全部权限」→ 受保护管理员。破坏实验：去掉 ``_core_resources`` 的
    spec 排除 → 本用例变红（原始 FAILED 行见交付回报）。
    """
    from app.api.resources.role import _role_grants_all_permissions
    from app.auth.permissions import all_resources
    from app.models import Role

    perms = {r: ["all"] for r in all_resources() if r != "spec"}
    role = Role(name="legacy-full-admin", permissions=perms)
    assert _role_grants_all_permissions(role) is True


def test_core_resources_exclude_spec_and_generated():
    """比较集不含 spec（静态 MCP 权限点）与任何生成资源。"""
    from app.api.resources.role import _core_resources
    from app.generated.permissions import GENERATED_PERMISSIONS

    core = set(_core_resources())
    assert "spec" not in core
    assert not (core & set(GENERATED_PERMISSIONS))


def test_list_and_discard_allowed_with_spec_write(repo, token_env, monkeypatch):
    """正例（审核测试空转 3）：list / discard 在有权限时正常工作。"""
    _mock_whoami(monkeypatch, account_id=7, permissions={"spec": ["write"]})
    assert list_proposals(repo_root=repo) == []
    result = propose_spec_change("demo", DEMO_SPEC, repo_root=repo)
    items = list_proposals(repo_root=repo)
    assert [i["branch"] for i in items] == [result["branch"]]
    # 提案分支相对 master 必有未合并 commit，删除需显式 force（git_isolation 契约）
    out = discard_proposal_tool(result["branch"], repo_root=repo, force=True)
    assert out["discarded"] == result["branch"]
    assert list_proposals(repo_root=repo) == []


def test_discard_rejection_keeps_existing_proposal(repo, token_env, monkeypatch):
    """
    空转修复（审核测试空转 1）：discard 的拒绝用例先建**真实**提案分支，
    断言拒绝后分支还在、临时目录无残留。
    """
    _mock_whoami(monkeypatch, account_id=7, permissions={"spec": ["write"]})
    result = propose_spec_change("demo", DEMO_SPEC, repo_root=repo)
    # 切到无权限场景再尝试删除
    _mock_whoami(monkeypatch, account_id=7, permissions={})
    baseline = _branch_list(repo)
    tmp_baseline = _tmp_proposal_dirs()
    with pytest.raises(IdentityError):
        discard_proposal_tool(result["branch"], repo_root=repo)
    _assert_zero_side_effect(repo, baseline, tmp_baseline)
    assert result["branch"] in _branch_list(repo), "被拒绝的 discard 不得删除既有提案分支"
