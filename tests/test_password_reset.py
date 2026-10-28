# -*- coding: utf-8 -*-
"""
密码重置（AUTH-03）的四条核心测试。

对应 CPL 给定的完成定义：

1. 存在邮箱 → 发得出（消息被投递，收件人正确，正文含 token）
2. 不存在邮箱 → 也返回 200，且**不创建 token**
3. token 过期 → 被拒
4. token 用后 → 不能复用

## 关于「永远返回 200」的边界

本测试只断言**响应层**不可区分（状态码、响应体逐字相同）。**时间侧信道不被消除**：
邮箱存在时多做「生成 token + 投递」两件事，耗时必然更长。这是 `request_password_reset()`
docstring 里明确声明的取舍——要彻底消除它，未命中分支也得做等量工作（例如生成了
token 再丢弃并投递到一个黑洞地址），那会让公开端点每次都产生投递副作用。

**因此下面 `test_request_nonexistent_email_returns_same_response` 只比较响应，不比较耗时。**
假装测了时序、实际测不准，比不测更糟。
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.models import Account, VerificationToken
from app.services import delivery

#: 符合强度要求的新口令（≥8 字符、≥2 类字符）
NEW_PASSWORD = "ResetPass456!"


@pytest.fixture()
def captured(monkeypatch):
    """
    替换投递后端为「记录到列表」的实现，不产生任何真实投递。

    用真实 `Backend` 子类而不是 mock —— 这样 `set_backend()` 的类型检查也
    被覆盖到（它要求 isinstance(Backend)）。
    """
    sent: list[dict] = []

    class _Capture(delivery.Backend):
        async def send(self, to: str, subject: str, body: str) -> None:
            sent.append({"to": to, "subject": subject, "body": body})

    delivery.reset_backend()
    delivery.set_backend(_Capture())
    yield sent
    delivery.reset_backend()


async def _admin_email() -> str:
    account = await Account.filter(is_admin=True).first()
    assert account is not None
    return account.email


# ---------------------------------------------------------------------------
# 情形 1：存在邮箱 → 发得出
# ---------------------------------------------------------------------------


async def test_request_existing_email_delivers_token(client, captured):
    email = await _admin_email()
    response = await client.post("/auth/password-reset/request", json={"email": email})

    assert response.status_code == 200
    assert len(captured) == 1, f"应投递一条消息，实际 {len(captured)}"
    message = captured[0]
    assert message["to"] == email

    # 正文里必须含一个真实的、能完成重置的令牌。
    # 库里存的是 sha256 哈希（见 _hash_reset_token），所以断言「正文中的串
    # 哈希后等于库里的值」——这同时验证了「存的是哈希」与「发出去的是原文」。
    import hashlib
    import re

    token_row = await VerificationToken.filter(account__email=email, token_type="password_reset", used=False).first()
    assert token_row is not None, "投递了消息但没有对应的令牌"

    match = re.search(r"令牌是：([A-Za-z0-9_-]+)", message["body"])
    assert match, f"正文里找不到令牌：{message['body']!r}"
    raw_in_body = match.group(1)
    assert hashlib.sha256(raw_in_body.encode()).hexdigest() == token_row.token, (
        "正文中的令牌哈希后与库里的值不一致——要么发出去的不是这句，要么库里存的不是它的哈希"
    )
    assert raw_in_body != token_row.token, "库里的 token 字段不应等于明文（应存哈希）"


# ---------------------------------------------------------------------------
# 情形 2：不存在邮箱 → 200 且不创建 token
# ---------------------------------------------------------------------------


async def test_request_nonexistent_email_returns_same_response(client, captured):
    existing = await _admin_email()

    # 先取「存在」分支的响应，作为逐字比较的基线
    response_hit = await client.post("/auth/password-reset/request", json={"email": existing})
    before_count = len(captured)

    ghost = "definitely-not-registered@example.invalid"
    response_miss = await client.post("/auth/password-reset/request", json={"email": ghost})

    # 状态码与响应体必须完全一致
    assert response_miss.status_code == response_hit.status_code == 200
    assert response_miss.json() == response_hit.json(), "两种邮箱的响应体不同，构成账户枚举侧信道"

    # 不存在的邮箱：不投递、不建 token
    assert len(captured) == before_count, "不存在的邮箱不应产生投递"
    assert not await VerificationToken.filter(account__email=ghost, token_type="password_reset").exists(), (
        "不存在的邮箱不应创建令牌"
    )


# ---------------------------------------------------------------------------
# 情形 3：token 过期被拒
# ---------------------------------------------------------------------------


async def test_confirm_rejects_expired_token(client, captured):
    email = await _admin_email()
    await client.post("/auth/password-reset/request", json={"email": email})

    import re

    token_row = await VerificationToken.filter(account__email=email, token_type="password_reset", used=False).first()
    assert token_row is not None

    # 把过期时间推到过去
    token_row.expires_at = token_row.expires_at - timedelta(days=1)
    await token_row.save(update_fields=["expires_at"])

    match = re.search(r"令牌是：([A-Za-z0-9_-]+)", captured[-1]["body"])
    assert match
    response = await client.post(
        "/auth/password-reset/confirm",
        json={"token": match.group(1), "new_password": NEW_PASSWORD},
    )
    assert response.status_code == 400, (response.status_code, response.text[:300])
    assert response.json()["error"] == "TOKEN_EXPIRED", response.json()

    # 过期令牌在 validate_token 里会被删除；无论如何不能改成新口令
    account = await Account.filter(email=email).first()
    assert not account.verify_password(NEW_PASSWORD), "过期令牌不应改掉口令"


# ---------------------------------------------------------------------------
# 情形 4：用后不能复用
# ---------------------------------------------------------------------------


async def test_confirm_token_is_single_use(client, captured):
    email = await _admin_email()
    await client.post("/auth/password-reset/request", json={"email": email})

    import re

    token_row = await VerificationToken.filter(account__email=email, token_type="password_reset", used=False).first()
    assert token_row is not None
    # 库里存哈希，真正可用于请求的是投递正文里的原文
    match = re.search(r"令牌是：([A-Za-z0-9_-]+)", captured[-1]["body"])
    assert match, "投递正文里没有令牌"
    token_value = match.group(1)

    # 库里存的是 sha256 哈希（见 verification._hash_reset_token），
    # 拿明文 token_value 去查 token 列**永远查不到**，断言会恒为真、零覆盖。
    # 必须先把明文哈希成与库中相同的形态再查。
    import hashlib

    hashed = hashlib.sha256(token_value.encode("utf-8")).hexdigest()

    # 正向对照（用前）：按哈希必须能查到未使用的这一行。
    # 若这里查不到，说明下面的「用后查不到」毫无判别力，测试应立刻失败。
    assert await VerificationToken.filter(token=hashed, used=False).exists(), (
        "正向对照失败：用前按哈希查不到令牌，后续断言没有判别力"
    )

    first = await client.post(
        "/auth/password-reset/confirm",
        json={"token": token_value, "new_password": NEW_PASSWORD},
    )
    assert first.status_code == 200, f"首次使用应成功：{first.text}"

    # 令牌应已从库里删除（reset_password 成功路径确实 verification_token.delete()）
    assert not await VerificationToken.filter(token=hashed).exists(), "用后应即焚，令牌仍存在"

    second = await client.post(
        "/auth/password-reset/confirm",
        json={"token": token_value, "new_password": "AnotherPass789!"},
    )
    assert second.status_code == 400, (second.status_code, second.text[:300])
    assert second.json()["error"] == "TOKEN_INVALID", second.json()

    # 第二次不应改掉口令（第一次设的那个仍然有效）
    account = await Account.filter(email=email).first()
    assert account.verify_password(NEW_PASSWORD), "第二次请求不应覆盖已重置的口令"


# ---------------------------------------------------------------------------
# 补充：同账户旧 token 在再次申请时作废
# ---------------------------------------------------------------------------


async def test_new_request_invalidates_previous_token(client, captured):
    email = await _admin_email()
    await client.post("/auth/password-reset/request", json={"email": email})
    import re

    first = await VerificationToken.filter(account__email=email, token_type="password_reset", used=False).first()
    assert first is not None
    first_raw = re.search(r"令牌是：([A-Za-z0-9_-]+)", captured[-1]["body"]).group(1)

    await client.post("/auth/password-reset/request", json={"email": email})
    first_after = await VerificationToken.filter(id=first.id).first()
    # 实现里把旧 token 标记为 used=True（而不是删除），二者都算「不可再用」
    assert first_after is None or first_after.used, "旧令牌应失效"

    response = await client.post(
        "/auth/password-reset/confirm",
        json={"token": first_raw, "new_password": NEW_PASSWORD},
    )
    assert response.status_code == 400, (response.status_code, response.text[:300])
    assert response.json()["error"] == "TOKEN_INVALID", response.json()


# ---------------------------------------------------------------------------
# 补充：投递后端单元测试（DeliveryBackend 抽象本身）
# ---------------------------------------------------------------------------


def test_logging_backend_does_not_leak_body(caplog):
    """
    `LoggingBackend` 只记收件人与正文长度，**不记正文**。

    正文含一次性 token——把 token 打进日志等于把它写到一个长期留存、
    可能被采集的地方。
    """
    import asyncio
    import logging

    backend = delivery.LoggingBackend()
    secret_body = "令牌是 SUPER-SECRET-TOKEN-12345"
    with caplog.at_level(logging.INFO, logger="app.services.delivery"):
        asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
            backend.send(to="u@example.invalid", subject="重置", body=secret_body)
        )
    text = caplog.text
    assert "u@example.invalid" in text, "应记录收件人（便于运维确认投递发生）"
    assert "SUPER-SECRET-TOKEN-12345" not in text, "正文（含 token）绝不能进日志"


def test_set_backend_rejects_non_backend():
    """`set_backend()` 只接受 Backend 实例——防止误传函数或字符串。"""
    with pytest.raises(TypeError):
        delivery.set_backend(lambda *a, **k: None)  # type: ignore[arg-type]


async def test_deliver_never_raises():
    """投递后端抛异常时，`deliver()` 返回 False 而不是把异常抛给调用方。"""

    class _Broken(delivery.Backend):
        async def send(self, to: str, subject: str, body: str) -> None:
            raise RuntimeError("smtp 挂了")

    delivery.reset_backend()
    delivery.set_backend(_Broken())
    try:
        ok = await delivery.deliver(to="u@example.invalid", subject="s", body="b")
        assert ok is False
    finally:
        delivery.reset_backend()


# ---------------------------------------------------------------------------
# 复审整改（ChangesRequested）的针对性验证
# ---------------------------------------------------------------------------


async def test_token_stored_as_hash_not_plaintext(client, captured):
    """
    [中] 令牌在库里必须是 sha256 哈希，不是明文。

    破坏实验：把 `_hash_reset_token` 改成恒等函数（返回原文），本测试必须红。
    """
    import hashlib

    email = await _admin_email()
    await client.post("/auth/password-reset/request", json={"email": email})

    row = await VerificationToken.filter(account__email=email, token_type="password_reset").first()
    assert row is not None
    # 明文 token_urlsafe(32) 长度约 43；sha256 hex 是 64 位
    assert len(row.token) == 64 and all(c in "0123456789abcdef" for c in row.token), f"库里存的不是 sha256 hex：{row.token!r}"
    # 且确实等于正文中原文的哈希
    import re

    raw = re.search(r"令牌是：([A-Za-z0-9_-]+)", captured[-1]["body"]).group(1)
    assert row.token == hashlib.sha256(raw.encode()).hexdigest()


async def test_old_token_invalidated_before_new_one_created(client, captured, monkeypatch):
    """
    [低2] 旧令牌必须先作废，再建新令牌。

    **为什么不能只断言终态**：只数「最终 used=False 的条数 == 1」，无法区分
    「先作废再建新」与「先建新再作废（作废时排除新建的那条）」——两种实现
    的终态都是 1。顺序本身才是要验证的性质，必须直接观测调用顺序。

    做法：在 `VerificationToken` 的 `create` 与 `QuerySet.update(used=True)`
    上各包一层，按实际发生顺序记录，断言「作废」先于「建新」。

    破坏实验：把 `request_password_reset()` 里「先作废旧」与「再建新」两段
    对调，本测试必须红（记录顺序变成 create → update）。
    """
    from tortoise.queryset import QuerySet

    order: list[str] = []
    orig_update = QuerySet.update
    orig_create = VerificationToken.create

    def spy_update(self, **kwargs):
        # 只关心「把 password_reset 令牌标记为已使用」这一种写
        if self.model is VerificationToken and kwargs.get("used") is True:
            order.append("update")
        return orig_update(self, **kwargs)

    async def spy_create(*args, **kwargs):
        if kwargs.get("token_type") == "password_reset":
            order.append("create")
        return await orig_create(*args, **kwargs)

    monkeypatch.setattr(QuerySet, "update", spy_update)
    monkeypatch.setattr(VerificationToken, "create", spy_create)

    email = await _admin_email()
    # 第一次申请：库里还没有旧令牌，只建一条
    await client.post("/auth/password-reset/request", json={"email": email})
    assert "create" in order, "第一次申请应创建令牌"

    # 第二次申请：此时库里已有一条有效令牌，应「先作废它、再建新的」
    order.clear()
    await client.post("/auth/password-reset/request", json={"email": email})

    assert "update" in order, f"再次申请应先作废旧令牌，实际调用顺序 {order}"
    assert "create" in order, f"再次申请应创建新令牌，实际调用顺序 {order}"
    assert order.index("update") < order.index("create"), (
        f"顺序错误：必须先作废旧令牌再建新令牌，实际 {order}"
    )

    # 终态检查作为次要断言（保留，但它无法单独区分顺序）
    active = await VerificationToken.filter(account__email=email, token_type="password_reset", used=False).count()
    assert active == 1, f"两次申请后应只剩 1 个有效令牌，实际 {active}"


async def test_confirm_consumes_token_atomically(client, captured):
    """
    [低1] 单次有效是原子认领：连续两次 confirm，第二次必须失败。

    这不是真正的并发测试（无法在 pytest 里稳定编排两个并发事务），
    但能验证「第一次已把 used 置位」这个前提——真正的竞态防护由
    `UPDATE ... WHERE used=False` 的影响行数保证（见 validate_token 的注释）。
    """
    email = await _admin_email()
    await client.post("/auth/password-reset/request", json={"email": email})

    import re

    raw = re.search(r"令牌是：([A-Za-z0-9_-]+)", captured[-1]["body"]).group(1)

    first = await client.post("/auth/password-reset/confirm", json={"token": raw, "new_password": NEW_PASSWORD})
    assert first.status_code == 200

    second = await client.post(
        "/auth/password-reset/confirm",
        json={"token": raw, "new_password": "SecondPass789!"},
    )
    assert second.status_code == 400, (second.status_code, second.text[:300])
    assert second.json()["error"] == "TOKEN_INVALID", second.json()


async def test_reset_rate_limit_key_is_independent_from_login(client):
    """
    [低4] 重置限流用独立键，不与登录的 (email, IP) 共用。

    验证方式：连续多次重置请求后，同一账户仍能正常登录。
    若共用键，这里会因登录被锁而失败。
    """
    from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD

    email = await _admin_email()
    for _ in range(6):
        await client.post("/auth/password-reset/request", json={"email": email})

    login = await client.post("/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert login.status_code == 200, f"多次重置请求后登录被锁：{login.status_code} {login.text}"


async def test_reset_rate_limit_blocks_after_limit(client, app):
    """
    AUTH-14 正向对照：重置限流**确实在工作**。

    逐次发起重置请求，直到被拒；断言**拦截发生在准确的边界**——
    第 ``limit + 1`` 次（``limit`` 取应用配置 ``LOGIN_RATELIMIT_MAX_ATTEMPTS``）。
    判定为 ``len(recent) >= limit`` 且判定时不含本次请求，故前 ``limit`` 次
    放行、第 ``limit + 1`` 次被拦。

    为什么需要这条：``test_reset_rate_limit_key_is_independent_from_login``
    只断言「重置不会误伤登录」—— 把 ``_enforce_reset_rate_limit`` 改成 no-op，
    那条测试照样绿。**它证明的是「不误伤」，不是「在工作」。**

    本条与上条构成一对：
    - 上条：重置限流不污染登录计数（隔离性）
    - 本条：重置限流本身会拦（有效性）

    不硬编码上限：``limit`` 从 app 配置读取（``LoginRateLimiter.from_request``
    读的就是 ``request.app.config["LOGIN_RATELIMIT_MAX_ATTEMPTS"]``）。
    断言精确边界还顺带锁住了「判据是 ``>=`` 而非 ``>``」。
    """
    limit = int(app.config["LOGIN_RATELIMIT_MAX_ATTEMPTS"])
    assert limit >= 1, f"配置的限流上限不合理：{limit}"

    email = await _admin_email()
    blocked_at = None
    # 余量给足：若限流是 no-op，循环跑完也不会出现 429。
    for attempt in range(1, limit + 10):
        response = await client.post("/auth/password-reset/request", json={"email": email})
        if response.status_code == 429:
            blocked_at = attempt
            assert response.json()["error"] == "RATE_LIMIT_EXCEEDED", response.json()
            break
        assert response.status_code == 200, (
            f"第 {attempt} 次不应被拒（上限 {limit}）：{response.status_code} {response.text[:200]}"
        )

    assert blocked_at is not None, (
        f"连续 {limit + 9} 次重置请求都没被限流 —— 限流未生效"
    )
    assert blocked_at == limit + 1, (
        f"应在第 {limit + 1} 次开始拦截，实际第 {blocked_at} 次"
    )


async def test_weak_password_does_not_burn_token(client, captured):
    """
    [中] 口令不达标时**不得消耗令牌**：用户换一个合规口令，同一个令牌仍可重试。

    破坏实验：把 `reset_password()` 里的 `set_password()`（口令校验）挪回
    `validate_token(..., consume=True)` 之后，本测试必须红——令牌会被标记
    used，第二次用同一令牌将得到 400。

    两层断言：
    1. 直接调 `reset_password()`，弱口令抛 `ValidationError`；
    2. 再通过 HTTP 用**同一个令牌**提交合规口令，必须 200，且新口令生效。
    """
    import re

    from app.auth.verification import reset_password
    from app.services.exceptions import ValidationError

    email = await _admin_email()
    await client.post("/auth/password-reset/request", json={"email": email})
    raw = re.search(r"令牌是：([A-Za-z0-9_-]+)", captured[-1]["body"]).group(1)

    # "short" —— 长度不足（MIN_PASSWORD_LENGTH=8），确定被 set_password 拒绝
    with pytest.raises(ValidationError):
        await reset_password(raw, "short")

    # 令牌必须仍然未被消耗
    row = await VerificationToken.filter(account__email=email, token_type="password_reset", used=False).first()
    assert row is not None, "弱口令失败后令牌不应被认领"

    # 同一个令牌仍可用于一次成功的重置
    ok = await client.post("/auth/password-reset/confirm", json={"token": raw, "new_password": NEW_PASSWORD})
    assert ok.status_code == 200, f"弱口令失败后同一令牌应仍可用：{ok.status_code} {ok.text}"

    account = await Account.filter(email=email).first()
    assert account.verify_password(NEW_PASSWORD), "新口令应已生效"


# ---------------------------------------------------------------------------
# AUTH-13：投递后端未配置时的静默回退
# ---------------------------------------------------------------------------
#
# 问题机制（与「后端抛异常」不同）：
#   未 `set_backend()` → `get_backend()` 惰性造 `LoggingBackend`
#   → 它的 `send()` **正常返回** → `deliver()` 返回 True
#   → 审计记 success → 用户看到「已发送」，而消息从未离开进程。
#
# 所以运行期无法区分「未配置」与「投递成功」，唯一区分点是启动期检查。


@pytest.fixture()
def clean_backend():
    """每个用例从「未配置」状态开始，结束后还原，避免模块级全局变量串味。"""
    delivery.reset_backend()
    yield
    delivery.reset_backend()


class _Real(delivery.Backend):
    """一个「真实投递」替身：不是 LoggingBackend，因此算已配置。"""

    async def send(self, to: str, subject: str, body: str) -> None:
        pass


def _delivery_warnings(caplog) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "app.services.delivery" and r.levelno >= 30
    ]


def test_unconfigured_backend_warns_on_non_production(clean_backend, caplog):
    """
    非生产未配置后端 → **有可见 warning**，且函数返回 False（不实际投递）。

    这是本任务的核心正向对照：以前这里一条日志都没有，所以要断言告警**确实产生**
    并含可检索的关键词，而不是只断言返回值。
    """
    import logging

    with caplog.at_level(logging.WARNING, logger="app.services.delivery"):
        configured = delivery.check_backend_configured(env="development")

    assert configured is False, "未配置后端时不应声称投递可用"
    messages = _delivery_warnings(caplog)
    assert messages, "非生产环境未配置后端时必须有 startup warning，实际一条都没有"
    assert any("LoggingBackend" in m for m in messages), f"告警里应指明退化到了 LoggingBackend：{messages}"


def test_configured_backend_is_silent_and_reports_available(clean_backend, caplog):
    """
    正向对照的另一半：配好真实后端时，**任何环境都不告警**且返回 True。

    没有这一条，「总是返回 False / 总是告警」的退化实现也能让上面的用例通过。
    """
    import logging

    delivery.set_backend(_Real())

    with caplog.at_level(logging.WARNING, logger="app.services.delivery"):
        assert delivery.check_backend_configured(env="development") is True
        assert delivery.check_backend_configured(env="production") is True

    assert _delivery_warnings(caplog) == [], f"已配置后端时不应有任何告警：{_delivery_warnings(caplog)}"


def test_explicit_logging_backend_counts_as_unconfigured(clean_backend, caplog):
    """
    显式 `set_backend(LoggingBackend())` 仍然等于没配——它不投递任何东西。

    若判定用的是「是否调用过 set_backend」，这个用例会红：那种实现会认为
    「配过了」，于是生产照常启动、消息照旧不发。
    """
    import logging

    delivery.set_backend(delivery.LoggingBackend())
    assert delivery.is_backend_configured() is False

    with caplog.at_level(logging.WARNING, logger="app.services.delivery"):
        assert delivery.check_backend_configured(env="development") is False
    assert _delivery_warnings(caplog), "显式设置 LoggingBackend 也应告警"


def test_production_without_backend_refuses_to_start(clean_backend):
    """生产 + 未配置 + 未放行 → 抛 DeliveryNotConfigured，且信息里给出逃生阀名字。"""
    with pytest.raises(delivery.DeliveryNotConfigured) as exc:
        delivery.check_backend_configured(env="production")
    assert "ALLOW_NOOP_DELIVERY" in str(exc.value), (
        f"拒绝启动的信息必须告诉运维怎么显式放行，实际：{exc.value}"
    )


def test_production_allow_noop_delivery_warns_but_passes(clean_backend, caplog):
    """
    生产 + 未配置 + `ALLOW_NOOP_DELIVERY=1` → 不抛，但仍打 warning。

    逃生阀的语义是「本部署确认不依赖投递」，不是「配好了」——所以返回值仍是
    False，运维仍有告警可查。
    """
    import logging

    with caplog.at_level(logging.WARNING, logger="app.services.delivery"):
        configured = delivery.check_backend_configured(env="production", allow_noop=True)

    assert configured is False
    messages = _delivery_warnings(caplog)
    assert any("ALLOW_NOOP_DELIVERY" in m for m in messages), f"放行时仍须告警并点明开关：{messages}"
    assert any("不会送达" in m for m in messages), f"告警应说明消息不会送达：{messages}"


# ---------------------------------------------------------------------------
# AUTH-13：启动流程真的接上了检查（不是只测函数）
# ---------------------------------------------------------------------------


def _production_app(tmp_path, *, allow_noop: bool):
    """
    构造一个 ENV=production 的应用（sqlite 库，不依赖 MySQL/Redis）。

    用 conftest 的 `_build_config` 再覆盖 ENV 与 `ALLOW_NOOP_DELIVERY`：
    **环境判定维度是 `ENV`**（与 `create_app` / `config.get_config` 一致），
    不看 `TESTING`/`DEBUG`——后者是测试便利开关，不该决定生产语义。
    """
    from app import create_app
    from tests.conftest import _build_config, _unregister_previous_apps

    db_path = tmp_path / "prod.sqlite3"
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)

    cfg = _build_config(db_path, upload_dir)
    cfg["ENV"] = "production"
    cfg["ALLOW_NOOP_DELIVERY"] = allow_noop

    _unregister_previous_apps()
    return create_app(cfg)


async def test_startup_refuses_in_production_without_backend(tmp_path, clean_backend):
    """
    端到端：production 应用启动时，`before_server_start` 真的把启动挡下来。

    破坏实验：把 `_register_listeners` 里那段 `check_backend_configured` 删掉，
    本用例必须红（启动静默通过）。只测 `check_backend_configured` 本身做不到
    这一点——函数正确但没人调用，功能等于没做。
    """
    import asyncio

    from tests.conftest import _unregister_previous_apps

    application = _production_app(tmp_path, allow_noop=False)
    application.asgi = True
    try:
        await application._startup()
        with pytest.raises(delivery.DeliveryNotConfigured):
            await application._server_event("init", "before", asyncio.get_running_loop())
    finally:
        _unregister_previous_apps()


async def _run_startup_capturing_delivery(application, caplog) -> list[str]:
    """
    跑一次 `before_server_start`，返回投递模块产生的 WARNING 文本。

    production 启动在投递检查之后还有一道**无关**的门禁（缺 aerich 迁移账本会
    抛 RuntimeError）。本文件只关心投递检查，所以：把 `DeliveryNotConfigured`
    单独放行（由调用方断言「不该出现」），其余异常视为「投递检查已通过」。
    """
    import asyncio
    import logging

    with caplog.at_level(logging.WARNING, logger="app.services.delivery"):
        try:
            await application._server_event("init", "before", asyncio.get_running_loop())
        except delivery.DeliveryNotConfigured:
            raise
        except Exception as exc:  # noqa: BLE001 - 后续门禁（迁移账本等）与本次改动无关
            assert "aerich" in str(exc) or "迁移" in str(exc), (
                f"启动失败的并非投递检查、也不是已知的迁移门禁：{type(exc).__name__}: {exc}"
            )
    return _delivery_warnings(caplog)


async def test_startup_passes_in_production_when_backend_configured(tmp_path, clean_backend, caplog):
    """对照：production + 已配置后端 → 启动不因投递被挡，且不产生任何投递告警。"""
    from tests.conftest import _unregister_previous_apps

    delivery.set_backend(_Real())
    application = _production_app(tmp_path, allow_noop=False)
    application.asgi = True
    try:
        await application._startup()
        assert await _run_startup_capturing_delivery(application, caplog) == []
    finally:
        from tortoise import Tortoise

        await Tortoise.close_connections()
        _unregister_previous_apps()


async def test_startup_warns_in_production_when_noop_allowed(tmp_path, clean_backend, caplog):
    """production + `ALLOW_NOOP_DELIVERY=True` → 启动不被挡，但告警必须出现。"""
    from tests.conftest import _unregister_previous_apps

    application = _production_app(tmp_path, allow_noop=True)
    application.asgi = True
    try:
        await application._startup()
        messages = await _run_startup_capturing_delivery(application, caplog)
        assert any("ALLOW_NOOP_DELIVERY" in m for m in messages), f"放行后仍须告警：{messages}"
    finally:
        from tortoise import Tortoise

        await Tortoise.close_connections()
        _unregister_previous_apps()


async def test_ordinary_startup_warns_but_does_not_block(tmp_path, clean_backend, caplog):
    """
    非生产（testing）走普通启动流程：告警出现，但**启动不被阻断**。

    这条同时回答了两个边界问题：

    1. 测试环境的 `ENV` 是 ``testing``（见 `tests/conftest.py`），所以 fail-fast
       不会生效——否则整个测试套件会集体起不来；
    2. 告警确实由**启动监听器**产生，而不只是 `check_backend_configured()` 能被
       单独调用到。
    """
    from app import create_app
    from tests.conftest import _build_config, _unregister_previous_apps

    db_path = tmp_path / "testing.sqlite3"
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)

    _unregister_previous_apps()
    application = create_app(_build_config(db_path, upload_dir))
    assert application.config.ENV == "testing", (
        f"测试环境应为 testing（fail-fast 不生效），实际 {application.config.ENV!r}"
    )
    application.asgi = True
    try:
        await application._startup()
        messages = await _run_startup_capturing_delivery(application, caplog)
        assert any("LoggingBackend" in m for m in messages), f"非生产启动应告警：{messages}"
    finally:
        from tortoise import Tortoise

        await Tortoise.close_connections()
        _unregister_previous_apps()


async def test_save_failure_rolls_back_token_claim(client, captured, monkeypatch):
    """
    [AUTH-11] 认领令牌与保存口令必须同一事务：save 失败时令牌不得被烧掉。

    故障场景：`validate_token(consume=True)` 已把令牌置为 used，随后
    `account.save()` 因 DB 错误/约束冲突失败。若无事务，令牌已被消耗、口令
    却没改——用户拿着一个作废的令牌，且不能用同一令牌重试。

    断言（四层）：
    1. 异常向上传播（不吞掉，调用方仍能看到失败）；
    2. 令牌回滚到 `used=False`（正向对照：失败前它确实是 False）；
    3. 账户旧口令仍然有效，新口令未落库；
    4. 回滚后同一令牌可原样重试成功，且新口令确实落库生效。

    破坏实验：去掉 `reset_password()` 里的 `in_transaction()`，第 2 条断言变红。
    """
    import re

    from app.auth.verification import reset_password

    email = await _admin_email()
    await client.post("/auth/password-reset/request", json={"email": email})
    raw = re.search(r"令牌是：([A-Za-z0-9_-]+)", captured[-1]["body"]).group(1)

    import hashlib

    hashed = hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # 正向对照：失败之前令牌确实是未使用状态，下面的「回滚后仍为 False」
    # 才有判别力（否则断言恒真）。
    assert await VerificationToken.filter(token=hashed, used=False).exists(), (
        "正向对照失败：发起重置后令牌本应为未使用，后续回滚断言没有判别力"
    )

    # 只让「保存口令」这一步失败，其它 save（如测试夹具的初始化）不受影响。
    orig_save = Account.save

    async def boom_save(self, *args, **kwargs):
        update_fields = kwargs.get("update_fields") or []
        if "password" in update_fields:
            raise RuntimeError("模拟 DB 写入失败")
        return await orig_save(self, *args, **kwargs)

    monkeypatch.setattr(Account, "save", boom_save)

    # ① 异常必须向上传播，不能被静默吞掉。
    with pytest.raises(RuntimeError, match="模拟 DB 写入失败"):
        await reset_password(raw, NEW_PASSWORD)

    monkeypatch.setattr(Account, "save", orig_save)

    # ② 令牌必须回到未认领状态（事务回滚）。
    row = await VerificationToken.filter(token=hashed, used=False).first()
    assert row is not None, "save 失败后令牌仍被标记 used —— 认领与保存未在同一事务里"

    # ③ 旧口令仍然有效、新口令没有落库。
    #
    # 旧口令用环境变量取（conftest.py 在模块级写入 INITIAL_ADMIN_PASSWORD），
    # 不 import `tests.conftest`：某些环境里 site-packages 的 `tests` 是一个
    # 常规包（带 __init__.py），会盖过仓库内无 __init__.py 的 `tests` 命名空间
    # 包，导致 `from tests.conftest import ADMIN_PASSWORD` 取到无关模块。
    import os

    admin_password = os.environ["INITIAL_ADMIN_PASSWORD"]
    account = await Account.filter(email=email).first()
    assert account.verify_password(admin_password), "save 失败后旧口令应仍然有效"
    assert not account.verify_password(NEW_PASSWORD), "save 失败但新口令已落库"

    # 回滚后令牌可原样重试——这是事务保护的实际价值。
    ok = await client.post("/auth/password-reset/confirm", json={"token": raw, "new_password": NEW_PASSWORD})
    assert ok.status_code == 200, f"回滚后同一令牌应仍可完成重置：{ok.status_code} {ok.text}"

    # ④ 重试不只是返回 200：新口令必须真的落库生效（否则「成功」可能是空转）。
    account = await Account.filter(email=email).first()
    assert account.verify_password(NEW_PASSWORD), "回滚后重试返回 200，但新口令未落库生效"


async def test_delete_failure_rolls_back_token_claim(client, captured, monkeypatch):
    """
    [AUTH-11] 事务边界必须覆盖 `verification_token.delete()`：删令牌失败时令牌不得被烧掉。

    故障场景：认领已置 used，口令已在同一事务里保存，随后
    `verification_token.delete()` 失败。若 delete 在事务外，令牌已被消耗、
    口令却已改变，用户拿着一个作废的令牌。

    断言与 save 失败用例同构：异常传播 + 令牌回滚为 used=False +
    旧口令仍有效且新口令未落库。

    破坏实验：把 `verification_token.delete()` 移到 `async with in_transaction()` 之外，
    本测试第 2 条断言变红。
    """
    import hashlib
    import os
    import re

    from app.auth.verification import reset_password

    email = await _admin_email()
    await client.post("/auth/password-reset/request", json={"email": email})
    raw = re.search(r"令牌是：([A-Za-z0-9_-]+)", captured[-1]["body"]).group(1)
    hashed = hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # 正向对照：失败前令牌确实是未使用状态，回滚断言才有判别力。
    assert await VerificationToken.filter(token=hashed, used=False).exists(), (
        "正向对照失败：发起重置后令牌本应为未使用"
    )

    orig_delete = VerificationToken.delete

    async def boom_delete(self, *args, **kwargs):
        raise RuntimeError("模拟 delete 失败")

    monkeypatch.setattr(VerificationToken, "delete", boom_delete)
    try:
        with pytest.raises(RuntimeError, match="模拟 delete 失败"):
            await reset_password(raw, NEW_PASSWORD)
    finally:
        monkeypatch.setattr(VerificationToken, "delete", orig_delete)

    # delete 失败必须整体回滚：认领作废、口令未改。
    row = await VerificationToken.filter(token=hashed, used=False).first()
    assert row is not None, "delete 失败后令牌仍被标记 used —— 事务未覆盖 delete"

    admin_password = os.environ["INITIAL_ADMIN_PASSWORD"]
    account = await Account.filter(email=email).first()
    assert account.verify_password(admin_password), "delete 失败后旧口令应仍然有效"
    assert not account.verify_password(NEW_PASSWORD), "delete 失败但新口令已落库"


async def test_session_disable_failure_rolls_back_token_claim(client, captured, monkeypatch):
    """
    [AUTH-11] 事务边界必须覆盖「作废既有登录会话」这一次写。

    故障场景：认领、存口令、删令牌都成功，最后
    `AuthenticationSession.filter(...).update(disabled=True)` 失败。
    若这一步在事务外，令牌已被消耗、口令已改，而旧会话仍然有效。

    断言：异常传播 + 令牌回滚为 used=False + 新口令未落库。

    破坏实验：把该 update 移到 `async with in_transaction()` 之外，第 2 条断言变红。
    """
    import hashlib
    import os
    import re

    from tortoise.queryset import QuerySet

    from app.auth.verification import reset_password
    from app.models import AuthenticationSession

    email = await _admin_email()
    await client.post("/auth/password-reset/request", json={"email": email})
    raw = re.search(r"令牌是：([A-Za-z0-9_-]+)", captured[-1]["body"]).group(1)
    hashed = hashlib.sha256(raw.encode("utf-8")).hexdigest()

    assert await VerificationToken.filter(token=hashed, used=False).exists(), (
        "正向对照失败：发起重置后令牌本应为未使用"
    )

    orig_update = QuerySet.update

    def boom_update(self, **kwargs):
        # 只让「禁用会话」这一步失败；认领用的
        # VerificationToken...update(used=True) 必须照常执行。
        if self.model is AuthenticationSession and kwargs.get("disabled") is True:
            raise RuntimeError("模拟会话作废失败")
        return orig_update(self, **kwargs)

    monkeypatch.setattr(QuerySet, "update", boom_update)
    try:
        with pytest.raises(RuntimeError, match="模拟会话作废失败"):
            await reset_password(raw, NEW_PASSWORD)
    finally:
        monkeypatch.setattr(QuerySet, "update", orig_update)

    row = await VerificationToken.filter(token=hashed, used=False).first()
    assert row is not None, "会话作废失败后令牌仍被标记 used —— 事务未覆盖该步"

    account = await Account.filter(email=email).first()
    admin_password = os.environ["INITIAL_ADMIN_PASSWORD"]
    assert account.verify_password(admin_password), "会话作废失败后旧口令应仍然有效"
    assert not account.verify_password(NEW_PASSWORD), "会话作废失败但新口令已落库"


# ---------------------------------------------------------------------------
# AUTH-12：弱口令在 HTTP 层必须精确渲染为 400 + VALIDATION_ERROR
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "weak_password",
    [
        "short",  # 5 字符，触发「长度不足」（app/models/account.py set_password）
        "alllowercase",  # 12 字符但只有 1 类字符，触发「至少 2 类字符」
    ],
    ids=["too-short", "single-class"],
)
async def test_confirm_weak_password_returns_400_validation_error(client, captured, weak_password):
    """
    端点 ``POST /auth/password-reset/confirm`` 收到「有效令牌 + 弱口令」时，
    必须是 **400 + error=VALIDATION_ERROR**，而不是 500（未捕获异常）或 400+TOKEN_*。

    为什么必须带正向对照
    --------------------
    ``TokenInvalidError`` / ``TokenExpiredError`` / ``ValidationError`` 三者
    都是 400（app/services/exceptions.py），所以「弱口令 → 400」本身零判别力。
    必须在**同一令牌**上换一个合规口令拿到 200，才能证明 400 来自
    ``set_password()`` 的强度校验。

    为什么不用 auth_headers
    ----------------------
    登录会带 session cookie，而本端点不在 CSRF 豁免前缀里
    （app/middleware/security_middleware.py），请求会被 403 挡在路由前。
    重置的真实场景本来就是未登录。

    破坏实验：把 ``ValidationError.status_code`` 从 400 改成 500
    （app/services/exceptions.py），本用例必须 FAILED（assert 500 == 400）。
    """
    import re

    email = await _admin_email()
    requested = await client.post("/auth/password-reset/request", json={"email": email})
    assert requested.status_code == 200, requested.text
    assert captured, "投递后端没有收到任何消息，无法取令牌"
    match = re.search(r"令牌是：([A-Za-z0-9_-]+)", captured[-1]["body"])
    assert match, f"投递正文里找不到令牌：{captured[-1]['body']!r}"
    raw = match.group(1)

    # ---- 主断言：精确 400 + 精确 error code（不是 >= 400） ----
    weak = await client.post(
        "/auth/password-reset/confirm",
        json={"token": raw, "new_password": weak_password},
    )
    assert weak.status_code == 400, f"弱口令 {weak_password!r} 应得 400，实际 {weak.status_code}: {weak.text[:300]}"
    body = weak.json()
    assert body["error"] == "VALIDATION_ERROR", body
    assert body.get("success") is False, body

    # ---- 正向对照：同一令牌 + 合规口令 → 200，且新口令真的生效 ----
    ok = await client.post(
        "/auth/password-reset/confirm",
        json={"token": raw, "new_password": NEW_PASSWORD},
    )
    assert ok.status_code == 200, (
        f"正向对照失败：同一令牌换合规口令应 200，实际 {ok.status_code}: {ok.text[:300]}"
        f"（若这里不是 200，则上面的 400 不能归因于口令强度校验）"
    )
    account = await Account.filter(email=email).first()
    assert account is not None
    assert account.verify_password(NEW_PASSWORD), "正向对照：合规口令应已落库"


async def test_weak_password_http_does_not_consume_token(client, captured):
    """
    AUTH-12 / T2：弱口令在 **HTTP 层**被拒后，令牌必须仍未认领，
    且可原样再用一次成功（``used`` 不得被烧掉）。

    与既有 ``test_weak_password_does_not_burn_token`` 的区别：那条前半段是
    ``reset_password()`` 直调，绕过了路由与错误渲染。本条全程走 HTTP，
    验证「路由 → 服务」整条链上的顺序性质。

    破坏实验：把 ``verification.py`` 里 ``account.set_password()`` 挪到
    ``validate_token(..., consume=True)`` 之后。此时弱口令 400 仍成立（T1 仍绿），
    但本条的 ``used`` 断言会红 —— 这就是 T2 相对 T1 的独立价值。
    """
    import hashlib
    import re

    email = await _admin_email()
    await client.post("/auth/password-reset/request", json={"email": email})
    assert captured, "投递后端没有收到任何消息，无法取令牌"
    match = re.search(r"令牌是：([A-Za-z0-9_-]+)", captured[-1]["body"])
    assert match, f"投递正文里找不到令牌：{captured[-1]['body']!r}"
    raw = match.group(1)
    hashed = hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # 正向对照（提交前）：令牌确实存在且未认领，否则下面的「仍未认领」恒真、零判别力。
    assert await VerificationToken.filter(token=hashed, used=False).exists(), "正向对照失败：申请重置后令牌本应为未使用"

    weak = await client.post("/auth/password-reset/confirm", json={"token": raw, "new_password": "short"})
    assert weak.status_code == 400, (weak.status_code, weak.text[:300])
    assert weak.json()["error"] == "VALIDATION_ERROR", weak.json()

    # 主断言：令牌未被认领
    row = await VerificationToken.filter(token=hashed, used=False).first()
    assert row is not None, "弱口令被拒后令牌仍被标记 used —— 校验顺序反了（先认领后校验）"

    # 主断言：同一令牌仍可完成一次成功重置
    ok = await client.post("/auth/password-reset/confirm", json={"token": raw, "new_password": NEW_PASSWORD})
    assert ok.status_code == 200, f"弱口令失败后同一令牌应仍可用：{ok.status_code} {ok.text[:300]}"
    account = await Account.filter(email=email).first()
    assert account.verify_password(NEW_PASSWORD), "新口令应已生效"


async def test_weak_password_writes_failure_audit(client, captured):
    """
    AUTH-12 / T3：弱口令被拒必须在 ``OperationLog`` 留痕
    （operation='password_reset_confirm', status='failure'），且 detail 能看出是
    口令校验失败类型。

    **本用例依赖 routes.py 的改动**（把 ValidationError 纳入 except 元组）。

    正向对照：同一操作的 success 分支必须能被数到（下面最后一段），
    否则「failure 恰好 1 条」的计数方式本身不可信。

    破坏实验：把 routes.py 的 ValidationError 从 except 元组里去掉 → 本用例红。
    """
    import re

    from app.models import OperationLog

    async def _rows(status):
        return await OperationLog.filter(operation="password_reset_confirm", status=status).order_by("id").all()

    email = await _admin_email()
    await client.post("/auth/password-reset/request", json={"email": email})
    assert captured, "投递后端没有收到任何消息，无法取令牌"
    match = re.search(r"令牌是：([A-Za-z0-9_-]+)", captured[-1]["body"])
    assert match, f"投递正文里找不到令牌：{captured[-1]['body']!r}"
    raw = match.group(1)

    # 前置状态：request 端点写的是 password_reset_request，不会污染本 filter；仍显式断言一下。
    assert not await _rows("failure"), "前置状态：此时不应已有 confirm 失败审计"

    # 用一个「够长但只有一类字符」的弱口令：走字符类别分支，又便于断言未泄漏原文。
    leak_probe = "leakprobe"
    weak = await client.post("/auth/password-reset/confirm", json={"token": raw, "new_password": leak_probe})
    assert weak.status_code == 400, (weak.status_code, weak.text[:300])
    assert weak.json()["error"] == "VALIDATION_ERROR", weak.json()

    failures = await _rows("failure")
    assert len(failures) == 1, f"弱口令应写 1 条 failure 审计，实际 {len(failures)}"
    row = failures[0]
    assert row.detail and "ValidationError" in row.detail, (
        f"detail 应能看出是口令校验失败（reason 类型），实际 {row.detail!r}"
    )
    assert row.operation_type == "auth", row.operation_type
    assert leak_probe not in f"{row.detail} {row.account_name} {row.user_agent}", "审计里出现了口令原文"

    # ---- 正向对照：同一 operation 的 success 分支确实可被数到 ----
    ok = await client.post("/auth/password-reset/confirm", json={"token": raw, "new_password": NEW_PASSWORD})
    assert ok.status_code == 200, (ok.status_code, ok.text[:300])
    successes = await _rows("success")
    assert len(successes) == 1, (
        f"正向对照失败：成功重置应有 1 条 success 审计，实际 {len(successes)}"
        "（若为 0，上面「failure 恰好 1 条」的计数方式本身不可信）"
    )
    assert successes[0].account_name, "success 审计应带账户名快照（失败分支 account=None，别断言它）"

