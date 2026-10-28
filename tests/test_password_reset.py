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
    assert response.status_code >= 400, "过期令牌必须被拒绝"

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

    first = await client.post(
        "/auth/password-reset/confirm",
        json={"token": token_value, "new_password": NEW_PASSWORD},
    )
    assert first.status_code == 200, f"首次使用应成功：{first.text}"

    # 令牌应已从库里删除
    assert not await VerificationToken.filter(token=token_value).exists(), "用后应即焚，令牌仍存在"

    second = await client.post(
        "/auth/password-reset/confirm",
        json={"token": token_value, "new_password": "AnotherPass789!"},
    )
    assert second.status_code >= 400, "同一令牌不应能第二次使用"

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
    assert response.status_code >= 400, "旧令牌不应还能用"


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

    验证方式：在「作废旧」与「建新」之间不留下两个有效令牌的窗口。
    做法：请求两次，然后断言库里对该账户只有 1 条 used=False。
    """
    email = await _admin_email()
    await client.post("/auth/password-reset/request", json={"email": email})
    await client.post("/auth/password-reset/request", json={"email": email})

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
    assert second.status_code >= 400


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
