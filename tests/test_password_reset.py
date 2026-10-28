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

    # 正文里必须含一个真实的、库里存在的 password_reset 令牌
    token = await VerificationToken.filter(account__email=email, token_type="password_reset", used=False).first()
    assert token is not None, "投递了消息但没有对应的令牌"
    assert token.token in message["body"], "正文里没有令牌，用户无法完成重置"


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

    token = await VerificationToken.filter(account__email=email, token_type="password_reset", used=False).first()
    assert token is not None

    # 把过期时间推到过去
    token.expires_at = token.expires_at - timedelta(days=1)
    await token.save(update_fields=["expires_at"])

    response = await client.post(
        "/auth/password-reset/confirm",
        json={"token": token.token, "new_password": NEW_PASSWORD},
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

    token = await VerificationToken.filter(account__email=email, token_type="password_reset", used=False).first()
    assert token is not None
    token_value = token.token

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
    first = await VerificationToken.filter(account__email=email, token_type="password_reset", used=False).first()
    assert first is not None

    await client.post("/auth/password-reset/request", json={"email": email})
    first_after = await VerificationToken.filter(id=first.id).first()
    # 实现里把旧 token 标记为 used=True（而不是删除），二者都算「不可再用」
    assert first_after is None or first_after.used, "旧令牌应失效"

    response = await client.post(
        "/auth/password-reset/confirm",
        json={"token": first.token, "new_password": NEW_PASSWORD},
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
