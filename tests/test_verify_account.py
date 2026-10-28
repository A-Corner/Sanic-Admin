# -*- coding: utf-8 -*-
"""
``POST /auth/verify`` 的分支覆盖（AUTH-02 后续）。

背景：该端点是 README「Known limitations」里**完整验证路径的唯一入口**，
此前零测试覆盖——既没有测试直接调用 ``verify_account``，也没有测试打这个端点。

被测实现 ``app/auth/verification.py:62-85``：

1. 无会话令牌           → ``SessionNotFoundError("未找到二步验证会话令牌")``
2. 会话未关联账户       → ``SessionNotFoundError("验证会话未关联账户")``
3. 账户已验证           → ``VerificationError("账户已验证")``
4. 验证码错误           → ``TokenInvalidError``（尝试次数用尽则 ``RateLimitExceededError``）
5. 成功                 → ``account.verified = True`` 并禁用会话

状态码与错误码的**契约来源**一律写在各自断言旁（``app/services/exceptions.py``），
测试里写死这些值——它们是对外契约，不是实现细节。
"""

from app.models import Account, TwoStepSession


async def _create_account(*, verified: bool, suffix: str) -> Account:
    """建一个可登录的账户；``verified`` 与唯一标识由用例指定。"""
    account = Account(
        username=f"verify-{suffix}"[:32],
        email=f"verify.{suffix}@example.com",
        verified=verified,
        disabled=False,
    )
    account.set_password("VerifyPass123!")
    await account.save()
    return account


async def _two_step_session_for(account, *, code: str = "ABC123") -> TwoStepSession:
    """为账户建一个两步验证会话，返回带令牌的会话对象。

    直接建会话而不是先打 ``/auth/register``：注册端点默认关闭
    （``ALLOW_SELF_REGISTRATION=False``），而本文件测的是 ``/auth/verify``，
    不该把「注册开关」这个无关变量拖进来。真实注册链路的用例见文件末尾的
    ``test_register_then_verify_then_login_end_to_end``。
    """
    return await TwoStepSession.create(
        ip="127.0.0.1", user_agent="pytest", bearer=account, code=code, expires=None
    )


# ---------------------------------------------------------------- 分支 1


async def test_verify_without_session_token_returns_session_not_found(client):
    """无令牌（body/header/cookie 都没有）→ 401 SESSION_NOT_FOUND。

    走到 ``_decode_two_step_session`` 的 ``if not token`` 分支
    （``app/auth/verification.py:55-56``）。

    状态码/错误码来源：``app/services/exceptions.py:116-119``
    （``SessionNotFoundError`` 继承 ``SessionError`` → ``AuthenticationError``，
    后者的 ``status_code = 401`` 见同文件 :53-57）。
    """
    response = await client.post("/auth/verify", json={"code": "123456"})

    assert response.status_code == 401, response.text
    body = response.json()
    assert body["success"] is False
    assert body["error"] == "SESSION_NOT_FOUND"
    # 错误文案区分「没有令牌」与「没关联账户」，否则 401 无法定位问题
    assert body["message"] == "未找到二步验证会话令牌"


# ---------------------------------------------------------------- 分支 2


async def test_verify_session_without_bearer_returns_session_not_found(client):
    """会话存在但 ``bearer_id`` 为 NULL → 401 SESSION_NOT_FOUND。

    构造方式：``TwoStepSession.bearer`` 在模型上是 ``null=True``
    （``app/models/session.py:75-77``），因此可以直接建一条
    ``bearer=None`` 的会话行。正常路径（注册/登录）总是带 bearer，
    但库层允许空值，这条防御分支就真实可达——不是不可能触发的死代码。

    状态码/错误码来源同分支 1（``exceptions.py:116-119``）。
    """
    session = await TwoStepSession.create(
        ip="127.0.0.1", user_agent="pytest", bearer=None, code="ABC123", expires=None
    )
    assert session.bearer_id is None

    response = await client.post(
        "/auth/verify", json={"two_step_token": session.token(), "code": "ABC123"}
    )

    assert response.status_code == 401, response.text
    body = response.json()
    assert body["error"] == "SESSION_NOT_FOUND"
    # 与分支 1 的文案不同：这里令牌是有效的，缺的是关联账户
    assert body["message"] == "验证会话未关联账户"


# ---------------------------------------------------------------- 分支 3


async def test_verify_already_verified_account_returns_verification_error(client):
    """已 ``verified=True`` 的账户再验证 → 400 VERIFICATION_ERROR。

    状态码/错误码来源：``app/services/exceptions.py:180-184``
    （``VerificationError`` 继承 ``SecurityError``，``status_code = 400``）。
    """
    account = await _create_account(verified=True, suffix="already")
    session = await _two_step_session_for(account)

    response = await client.post(
        "/auth/verify", json={"two_step_token": session.token(), "code": "ABC123"}
    )

    assert response.status_code == 400, response.text
    body = response.json()
    assert body["success"] is False
    assert body["error"] == "VERIFICATION_ERROR"
    assert body["message"] == "账户已验证"


# ---------------------------------------------------------------- 分支 4


async def test_verify_wrong_code_returns_token_invalid_and_keeps_account_unverified(client):
    """验证码错误 → 400 TOKEN_INVALID，且账户**仍未**验证。

    正向对照（证明「未验证不可登录」这个前提真的成立，否则下面
    「账户仍未验证」的断言没有判别力）：
    先打一次登录，必须是 401 ACCOUNT_UNVERIFIED。

    状态码/错误码来源：
    * ``TokenInvalidError`` → ``exceptions.py:187-190``（400 TOKEN_INVALID）
    * ``UnverifiedError`` → ``exceptions.py:104-107``（401 ACCOUNT_UNVERIFIED）
    """
    email, password = "verify.wrongcode@example.com", "VerifyPass123!"
    account = Account(username="verify-wrongcode", email=email, verified=False, disabled=False)
    account.set_password(password)
    await account.save()
    session = await _two_step_session_for(account)

    # 正向对照：验证前该账户登录被拒
    login_before = await client.post("/auth/login", json={"email": email, "password": password})
    assert login_before.status_code == 401, login_before.text
    assert login_before.json()["error"] == "ACCOUNT_UNVERIFIED"

    response = await client.post(
        "/auth/verify", json={"two_step_token": session.token(), "code": "000000"}
    )

    assert response.status_code == 400, response.text
    body = response.json()
    assert body["error"] == "TOKEN_INVALID"
    assert body["message"] == "验证码不正确"

    # 关键：失败的验证绝不能把账户置为已验证
    fresh = await Account.filter(email=email).first()
    assert fresh.verified is False


async def test_verify_exhausts_attempts_returns_rate_limit_and_keeps_account_unverified(client):
    """连续错码达上限后 → 429 RATE_LIMIT_EXCEEDED（``check_code`` 的另一条分支）。

    ``VERIFICATION_MAX_ATTEMPTS = 5``（``app/models/session.py:38``），
    前 5 次错码各自 400，第 6 次在「未达上限则计数加一」的原子更新上失败 → 429。

    状态码/错误码来源：``exceptions.py:247-251``（``RateLimitExceededError``
    继承 ``BaseError``，``status_code = 429``）。
    """
    email, password = "verify.ratelimit@example.com", "VerifyPass123!"
    account = Account(username="verify-ratelimit", email=email, verified=False, disabled=False)
    account.set_password(password)
    await account.save()
    session = await _two_step_session_for(account)
    token = session.token()

    for attempt in range(5):
        wrong = await client.post(
            "/auth/verify", json={"two_step_token": token, "code": "000000"}
        )
        assert wrong.status_code == 400, f"第 {attempt + 1} 次: {wrong.text}"
        assert wrong.json()["error"] == "TOKEN_INVALID"

    blocked = await client.post("/auth/verify", json={"two_step_token": token, "code": "ABC123"})
    assert blocked.status_code == 429, blocked.text
    assert blocked.json()["error"] == "RATE_LIMIT_EXCEEDED"

    # 即使第 6 次给的是正确验证码，也不能验证成功
    still_unverified = await Account.filter(email=email).first()
    assert still_unverified.verified is False


# ---------------------------------------------------------------- 分支 5


async def test_verify_success_sets_verified_and_allows_login(client):
    """正确验证码 → 200 + ``verified=True`` + **真的能登录**（外部效果）。

    ``verified=True`` 只是内部状态；这个端点的目的是让账户可用，所以必须断言
    登录成功。否则「字段改了但登录仍然失败」这种回归测不出来。

    同时断言会话被作废（``verify_account`` 末尾的 ``await session.disable()``）：
    同一令牌再用一次 → 401 SESSION_INVALID（``exceptions.py:122-125``，
    该异常经 ``Session.decode`` → ``Session.validate()`` 抛出）。
    """
    email, password = "verify.success@example.com", "VerifyPass123!"
    account = Account(username="verify-success", email=email, verified=False, disabled=False)
    account.set_password(password)
    await account.save()
    session = await _two_step_session_for(account)
    token = session.token()

    response = await client.post("/auth/verify", json={"two_step_token": token, "code": "ABC123"})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == 0

    # 会话已被禁用：同一令牌不能再用（放在登录之前，避免登录下发的会话 cookie
    # 让后续 POST 触发 CSRF 校验）
    replay = await client.post("/auth/verify", json={"two_step_token": token, "code": "ABC123"})
    assert replay.status_code == 401, replay.text
    assert replay.json()["error"] == "SESSION_INVALID"

    # **先断言外部效果**：能登录才是这个端点的目的。放在内部状态断言之前，
    # 是为了让「字段改了但账户仍不可用」这类回归在登录这一步就暴露。
    login_after = await client.post("/auth/login", json={"email": email, "password": password})
    assert login_after.status_code == 200, login_after.text
    assert login_after.headers.get("authorization", "").startswith("Bearer ")

    # 再断言内部状态
    assert body["data"]["verified"] is True
    fresh = await Account.filter(email=email).first()
    assert fresh.verified is True


# ---------------------------------------------------------------- 端到端


async def test_register_then_verify_then_login_end_to_end(client, app):
    """注册 → 拿响应里的验证码 → 验证 → 登录，走真实生产链路。

    与上面各条的差别：令牌与验证码来自 ``/auth/register`` 的真实响应
    （``app/auth/routes.py:132-140``），而不是测试自己建会话。
    这条用例才是 README「Known limitations」所描述路径的逐字复现。

    ``_delivery_code``（``routes.py:66-72``）只在 ``DEBUG`` 下把验证码放进
    响应体；conftest 的测试配置 ``DEBUG=True``（``tests/conftest.py:133``）。
    """
    app.config["ALLOW_SELF_REGISTRATION"] = True
    email, username, password = "verify.e2e@example.com", "verify-e2e", "VerifyPass123!"

    try:
        registered = await client.post(
            "/auth/register", json={"username": username, "email": email, "password": password}
        )
        assert registered.status_code == 200, registered.text
        code = registered.json()["data"]
        assert code, "DEBUG 下注册响应应带验证码"

        # 令牌经响应头 / Cookie 下发；响应体里也接受 two_step_token 参数，
        # 这里从响应头取，验证的是真实的客户端获取方式。
        two_step_token = registered.headers.get("X-Two-Step-Token")
        assert two_step_token, "注册响应缺少 X-Two-Step-Token 头"

        # 注册出来的账户还不能登录
        login_before = await client.post("/auth/login", json={"email": email, "password": password})
        assert login_before.status_code == 401, login_before.text
        assert login_before.json()["error"] == "ACCOUNT_UNVERIFIED"

        verified = await client.post(
            "/auth/verify", json={"two_step_token": two_step_token, "code": code}
        )
        assert verified.status_code == 200, verified.text
        assert verified.json()["data"]["verified"] is True

        login_after = await client.post("/auth/login", json={"email": email, "password": password})
        assert login_after.status_code == 200, login_after.text
        assert login_after.headers.get("authorization", "").startswith("Bearer ")
    finally:
        app.config["ALLOW_SELF_REGISTRATION"] = False
