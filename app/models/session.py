#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
会话模型模块，包含各种会话类型

会话以 RS256 签名的 JWT 下发给客户端（JWT 只含 session_id 与会话类型），
有效性（是否禁用、过期、二次验证）以服务端会话表为准。
"""
import datetime
import os
import secrets
import jwt
from typing import TYPE_CHECKING, Optional
from sanic.log import logger
from sanic.response import HTTPResponse, raw
from captcha.image import ImageCaptcha
from app.models.base import BaseModel
from tortoise import fields
from tortoise.expressions import F
from app.config import BaseConfig
from app.services.utils import get_ip, get_code, get_expiration_date, utcnow, ensure_aware
from app.services.exceptions import (
    BaseError,
    SessionNotFoundError,
    SessionValidationError,
    SessionExpiredError,
    InvalidTokenError,
    RateLimitExceededError,
    TokenInvalidError,
)

if TYPE_CHECKING:
    from app.models.account import Account

# 验证类会话（验证码、两步验证）的有效期与最大尝试次数
VERIFICATION_SESSION_EXPIRATION = 600  # 10分钟
VERIFICATION_MAX_ATTEMPTS = 5


def _all_session_models(base=None):
    """递归收集 Session 的全部非抽象子类。"""
    base = base or Session
    found = []
    for sub in base.__subclasses__():
        if not sub._meta.abstract:
            found.append(sub)
        found.extend(_all_session_models(sub))
    return found


class Session(BaseModel):
    """
    会话抽象基类，用于客户端标识和验证

    每种会话类型是独立的表；令牌里的 ``session_type`` 用于定位表。

    Attributes:
        ip (str): 会话关联的IP地址
        user_agent (str): 会话关联的用户代理
        expires (datetime): 会话过期时间，为空表示不过期
        disabled (bool): 会话是否被禁用
        bearer (ForeignKeyField): 与会话关联的账户
    """
    # 令牌在 Cookie / 响应头中的名称，子类按类型覆盖，避免互相覆盖
    cookie_name = "session"
    header_name = "Authorization"
    header_prefix = "Bearer "

    ip: str = fields.CharField(max_length=45)
    user_agent: str = fields.CharField(max_length=255, null=True)
    expires: datetime.datetime = fields.DatetimeField(null=True)
    disabled: bool = fields.BooleanField(default=False)
    # related_name=False：各会话子类各有一张表，不在 Account 上生成重名反向关系
    bearer: fields.ForeignKeyRelation["Account"] = fields.ForeignKeyField(
        "models.Account", related_name=False, null=True
    )

    class Meta:
        abstract = True

    @property
    def json(self) -> dict:
        """
        生成会话的JSON表示

        Returns:
            dict: 会话数据的字典表示
        """
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "ip": self.ip,
            "user_agent": self.user_agent,
            "expires": self.expires.isoformat() if self.expires else None,
            "disabled": self.disabled,
            "bearer_id": self.bearer_id,
        }

    @property
    def expired(self) -> bool:
        """
        检查会话是否已过期

        Returns:
            bool: 如果会话已过期，则为True，否则为False
        """
        if not self.expires:
            return False
        return utcnow() > ensure_aware(self.expires)

    def validate(self) -> None:
        """
        验证会话状态

        Raises:
            SessionValidationError: 如果会话已被删除或禁用
            SessionExpiredError: 如果会话已过期
        """
        if self.deleted:
            raise SessionValidationError("会话已被删除")
        elif self.disabled:
            raise SessionValidationError("会话已被禁用")
        elif self.expired:
            raise SessionExpiredError()

    def token(self) -> str:
        """签发该会话的 JWT。"""
        payload = {"session_id": self.id, "session_type": self.__class__.__name__}
        return jwt.encode(
            payload, BaseConfig.SECRET, algorithm=BaseConfig.SESSION_ENCODING_ALGORITHM
        )

    def encode(self, response: HTTPResponse) -> None:
        """
        将会话编码为JWT并设置到响应的Cookie和Header中

        Args:
            response: Sanic响应对象
        """
        token = self.token()

        response.add_cookie(
            self.cookie_name,
            token,
            httponly=True,
            secure=BaseConfig.SESSION_SECURE,
            samesite="Lax",
        )

        # 同时设置响应头以支持API调用
        response.headers[self.header_name] = f"{self.header_prefix}{token}"

    @classmethod
    async def decode(cls, token: str):
        """
        解码JWT并获取对应的会话

        Args:
            token: JWT令牌

        Returns:
            Session: 解码后的会话实例（类型必须与 cls 兼容）

        Raises:
            InvalidTokenError: 如果令牌无效或类型不匹配
            SessionNotFoundError: 如果会话不存在
            SessionValidationError / SessionExpiredError: 会话不可用
        """
        if not token:
            raise InvalidTokenError("缺少令牌")
        try:
            payload = jwt.decode(
                token,
                BaseConfig.PUBLIC_SECRET,
                algorithms=[BaseConfig.SESSION_ENCODING_ALGORITHM],
            )
        except jwt.PyJWTError as e:
            raise InvalidTokenError("无效的令牌") from e

        session_id = payload.get("session_id")
        session_type = payload.get("session_type")
        models = {m.__name__: m for m in _all_session_models()}
        session_model = models.get(session_type)
        if session_model is None or not issubclass(session_model, cls) or session_id is None:
            raise InvalidTokenError("令牌类型不匹配")

        session = await session_model.get_or_none(id=session_id)
        if not session:
            raise SessionNotFoundError("找不到对应的会话")

        session.validate()
        return session

    @classmethod
    async def get_valid_session(cls, token: str) -> Optional["AuthenticationSession"]:
        """
        根据令牌获取有效的认证会话（供认证中间件使用）。

        令牌无效、会话不可用或账户已禁用/删除时返回 None，不抛异常。
        二次验证要求由 ``requires_authentication`` 另行检查。
        """
        try:
            session = await AuthenticationSession.decode(token)
            await session.fetch_related("bearer")
            if session.bearer is None or session.bearer.deleted or session.bearer.disabled:
                return None
            return session
        except BaseError as e:
            logger.debug(f"会话校验未通过: {e.message}")
            return None

    @classmethod
    async def create_from_request(cls, request, bearer=None, expires_in: Optional[int] = None, **kwargs):
        """
        从请求中创建新会话

        Args:
            request: Sanic请求对象
            bearer: 关联的账户
            expires_in: 有效期（秒），为空表示不过期
            **kwargs: 子类字段

        Returns:
            Session: 新创建的会话实例
        """
        return await cls.create(
            ip=get_ip(request)[:45],
            user_agent=(request.headers.get("user-agent") or "")[:255] or None,
            bearer=bearer,
            expires=get_expiration_date(expires_in) if expires_in else None,
            **kwargs,
        )

    async def disable(self):
        """
        禁用会话
        """
        self.disabled = True
        await self.save(update_fields=["disabled"])


class VerificationSession(Session):
    """
    验证会话抽象基类，用于验证码与两步验证

    Attributes:
        code (str): 验证码
        attempts (int): 已尝试次数，超过上限后会话作废
    """
    code: str = fields.CharField(max_length=32)
    attempts: int = fields.IntField(default=0)

    class Meta:
        abstract = True

    @property
    def json(self) -> dict:
        """
        生成验证会话的JSON表示（不含验证码本身）

        Returns:
            dict: 验证会话数据的字典表示
        """
        return super().json

    @classmethod
    async def create_from_request(cls, request, bearer=None, code: Optional[str] = None,
                                  expires_in: int = VERIFICATION_SESSION_EXPIRATION, **kwargs):
        """创建验证会话；未指定验证码时随机生成。"""
        return await super().create_from_request(
            request, bearer=bearer, expires_in=expires_in, code=code or get_code(), **kwargs
        )

    async def check_code(self, submitted) -> None:
        """
        校验提交的验证码（不区分大小写，常数时间比较），限制尝试次数。

        Raises:
            RateLimitExceededError: 尝试次数用尽
            TokenInvalidError: 验证码不正确
        """
        # 原子地"未达上限则计数加一"：并发请求下计数不丢失、也不会超过上限
        updated = await type(self).filter(
            id=self.id, attempts__lt=VERIFICATION_MAX_ATTEMPTS
        ).update(attempts=F("attempts") + 1)
        if not updated:
            # 不禁用会话：达到上限后的所有请求稳定返回 429，会话随有效期自然过期
            raise RateLimitExceededError("验证码尝试次数过多，请重新获取")
        expected = self.code.upper().encode()
        given = str(submitted or "").upper().encode()
        if not secrets.compare_digest(expected, given):
            raise TokenInvalidError("验证码不正确")


class TwoStepSession(VerificationSession):
    """
    两步验证会话模型
    """
    cookie_name = "two_step_session"
    header_name = "X-Two-Step-Token"
    header_prefix = ""

    class Meta:
        table = "two_step_session"


class CaptchaSession(VerificationSession):
    """
    验证码会话模型

    增加了生成验证码图像的功能
    """
    cookie_name = "captcha_session"
    header_name = "X-Captcha-Token"
    header_prefix = ""

    class Meta:
        table = "captcha_session"

    async def generate_image(self):
        """
        生成验证码图像

        Returns:
            HTTPResponse: 包含验证码图像的响应
        """
        font = BaseConfig.CAPTCHA_FONT
        # 配置的字体文件不存在时退回 captcha 库自带字体
        image = ImageCaptcha(fonts=[font] if font and os.path.isfile(font) else None)
        data = image.generate(self.code)
        return raw(data.getvalue(), content_type="image/png")


class AuthenticationSession(Session):
    """
    认证会话模型，用于用户登录

    Attributes:
        requires_second_factor (bool): 是否需要二次验证
        second_factor_verified (bool): 二次验证是否已完成
    """
    requires_second_factor: bool = fields.BooleanField(default=False)
    second_factor_verified: bool = fields.BooleanField(default=False)

    class Meta:
        table = "authentication_session"

    @property
    def json(self) -> dict:
        """
        生成认证会话的JSON表示

        Returns:
            dict: 认证会话数据的字典表示
        """
        result = super().json
        result["requires_second_factor"] = self.requires_second_factor
        result["second_factor_verified"] = self.second_factor_verified
        return result

    @property
    def second_factor_pending(self) -> bool:
        """是否仍待完成二次验证。"""
        return self.requires_second_factor and not self.second_factor_verified

    @classmethod
    async def create_from_request(cls, request, bearer=None, requires_second_factor=False, **kwargs):
        """
        从请求创建认证会话

        Args:
            request: Sanic请求对象
            bearer: 关联的账户
            requires_second_factor: 是否需要二次验证

        Returns:
            AuthenticationSession: 新创建的认证会话
        """
        return await super().create_from_request(
            request,
            bearer=bearer,
            expires_in=BaseConfig.AUTHENTICATION_SESSION_EXPIRATION,
            requires_second_factor=requires_second_factor,
        )

    @classmethod
    async def get_associated(cls, account):
        """
        获取与账户关联的所有认证会话

        Args:
            account: 账户实例

        Returns:
            List[AuthenticationSession]: 与账户关联的认证会话列表
        """
        return await cls.filter(bearer=account, deleted=False, disabled=False).all()
