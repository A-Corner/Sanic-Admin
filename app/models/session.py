#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
会话模型模块，包含各种会话类型
"""
import datetime
import jwt
from io import BytesIO
from sanic.response import HTTPResponse, raw
from captcha.image import ImageCaptcha
from jwt import DecodeError
from app.models.base import BaseModel
from app.models.user import Account
from tortoise import fields
from tortoise.exceptions import DoesNotExist
from app.config import BaseConfig
from app.services.utils import get_ip, get_code, get_expiration_date
from app.services.exceptions import (
    SessionNotFoundError, 
    SessionValidationError,
    SessionExpiredError,
    InvalidTokenError
)


class Session(BaseModel):
    """
    会话基类模型，用于客户端标识和验证
    
    所有会话模型都从此模型派生。
    
    Attributes:
        ip (str): 会话关联的IP地址
        user_agent (str): 会话关联的用户代理
        expires (datetime): 会话过期时间
        disabled (bool): 会话是否被禁用
        bearer (ForeignKeyField): 与会话关联的账户
    """
    ip: str = fields.CharField(max_length=45)
    user_agent: str = fields.CharField(max_length=255, null=True)
    expires: datetime.datetime = fields.DatetimeField(null=True)
    disabled: bool = fields.BooleanField(default=False)
    bearer: fields.ForeignKeyRelation["Account"] = fields.ForeignKeyField(
        "models.Account", related_name="sessions", null=True
    )

    @property
    def json(self) -> dict:
        """
        生成会话的JSON表示
        
        Returns:
            dict: 会话数据的字典表示
        """
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "ip": self.ip,
            "user_agent": self.user_agent,
            "expires": str(self.expires) if self.expires else None,
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
        return datetime.datetime.now() > self.expires

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

    def encode(self, response: HTTPResponse) -> None:
        """
        将会话编码为JWT并设置到响应的Cookie和Header中
        
        Args:
            response: Sanic响应对象
        """
        payload = {"session_id": self.id, "session_type": self.__class__.__name__}
        token = jwt.encode(
            payload, BaseConfig.SECRET, algorithm=BaseConfig.SESSION_ENCODING_ALGORITHM
        )
        
        response.cookies["session"] = token
        response.cookies["session"]["httponly"] = True
        response.cookies["session"]["secure"] = BaseConfig.SESSION_SECURE
        
        # 同时设置Authorization头以支持API调用
        response.headers["Authorization"] = f"Bearer {token}"

    @classmethod
    async def decode(cls, token: str):
        """
        解码JWT并获取对应的会话
        
        Args:
            token: JWT令牌
            
        Returns:
            Session: 解码后的会话实例
            
        Raises:
            InvalidTokenError: 如果令牌无效或会话不存在
        """
        try:
            payload = jwt.decode(
                token, 
                BaseConfig.PUBLIC_SECRET, 
                algorithms=[BaseConfig.SESSION_ENCODING_ALGORITHM]
            )
            
            session_id = payload.get("session_id")
            session_type = payload.get("session_type", cls.__name__)
            
            # 根据会话类型获取对应的模型
            session_model = globals().get(session_type, cls)
            
            session = await session_model.get_or_none(id=session_id)
            if not session:
                raise SessionNotFoundError("找不到对应的会话")
                
            session.validate()
            return session
        except (DecodeError, KeyError) as e:
            raise InvalidTokenError("无效的令牌") from e
        except DoesNotExist as e:
            raise SessionNotFoundError("找不到对应的会话") from e

    @classmethod
    async def create_from_request(cls, request):
        """
        从请求中创建新会话
        
        Args:
            request: Sanic请求对象
            
        Returns:
            Session: 新创建的会话实例
        """
        return await cls.create(
            ip=get_ip(request),
            user_agent=request.headers.get("user-agent"),
        )

    async def disable(self):
        """
        禁用会话
        """
        self.disabled = True
        await self.save(update_fields=["disabled"])


class VerificationSession(Session):
    """
    验证会话模型，用于账户验证过程
    
    Attributes:
        code (str): 验证码
    """
    code: str = fields.CharField(max_length=32)

    @property
    def json(self) -> dict:
        """
        生成验证会话的JSON表示
        
        Returns:
            dict: 验证会话数据的字典表示
        """
        result = super().json
        result["code"] = self.code
        return result


class TwoStepSession(VerificationSession):
    """
    两步验证会话模型
    """
    pass


class CaptchaSession(VerificationSession):
    """
    验证码会话模型
    
    增加了生成验证码图像的功能
    """
    
    async def generate_image(self):
        """
        生成验证码图像
        
        Returns:
            HTTPResponse: 包含验证码图像的响应
        """
        image = ImageCaptcha(fonts=[BaseConfig.CAPTCHA_FONT])
        data = image.generate(self.code)
        
        # 将BytesIO转换为bytes
        img_bytes = BytesIO()
        image.write(self.code, img_bytes)
        img_bytes.seek(0)
        
        return raw(img_bytes.getvalue(), content_type="image/png")


class AuthenticationSession(Session):
    """
    认证会话模型，用于用户登录
    
    Attributes:
        requires_second_factor (bool): 是否需要二次验证
        second_factor_verified (bool): 二次验证是否已完成
    """
    requires_second_factor: bool = fields.BooleanField(default=False)
    second_factor_verified: bool = fields.BooleanField(default=False)

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

    def validate(self) -> None:
        """
        验证认证会话状态
        
        Raises:
            SessionValidationError: 如果会话已被删除、禁用或需要二次验证但未验证
            SessionExpiredError: 如果会话已过期
        """
        super().validate()
        if self.requires_second_factor and not self.second_factor_verified:
            raise SessionValidationError("需要二次验证")

    @classmethod
    async def create_from_request(cls, request, bearer=None, requires_second_factor=False):
        """
        从请求创建认证会话
        
        Args:
            request: Sanic请求对象
            bearer: 关联的账户
            requires_second_factor: 是否需要二次验证
            
        Returns:
            AuthenticationSession: 新创建的认证会话
        """
        expires = get_expiration_date(BaseConfig.AUTHENTICATION_SESSION_EXPIRATION)
        return await cls.create(
            ip=get_ip(request),
            user_agent=request.headers.get("user-agent"),
            bearer=bearer,
            expires=expires,
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