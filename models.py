# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# File       : models.py
# Time       ：10/9/2023 10:03 pm
# Author     ：author A-Corner
# version    ：python 3.11
# Description：
"""
import datetime
import jwt
from io import BytesIO
from typing import Union
from captcha.image import ImageCaptcha
from jwt import DecodeError
from sanic.log import logger
from sanic.request import Request
from sanic.response import HTTPResponse, raw
from typing import Dict, Type
from tortoise import fields
from tortoise.models import Model
from tortoise.exceptions import DoesNotExist
from tortoise.expressions import Q
from configuration import config as security_config
from exceptions import *
from utils import get_ip, get_code, get_expiration_date
from celery import schedules
from celery.beat import ScheduleEntry
# BaseModel是其他模型的基类，包括Account、Session、VerificationSession、TwoStepSession、CaptchaSession、AuthenticationSession、Role。
# 这些模型都继承自BaseModel，并可以使用BaseModel中定义的字段和方法。


class BaseModel(Model):
    """
    BaseModel是引用了sanic security的BaseModel来进行二次修改的。
    这个基类定义了一些共有的字段和方法，所有模型都可以继承它。
    它包括了一些常见的数据库字段，例如id，创建时间，更新时间，删除标记，锁定标记。这些字段用于跟踪数据库中的记录。
    Attributes:
        id (int): 模型的主键。
        date_created (datetime): 记录在数据库中创建的时间。
        date_updated (datetime): 记录在数据库中更新的时间。
        deleted (bool): 记录是否被标记为删除。
    """

    id: int = fields.IntField(pk=True)  # type: ignore
    date_created: datetime.datetime = fields.DatetimeField(
        auto_now_add=True, description="创建时间")
    date_updated: datetime.datetime = fields.DatetimeField(
        auto_now=True, description="更新时间")
    deleted: bool = fields.BooleanField(default=False, description="删除标记")

    def validate(self) -> None:
        """
        这个方法用于验证模型的状态是否合法。子类可以覆盖这个方法来实现特定的验证逻辑。
        Raises:
            SecurityError: 如果验证失败，会引发此异常。
        """
        raise NotImplementedError()

    @property
    def json(self) -> dict:
        """
        生成一个JSON可序列化的字典，用于在HTTP请求或响应中使用。
        Returns:
            dict: 包含模型数据的字典。
        这个方法可以将模型的数据转换为JSON格式，以便在HTTP请求和响应中传递数据。
        """
        raise NotImplementedError()

    class Meta:
        abstract = True  # 代表了这个是抽象类


# Account模型表示用户帐户的信息，包括用户名、电子邮件、密码等等。它还定义了一些方法，例如禁用帐户、获取帐户等等。
class Account(BaseModel):
    """
    包含所有可识别用户信息的模型。
    Attributes:
        username (str): 公共标识符。
        email (str): 私有标识符，可用于验证。
        phone (str): 包含国家代码的手机号，可用于验证。可以为null或空。
        password (str): 用于保护帐户的密码。必须使用Argon2哈希。
        disabled (bool): 使帐户不可用但仍可用。
        verified (bool): 使帐户不可用，直到通过两步验证或其他方法验证。
        roles (ManyToManyRelation[Role]): 与此帐户关联的角色。

    这个模型表示用户的基本信息，包括用户名、电子邮件、电话号码和密码。还可以标记帐户是否已禁用、是否已验证，以及与帐户相关联的角色。
    """

    username: str = fields.CharField(unique=True, max_length=32)
    email: str = fields.CharField(unique=True, max_length=255)
    phone: str = fields.CharField(unique=True, max_length=14, null=True)
    password: str = fields.CharField(max_length=255)
    disabled: bool = fields.BooleanField(default=False)
    verified: bool = fields.BooleanField(default=False)
    roles: fields.ManyToManyRelation["Role"] = fields.ManyToManyField(
        "models.Role", through="account_role"
    )

    @property
    def json(self) -> dict:
        """
        生成一个包含帐户信息的JSON可序列化字典。
        Returns:
            dict: 包含帐户信息的字典。
        """
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "email": self.email,
            "username": self.username,
            "phone": self.phone,
            "disabled": self.disabled,
            "verified": self.verified,
        }

    def validate(self) -> None:
        """
        验证帐户状态是否合法。
        Raises:
            DeletedError: 如果帐户已被删除，引发此异常。
            UnverifiedError: 如果帐户未经验证，引发此异常。
            DisabledError: 如果帐户已禁用，引发此异常。
        """
        if self.deleted:
            raise DeletedError("帐户已被删除。")
        elif not self.verified:
            raise UnverifiedError()
        elif self.disabled:
            raise DisabledError()

    async def disable(self):
        """
        使帐户不可用。

        Raises:
            DisabledError: 如果帐户已被禁用，引发此异常。
        """
        if self.disabled:
            raise DisabledError("帐户已被禁用。")
        self.disabled = True
        await self.save(update_fields=["disabled"])

    @staticmethod
    async def get_via_email(email: str):
        """
        通过电子邮件获取帐户。
        Args:
            email (str): 与要检索的帐户关联的电子邮件。
        Returns:
            account: 符合条件的帐户。
        Raises:
            NotFoundError: 如果找不到与给定电子邮件相关联的帐户，引发此异常。
        """
        try:
            return await Account.filter(email=email, deleted=False).get()
        except DoesNotExist as e:
            raise NotFoundError("找不到使用此电子邮件的帐户。") from e

    @staticmethod
    async def get_via_username(username: str):
        """
        通过用户名获取帐户。
        Args:
            username (str): 与要检索的帐户关联的用户名。
        Returns:
            account: 符合条件的帐户。
        Raises:
            NotFoundError: 如果找不到与给定用户名相关联的帐户，引发此异常。
        """
        try:
            return await Account.filter(username=username, deleted=False).get()
        except DoesNotExist as e:
            raise NotFoundError("找不到使用此用户名的帐户。") from e

    @staticmethod
    async def get_via_phone(phone: str):
        """
        通过电话号码获取帐户。
        Args:
            phone (str): 与要检索的帐户关联的电话号码。
        Returns:
            account: 符合条件的帐户。
        Raises:
            NotFoundError: 如果找不到与给定电话号码相关联的帐户，引发此异常。
        """
        try:
            return await Account.filter(phone=phone, deleted=False).get()
        except DoesNotExist as e:
            raise NotFoundError("找不到使用此电话号码的帐户。") from e


# Session模型表示用户会话的信息，包括会话的有效期、是否可用，以及与会话相关联的帐户。它还定义了一些方法，例如将会话编码为JWT令牌，并从JWT令牌解码会话。
# 接下来的几个模型VerificationSession、TwoStepSession、CaptchaSession、AuthenticationSession都是从Session派生的特殊会话模型，
# 用于不同的身份验证和验证方法。
class Session(BaseModel):
    """
    用于客户端标识和验证的模型。所有会话模型都从此模型派生。
    Attributes:
        expiration_date (datetime): 会话过期的日期和时间，之后无法再使用。
        active (bool): 确定会话是否可以使用。
        ip (str): 创建会话的客户端的IP地址。
        bearer (ForeignKeyRelation[Account]): 与此会话关联的帐户。
    这个模型用于跟踪会话，包括会话的有效期、是否可用，以及与会话相关联的帐户。
    """
    expiration_date: datetime.datetime = fields.DatetimeField(
        null=True, description="会话过期的日期和时间，之后无法再使用")
    active: bool = fields.BooleanField(default=True, description="确定会话是否可以使用")
    ip: str = fields.CharField(max_length=16)
    bearer: fields.ForeignKeyRelation["Account"] = fields.ForeignKeyField(
        "models.Account", null=True
    )   # 关联Account模型

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @property
    def json(self) -> dict:
        """
        生成一个包含会话信息的JSON可序列化字典。
        Returns:
            dict: 包含会话信息的字典。
        """
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "expiration_date": str(self.expiration_date),
            "bearer": self.bearer.username
            if isinstance(self.bearer, Account)
            else None,
            "active": self.active,
        }

    def validate(self) -> None:
        """
        验证会话状态是否合法。判断会话是否已被删除、是否已过期、是否已停用。
        Raises:
            DeletedError: 如果会话已被删除，引发此异常。
            ExpiredError: 如果会话已过期，引发此异常。
            DeactivatedError: 如果会话已被停用，引发此异常。
        """
        if self.deleted:
            raise DeletedError("会话已被删除。")
        elif (
                self.expiration_date
                and datetime.datetime.now(datetime.timezone.utc) >= self.expiration_date
        ):
            raise ExpiredError()
        elif not self.active:
            raise DeactivatedError()

    async def deactivate(self):
        """
        使会话停用并不可用。
        Raises:
            DeactivatedError: 如果会话已被停用，引发此异常。
        """
        if self.active:
            self.active = False
            await self.save(update_fields=["active"])
        else:
            raise DeactivatedError("会话已被停用。", 403)

    def encode(self, response: HTTPResponse) -> None:
        """
        将会话转换为JWT，然后存储在客户端的cookie中。
        Args:
            response (HTTPResponse): 用于在客户端cookie中存储JWT的Sanic响应。
        """
        payload = {
            "id": self.id,
            "date_created": str(self.date_created),
            "expiration_date": str(self.expiration_date),
            "ip": self.ip,
        }
        cookie = (
            f"{security_config.SESSION_PREFIX}_{self.__class__.__name__.lower()[:7]}"
        )
        encoded_session = jwt.encode(
            payload, security_config.SECRET, security_config.SESSION_ENCODING_ALGORITHM
        )
        if isinstance(encoded_session, bytes):
            encoded_session = encoded_session.decode()
        response.cookies.add_cookie(
            cookie,
            encoded_session,
            httponly=security_config.SESSION_HTTPONLY,
            samesite=security_config.SESSION_SAMESITE,
            secure=security_config.SESSION_SECURE,
        )
        if self.expiration_date:
            response.cookies.get_cookie(cookie).expires = self.expiration_date
        if security_config.SESSION_DOMAIN:
            response.cookies.get_cookie(
                cookie).domain = security_config.SESSION_DOMAIN

    @classmethod
    async def new(
            cls,
            request: Request,
            account: Account,
            **kwargs: Union[int, str, bool, float, list, dict],
    ):
        """
        使用预设值创建会话。 会话的有效期、IP地址和与会话关联的帐户都是预设的。
        Args:
            request (Request): Sanic请求参数。
            account (Account): 与会话关联的帐户。
            **kwargs (dict[str, Union[int, str, bool, float, list, dict]]): 在创建会话期间应用的额外参数。
        Returns:
            session: 创建的会话。
        """
        raise NotImplementedError()

    @classmethod
    async def get_associated(cls, account: Account):
        """
        检索与帐户关联的会话。 会话的有效期、IP地址和与会话关联的帐户都是预设的。
        Args:
            account (Request): 与要检索的会话关联的帐户。
        Returns:
            sessions: 与帐户关联的会话列表。
        Raises:
            NotFoundError: 如果找不到与帐户关联的会话，引发此异常。
        """
        sessions = await cls.filter(bearer=account).prefetch_related("bearer").all()
        if not sessions:
            raise NotFoundError("未找到与帐户关联的会话。")
        return sessions

    @classmethod
    def decode_raw(cls, request: Request) -> dict:
        """
        从客户端cookie中解码JWT令牌并转换为Python字典。 令牌的有效性不会被检查。 令牌的有效性应该在调用此方法之前检查。 
        Args:
            request (Request): Sanic请求参数。
        Returns:
            session_dict: 包含会话信息的字典。
        Raises:
            JWTDecodeError: 如果解码失败，引发此异常。
        """
        cookie = request.cookies.get(
            f"{security_config.SESSION_PREFIX}_{cls.__name__.lower()[:7]}"
        )
        try:
            if not cookie:
                raise JWTDecodeError("未提供或已过期的会话令牌。", 401)
            else:
                return jwt.decode(
                    cookie,
                    security_config.PUBLIC_SECRET or security_config.SECRET,
                    security_config.SESSION_ENCODING_ALGORITHM,
                )
        except DecodeError as e:
            raise JWTDecodeError(str(e)) from e

    @classmethod
    async def decode(cls, request: Request):
        """
        从客户端cookie中解码会话JWT并将其转换为Sanic Security会话。 
        令牌的有效性将在此方法中检查。  
        如果令牌无效，将引发异常。
        Args:
            request (Request): Sanic请求参数。
        Returns:
            session: 解码后的会话。
        Raises:
            JWTDecodeError: 如果解码失败，引发此异常。
            NotFoundError: 如果找不到会话，引发此异常。
        """
        try:
            decoded_raw = cls.decode_raw(request)
            decoded_session = (
                await cls.filter(id=decoded_raw["id"]).prefetch_related("bearer").get()
            )
        except DoesNotExist as e:
            raise NotFoundError("找不到会话。") from e
        return decoded_session  # 返回解码后的会

    class Meta:
        abstract = True


# VerificationSession模型表示需要某种形式的代码、密钥来验证客户端的情况。它包括了用于验证的代码和错误尝试的次数。
class VerificationSession(Session):
    """
    用于需要某种形式的代码、密钥的客户端验证方法。 
    与Session相比，VerificationSession是一种特殊的会话，它需要某种形式的代码、密钥来验证客户端。
    Attributes:
        attempts (int): 用户输入与此验证会话代码不相等的错误次数。
        code (str): 用作密钥的代码，将通过电子邮件、短信等方式发送以完成验证挑战。
    这个模型用于需要通过输入代码来验证客户端的情况，例如通过电子邮件或短信发送的验证码。
    """
    attempts: int = fields.IntField(
        default=0, description="用户输入与此验证会话代码不相等的错误次数")
    code: str = fields.CharField(
        max_length=10, default=get_code, null=True, description="用作密钥的代码，将通过电子邮件、短信等方式发送以完成验证")

    @classmethod
    async def new(cls, request: Request, account: Account, **kwargs):
        raise NotImplementedError

    async def check_code(self, request: Request, code: str) -> None:
        """
        检查传递的代码是否等于会话代码。 如果不相等，会话的错误尝试次数将增加。
        Args:
            code (str): 与会话代码进行交叉检查的代码。
            request (Request): Sanic请求参数。
        Raises:
            ChallengeError: 如果代码不匹配验证会话代码，引发此异常。
            MaxedOutChallengeError: 如果尝试次数超过了最大挑战次数，引发此异常。
        """
        if self.code == code.upper():
            self.active = False
            await self.save(update_fields=["active"])

        elif self.attempts < security_config.MAX_CHALLENGE_ATTEMPTS:  # 如果尝试次数小于最大挑战次数
            self.attempts += 1
            await self.save(update_fields=["attempts"])  # 保存尝试次数
            raise ChallengeError(
                "您的代码与验证会话代码不匹配。"
            )
        else:
            logger.warning(
                f"客户端 ({get_ip(request)}) 已达到会话挑战尝试的最大次数"
            )
            raise MaxedOutChallengeError()

    class Meta:
        abstract = True


# TwoStepSession模型表示通过电子邮件或短信发送的代码来验证客户端的情况。它派生自VerificationSession，并提供了特定的实现。
class TwoStepSession(VerificationSession):
    """
    通过电子邮件或短信发送的代码来验证客户端。 
    与VerificationSession相比，TwoStepSession是一种特殊的验证方法，它通过电子邮件或短信发送代码来验证客户端。
    """

    @classmethod
    async def new(cls, request: Request, account: Account, **kwargs):
        # 创建新的两步验证会话  -->两步验证会话的创建-->两步验证会话的验证-->两步验证会话的停用
        return await TwoStepSession.create(
            **kwargs,
            ip=get_ip(request),
            bearer=account,
            expiration_date=get_expiration_date(
                security_config.TWO_STEP_SESSION_EXPIRATION
            ),
        )

    class Meta:
        table = "two_step_session"


# CaptchaSession模型表示通过验证码挑战来验证客户端的情况。它派生自VerificationSession，并提供了特定的实现。
# 可实现僵尸客户端的验证，不是同时图片验证码来验证登录信息
class CaptchaSession(VerificationSession):
    """
    通过验证码挑战来验证客户端。  
    与VerificationSession相比，CaptchaSession是一种特殊的验证方法，它通过Captcha验证码来验证客户端。
    """

    @classmethod
    # 创建新的验证码会话-->验证码会话的创建-->验证码会话的验证-->验证码会话的停用
    async def new(cls, request: Request, **kwargs):
        return await CaptchaSession.create(
            **kwargs,
            ip=get_ip(request),
            expiration_date=get_expiration_date(
                security_config.CAPTCHA_SESSION_EXPIRATION
            ),
        )  # 创建新的验证码会话。

    def get_image(self) -> HTTPResponse:
        """
        检索验证码图像文件。 
        Returns:
            captcha_image: 包含验证码图像的HTTP响应。
        """
        image = ImageCaptcha(190, 90, fonts=[security_config.CAPTCHA_FONT])
        # 创建验证码图像  -->验证码图像的创建  -->验证码图像的保存  -->验证码图像的检索
        with BytesIO() as output:  # BytesIO()函数用于在内存中创建一个bytes流，用于存储二进制数据
            image.generate_image(self.code).save(output, format="JPEG")
            return raw(output.getvalue(), content_type="image/jpeg")

    class Meta:
        table = "captcha_session"


class AuthenticationSession(Session):
    # AuthenticationSession模型表示用于身份验证和识别客户端的情况。它可以配置为需要第二因素验证。
    """
    用于身份验证和识别客户端的模型。 
    Attributes:
        requires_second_factor (bool): 确定会话是否需要第二因素验证。
    这个模型用于身份验证和识别客户端。它可以配置为需要第二因素验证。
    """
    requires_second_factor: bool = fields.BooleanField(
        default=False)   # 确定会话是否需要第二因素验证。

    def validate(self) -> None:
        """
        验证会话状态是否合法。
        Raises:
            DeletedError: 如果会话已被删除，引发此异常。
            ExpiredError: 如果会话已过期，引发此异常。
            DeactivatedError: 如果会话已被停用，引发此异常。
            SecondFactorRequiredError: 如果需要第二因素验证，引发此异常。
        """
        super().validate()  # 调用父类的validate方法
        if self.requires_second_factor:  # 如果需要第二因素验证
            raise SecondFactorRequiredError()

    @classmethod
    async def new(
            cls, request: Request, account: Account, requires_second_factor: bool = False
    ):
        """
        创建新的身份验证会话。
        Args:
            request (Request): Sanic请求参数。
            account (Account): 与会话关联的帐户。
            requires_second_factor (bool): 确定会话是否需要第二因素验证。
        Returns:
            session: 创建的身份验证会话。
        """
        return await cls.create(
            ip=get_ip(request),
            bearer=account,
            requires_second_factor=requires_second_factor,
        )   # 创建新的身份验证会话。

    class Meta:
        table = "authentication_session"


class Role(BaseModel):
    """
    用于定义用户角色的模型。
    Attributes:
        name (str): 角色的名称。
        permissions (List[str]): 与角色关联的权限列表。
    这个模型用于定义用户角色，每个角色可以包括一组权限。这些角色用于授权用户访问不同的资源和执行不同的操作。
    """
    name: str = fields.CharField(unique=True, max_length=255)
    description: str = fields.CharField(max_length=255, null=True)
    permissions: str = fields.CharField(max_length=255, null=True)

    @property   # 用于将方法转换为属性
    def json(self) -> dict:
        """
        生成一个包含角色信息的JSON可序列化字典。
        Returns:
            dict: 包含角色信息的字典。
        """
        return {"id": self.id, "name": self.name, "permissions": self.permissions}

    def validate(self) -> None:  # 验证角色状态是否合法。
        raise NotImplementedError()

    class Meta:
        table = "role"


class Permission(BaseModel):
    """
    用于定义权限的模型。
    Attributes:
        name (str): 权限的名称。
        description (str): 权限的描述。
    这个模型用于定义不同权限，每个权限可以包括一个名称和描述，以便更好地理解它的作用。
    """
    name: str = fields.CharField(unique=True, max_length=255)
    description: str = fields.CharField(max_length=255, null=True)

    @property
    def json(self) -> dict:
        """
        生成一个包含权限信息的JSON可序列化字典。
        Returns:
            dict: 包含权限信息的字典。
        """
        return {"id": self.id, "name": self.name, "description": self.description}

    def validate(self) -> None:
        """
        验证权限状态是否合法。
        """
        raise NotImplementedError()


class Department(BaseModel):
    """
    用于定义部门的模型。
    Attributes:
        name (str): 部门的名称。
        description (str): 部门的描述。
    这个模型用于定义不同部门，每个部门可以包括一个名称和描述，以便更好地组织和管理用户。
    """
    name: str = fields.CharField(unique=True, max_length=255)
    description: str = fields.CharField(max_length=255, null=True)

    @property
    def json(self) -> dict:
        """
        生成一个包含部门信息的JSON可序列化字典。
        Returns:
            dict: 包含部门信息的字典。
        """
        return {"id": self.id, "name": self.name, "description": self.description}

    def validate(self) -> None:
        """
        验证部门状态是否合法。
        """
        raise NotImplementedError()


class Server(BaseModel):
    """
    服务器模型，表示远程服务器的信息。
    Attributes:
        name (str): 服务器名称。
        ip_address (str): 服务器的IP地址。
        port (int): 服务器的端口号。
        username (str): 用于登录服务器的用户名。
        password (str): 用于登录服务器的密码，应使用安全加密存储。
        is_active (bool): 服务器是否激活。
    """

    name: str = fields.CharField(max_length=255)
    ip_address: str = fields.CharField(max_length=15)  # IPv4格式
    port: int = fields.IntField()
    username: str = fields.CharField(max_length=255)
    password: str = fields.CharField(max_length=255)  # 使用安全加密存储
    is_active: bool = fields.BooleanField(default=True)

    @property
    def json(self) -> dict:
        """
        生成一个包含服务器信息的JSON可序列化字典。
        Returns:
            dict: 包含服务器信息的字典。
        """
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "name": self.name,
            "ip_address": self.ip_address,
            "port": self.port,
            "username": self.username,
            "is_active": self.is_active,
        }


class ScheduledTask(BaseModel):
    """
    定时任务模型，表示需要在服务器上执行的定时任务。
    Attributes:
        name (str): 任务名称。
        command (str): 要执行的命令。
        schedule_type (str): 定时任务的类型，如"interval"或"cron"。
        schedule_value (Union[dict, str]): 定时任务的值，可以是Cron表达式（str）或间隔配置（dict）。
        server (ForeignKey[Server]): 任务所属的服务器。
    """

    name: str = fields.CharField(max_length=255)
    command: str = fields.TextField()
    schedule_type: str = fields.CharField(
        max_length=10, choices=["interval", "cron"]
    )
    schedule_value: Union[dict, str] = fields.JSONField()
    server: fields.ForeignKeyRelation[Server] = fields.ForeignKeyField(
        "models.Server", related_name="scheduled_tasks"
    )

    @property
    def json(self) -> dict:
        """
        生成一个包含定时任务信息的JSON可序列化字典。
        Returns:
            dict: 包含定时任务信息的字典。
        """
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "name": self.name,
            "schedule_type": self.schedule_type,
            "schedule_value": self.schedule_value,
            "server_id": self.server.id,
        }

    def get_schedule_entry(self) -> ScheduleEntry:
        """
        函数 `get_schedule_entry` 根据计划任务的类型和值创建一个 Celery `ScheduleEntry` 对象。
        :return: 一个 Celery ScheduleEntry 对象。
        """
        if self.schedule_type == "interval":
            return schedules.schedule(
                datetime.datetime.timedelta(
                    seconds=self.schedule_value["seconds"])
            )
        elif self.schedule_type == "cron":
            return schedules.crontab(
                minute=self.schedule_value["minute"],
                hour=self.schedule_value["hour"],
                day_of_week=self.schedule_value["day_of_week"],
                day_of_month=self.schedule_value["day_of_month"],
                month_of_year=self.schedule_value["month_of_year"],
            )


class LogEntry(BaseModel):
    """
    日志模型，用于存储日志条目的信息。
    Attributes:
        timestamp (datetime.datetime): 日志条目的时间戳。
        log_level (str): 日志级别（例如：INFO、WARNING、ERROR等）。
        message (str): 日志消息内容。
        # 其他字段可以根据需求添加
    """

    timestamp: datetime.datetime = fields.DatetimeField()
    log_level: str = fields.CharField(max_length=255)
    message: str = fields.TextField()
    # 可以根据需要添加其他字段

    @property
    def json(self) -> dict:
        return {
            "id": self.id,
            "timestamp": str(self.timestamp),
            "log_level": self.log_level,
            "message": self.message,
            # 添加其他字段的序列化
        }


async def get_or_create_record(model_cls: Type, data: Dict):
    """
    函数“get_or_create_record”根据给定数据检查模型中是否存在记录，如果不存在则创建新记录。

    :param model_cls: 参数“model_cls”是您要从中创建或检索记录的模型的类。它应该是数据库模型类的子类，例如 Django 模型或 ORM 模型。
    :type model_cls: Type
    :param data: “data”参数是一个字典，其中包含用于在数据库中查询或创建记录的数据。字典的键代表记录的字段，值代表这些字段的值。
    :type data: Dict
    :return: 函数“get_or_create_record”返回一个记录对象。
    """
    # 构建Q对象来查询记录
    query = Q(**data)
    record = await model_cls.get_or_none(query)
    # print(record.pk)
    if record is None:
        # 如果记录不存在，创建一个新记录
        record = await model_cls.create(**data)
    return record
# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# File       : models.py
# Time       ：10/9/2023 10:03 pm
# Author     ：author A-Corner
# version    ：python 3.11
# Description：
"""
# BaseModel是其他模型的基类，包括Account、Session、VerificationSession、TwoStepSession、CaptchaSession、AuthenticationSession、Role。
# 这些模型都继承自BaseModel，并可以使用BaseModel中定义的字段和方法。


class BaseModel(Model):
    """
    BaseModel是引用了sanic security的BaseModel来进行二次修改的。
    这个基类定义了一些共有的字段和方法，所有模型都可以继承它。
    它包括了一些常见的数据库字段，例如id，创建时间，更新时间，删除标记，锁定标记。这些字段用于跟踪数据库中的记录。
    Attributes:
        id (int): 模型的主键。
        date_created (datetime): 记录在数据库中创建的时间。
        date_updated (datetime): 记录在数据库中更新的时间。
        deleted (bool): 记录是否被标记为删除。
    """

    id: int = fields.IntField(pk=True)  # type: ignore
    date_created: datetime.datetime = fields.DatetimeField(
        auto_now_add=True, description="创建时间")
    date_updated: datetime.datetime = fields.DatetimeField(
        auto_now=True, description="更新时间")
    deleted: bool = fields.BooleanField(default=False, description="删除标记")

    def validate(self) -> None:
        """
        这个方法用于验证模型的状态是否合法。子类可以覆盖这个方法来实现特定的验证逻辑。
        Raises:
            SecurityError: 如果验证失败，会引发此异常。
        """
        raise NotImplementedError()

    @property
    def json(self) -> dict:
        """
        生成一个JSON可序列化的字典，用于在HTTP请求或响应中使用。
        Returns:
            dict: 包含模型数据的字典。
        这个方法可以将模型的数据转换为JSON格式，以便在HTTP请求和响应中传递数据。
        """
        raise NotImplementedError()

    class Meta:
        abstract = True  # 代表了这个是抽象类


# Account模型表示用户帐户的信息，包括用户名、电子邮件、密码等等。它还定义了一些方法，例如禁用帐户、获取帐户等等。
class Account(BaseModel):
    """
    包含所有可识别用户信息的模型。
    Attributes:
        username (str): 公共标识符。
        email (str): 私有标识符，可用于验证。
        phone (str): 包含国家代码的手机号，可用于验证。可以为null或空。
        password (str): 用于保护帐户的密码。必须使用Argon2哈希。
        disabled (bool): 使帐户不可用但仍可用。
        verified (bool): 使帐户不可用，直到通过两步验证或其他方法验证。
        roles (ManyToManyRelation[Role]): 与此帐户关联的角色。

    这个模型表示用户的基本信息，包括用户名、电子邮件、电话号码和密码。还可以标记帐户是否已禁用、是否已验证，以及与帐户相关联的角色。
    """

    username: str = fields.CharField(unique=True, max_length=32)
    email: str = fields.CharField(unique=True, max_length=255)
    phone: str = fields.CharField(unique=True, max_length=14, null=True)
    password: str = fields.CharField(max_length=255)
    disabled: bool = fields.BooleanField(default=False)
    verified: bool = fields.BooleanField(default=False)
    roles: fields.ManyToManyRelation["Role"] = fields.ManyToManyField(
        "models.Role", through="account_role"
    )

    @property
    def json(self) -> dict:
        """
        生成一个包含帐户信息的JSON可序列化字典。
        Returns:
            dict: 包含帐户信息的字典。
        """
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "email": self.email,
            "username": self.username,
            "phone": self.phone,
            "disabled": self.disabled,
            "verified": self.verified,
        }

    def validate(self) -> None:
        """
        验证帐户状态是否合法。
        Raises:
            DeletedError: 如果帐户已被删除，引发此异常。
            UnverifiedError: 如果帐户未经验证，引发此异常。
            DisabledError: 如果帐户已禁用，引发此异常。
        """
        if self.deleted:
            raise DeletedError("帐户已被删除。")
        elif not self.verified:
            raise UnverifiedError()
        elif self.disabled:
            raise DisabledError()

    async def disable(self):
        """
        使帐户不可用。

        Raises:
            DisabledError: 如果帐户已被禁用，引发此异常。
        """
        if self.disabled:
            raise DisabledError("帐户已被禁用。")
        self.disabled = True
        await self.save(update_fields=["disabled"])

    @staticmethod
    async def get_via_email(email: str):
        """
        通过电子邮件获取帐户。
        Args:
            email (str): 与要检索的帐户关联的电子邮件。
        Returns:
            account: 符合条件的帐户。
        Raises:
            NotFoundError: 如果找不到与给定电子邮件相关联的帐户，引发此异常。
        """
        try:
            return await Account.filter(email=email, deleted=False).get()
        except DoesNotExist as e:
            raise NotFoundError("找不到使用此电子邮件的帐户。") from e

    @staticmethod
    async def get_via_username(username: str):
        """
        通过用户名获取帐户。
        Args:
            username (str): 与要检索的帐户关联的用户名。
        Returns:
            account: 符合条件的帐户。
        Raises:
            NotFoundError: 如果找不到与给定用户名相关联的帐户，引发此异常。
        """
        try:
            return await Account.filter(username=username, deleted=False).get()
        except DoesNotExist as e:
            raise NotFoundError("找不到使用此用户名的帐户。") from e

    @staticmethod
    async def get_via_phone(phone: str):
        """
        通过电话号码获取帐户。
        Args:
            phone (str): 与要检索的帐户关联的电话号码。
        Returns:
            account: 符合条件的帐户。
        Raises:
            NotFoundError: 如果找不到与给定电话号码相关联的帐户，引发此异常。
        """
        try:
            return await Account.filter(phone=phone, deleted=False).get()
        except DoesNotExist as e:
            raise NotFoundError("找不到使用此电话号码的帐户。") from e


# Session模型表示用户会话的信息，包括会话的有效期、是否可用，以及与会话相关联的帐户。它还定义了一些方法，例如将会话编码为JWT令牌，并从JWT令牌解码会话。
# 接下来的几个模型VerificationSession、TwoStepSession、CaptchaSession、AuthenticationSession都是从Session派生的特殊会话模型，
# 用于不同的身份验证和验证方法。
class Session(BaseModel):
    """
    用于客户端标识和验证的模型。所有会话模型都从此模型派生。
    Attributes:
        expiration_date (datetime): 会话过期的日期和时间，之后无法再使用。
        active (bool): 确定会话是否可以使用。
        ip (str): 创建会话的客户端的IP地址。
        bearer (ForeignKeyRelation[Account]): 与此会话关联的帐户。
    这个模型用于跟踪会话，包括会话的有效期、是否可用，以及与会话相关联的帐户。
    """
    expiration_date: datetime.datetime = fields.DatetimeField(
        null=True, description="会话过期的日期和时间，之后无法再使用")
    active: bool = fields.BooleanField(default=True, description="确定会话是否可以使用")
    ip: str = fields.CharField(max_length=16)
    bearer: fields.ForeignKeyRelation["Account"] = fields.ForeignKeyField(
        "models.Account", null=True
    )   # 关联Account模型

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @property
    def json(self) -> dict:
        """
        生成一个包含会话信息的JSON可序列化字典。
        Returns:
            dict: 包含会话信息的字典。
        """
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "expiration_date": str(self.expiration_date),
            "bearer": self.bearer.username
            if isinstance(self.bearer, Account)
            else None,
            "active": self.active,
        }

    def validate(self) -> None:
        """
        验证会话状态是否合法。判断会话是否已被删除、是否已过期、是否已停用。
        Raises:
            DeletedError: 如果会话已被删除，引发此异常。
            ExpiredError: 如果会话已过期，引发此异常。
            DeactivatedError: 如果会话已被停用，引发此异常。
        """
        if self.deleted:
            raise DeletedError("会话已被删除。")
        elif (
                self.expiration_date
                and datetime.datetime.now(datetime.timezone.utc) >= self.expiration_date
        ):
            raise ExpiredError()
        elif not self.active:
            raise DeactivatedError()

    async def deactivate(self):
        """
        使会话停用并不可用。
        Raises:
            DeactivatedError: 如果会话已被停用，引发此异常。
        """
        if self.active:
            self.active = False
            await self.save(update_fields=["active"])
        else:
            raise DeactivatedError("会话已被停用。", 403)

    def encode(self, response: HTTPResponse) -> None:
        """
        将会话转换为JWT，然后存储在客户端的cookie中。
        Args:
            response (HTTPResponse): 用于在客户端cookie中存储JWT的Sanic响应。
        """
        payload = {
            "id": self.id,
            "date_created": str(self.date_created),
            "expiration_date": str(self.expiration_date),
            "ip": self.ip,
        }
        cookie = (
            f"{security_config.SESSION_PREFIX}_{self.__class__.__name__.lower()[:7]}"
        )
        encoded_session = jwt.encode(
            payload, security_config.SECRET, security_config.SESSION_ENCODING_ALGORITHM
        )
        if isinstance(encoded_session, bytes):
            encoded_session = encoded_session.decode()
        response.cookies.add_cookie(
            cookie,
            encoded_session,
            httponly=security_config.SESSION_HTTPONLY,
            samesite=security_config.SESSION_SAMESITE,
            secure=security_config.SESSION_SECURE,
        )
        if self.expiration_date:
            response.cookies.get_cookie(cookie).expires = self.expiration_date
        if security_config.SESSION_DOMAIN:
            response.cookies.get_cookie(
                cookie).domain = security_config.SESSION_DOMAIN

    @classmethod
    async def new(
            cls,
            request: Request,
            account: Account,
            **kwargs: Union[int, str, bool, float, list, dict],
    ):
        """
        使用预设值创建会话。 会话的有效期、IP地址和与会话关联的帐户都是预设的。
        Args:
            request (Request): Sanic请求参数。
            account (Account): 与会话关联的帐户。
            **kwargs (dict[str, Union[int, str, bool, float, list, dict]]): 在创建会话期间应用的额外参数。
        Returns:
            session: 创建的会话。
        """
        raise NotImplementedError()

    @classmethod
    async def get_associated(cls, account: Account):
        """
        检索与帐户关联的会话。 会话的有效期、IP地址和与会话关联的帐户都是预设的。
        Args:
            account (Request): 与要检索的会话关联的帐户。
        Returns:
            sessions: 与帐户关联的会话列表。
        Raises:
            NotFoundError: 如果找不到与帐户关联的会话，引发此异常。
        """
        sessions = await cls.filter(bearer=account).prefetch_related("bearer").all()
        if not sessions:
            raise NotFoundError("未找到与帐户关联的会话。")
        return sessions

    @classmethod
    def decode_raw(cls, request: Request) -> dict:
        """
        从客户端cookie中解码JWT令牌并转换为Python字典。 令牌的有效性不会被检查。 令牌的有效性应该在调用此方法之前检查。 
        Args:
            request (Request): Sanic请求参数。
        Returns:
            session_dict: 包含会话信息的字典。
        Raises:
            JWTDecodeError: 如果解码失败，引发此异常。
        """
        cookie = request.cookies.get(
            f"{security_config.SESSION_PREFIX}_{cls.__name__.lower()[:7]}"
        )
        try:
            if not cookie:
                raise JWTDecodeError("未提供或已过期的会话令牌。", 401)
            else:
                return jwt.decode(
                    cookie,
                    security_config.PUBLIC_SECRET or security_config.SECRET,
                    security_config.SESSION_ENCODING_ALGORITHM,
                )
        except DecodeError as e:
            raise JWTDecodeError(str(e)) from e

    @classmethod
    async def decode(cls, request: Request):
        """
        从客户端cookie中解码会话JWT并将其转换为Sanic Security会话。 
        令牌的有效性将在此方法中检查。  
        如果令牌无效，将引发异常。
        Args:
            request (Request): Sanic请求参数。
        Returns:
            session: 解码后的会话。
        Raises:
            JWTDecodeError: 如果解码失败，引发此异常。
            NotFoundError: 如果找不到会话，引发此异常。
        """
        try:
            decoded_raw = cls.decode_raw(request)
            decoded_session = (
                await cls.filter(id=decoded_raw["id"]).prefetch_related("bearer").get()
            )
        except DoesNotExist as e:
            raise NotFoundError("找不到会话。") from e
        return decoded_session  # 返回解码后的会

    class Meta:
        abstract = True


# VerificationSession模型表示需要某种形式的代码、密钥来验证客户端的情况。它包括了用于验证的代码和错误尝试的次数。
class VerificationSession(Session):
    """
    用于需要某种形式的代码、密钥的客户端验证方法。 
    与Session相比，VerificationSession是一种特殊的会话，它需要某种形式的代码、密钥来验证客户端。
    Attributes:
        attempts (int): 用户输入与此验证会话代码不相等的错误次数。
        code (str): 用作密钥的代码，将通过电子邮件、短信等方式发送以完成验证挑战。
    这个模型用于需要通过输入代码来验证客户端的情况，例如通过电子邮件或短信发送的验证码。
    """
    attempts: int = fields.IntField(
        default=0, description="用户输入与此验证会话代码不相等的错误次数")
    code: str = fields.CharField(
        max_length=10, default=get_code, null=True, description="用作密钥的代码，将通过电子邮件、短信等方式发送以完成验证")

    @classmethod
    async def new(cls, request: Request, account: Account, **kwargs):
        raise NotImplementedError

    async def check_code(self, request: Request, code: str) -> None:
        """
        检查传递的代码是否等于会话代码。 如果不相等，会话的错误尝试次数将增加。
        Args:
            code (str): 与会话代码进行交叉检查的代码。
            request (Request): Sanic请求参数。
        Raises:
            ChallengeError: 如果代码不匹配验证会话代码，引发此异常。
            MaxedOutChallengeError: 如果尝试次数超过了最大挑战次数，引发此异常。
        """
        if self.code == code.upper():
            self.active = False
            await self.save(update_fields=["active"])

        elif self.attempts < security_config.MAX_CHALLENGE_ATTEMPTS:  # 如果尝试次数小于最大挑战次数
            self.attempts += 1
            await self.save(update_fields=["attempts"])  # 保存尝试次数
            raise ChallengeError(
                "您的代码与验证会话代码不匹配。"
            )
        else:
            logger.warning(
                f"客户端 ({get_ip(request)}) 已达到会话挑战尝试的最大次数"
            )
            raise MaxedOutChallengeError()

    class Meta:
        abstract = True


# TwoStepSession模型表示通过电子邮件或短信发送的代码来验证客户端的情况。它派生自VerificationSession，并提供了特定的实现。
class TwoStepSession(VerificationSession):
    """
    通过电子邮件或短信发送的代码来验证客户端。 
    与VerificationSession相比，TwoStepSession是一种特殊的验证方法，它通过电子邮件或短信发送代码来验证客户端。
    """

    @classmethod
    async def new(cls, request: Request, account: Account, **kwargs):
        # 创建新的两步验证会话  -->两步验证会话的创建-->两步验证会话的验证-->两步验证会话的停用
        return await TwoStepSession.create(
            **kwargs,
            ip=get_ip(request),
            bearer=account,
            expiration_date=get_expiration_date(
                security_config.TWO_STEP_SESSION_EXPIRATION
            ),
        )

    class Meta:
        table = "two_step_session"


# CaptchaSession模型表示通过验证码挑战来验证客户端的情况。它派生自VerificationSession，并提供了特定的实现。
# 可实现僵尸客户端的验证，不是同时图片验证码来验证登录信息
class CaptchaSession(VerificationSession):
    """
    通过验证码挑战来验证客户端。  
    与VerificationSession相比，CaptchaSession是一种特殊的验证方法，它通过Captcha验证码来验证客户端。
    """

    @classmethod
    # 创建新的验证码会话-->验证码会话的创建-->验证码会话的验证-->验证码会话的停用
    async def new(cls, request: Request, **kwargs):
        return await CaptchaSession.create(
            **kwargs,
            ip=get_ip(request),
            expiration_date=get_expiration_date(
                security_config.CAPTCHA_SESSION_EXPIRATION
            ),
        )  # 创建新的验证码会话。

    def get_image(self) -> HTTPResponse:
        """
        检索验证码图像文件。 
        Returns:
            captcha_image: 包含验证码图像的HTTP响应。
        """
        image = ImageCaptcha(190, 90, fonts=[security_config.CAPTCHA_FONT])
        # 创建验证码图像  -->验证码图像的创建  -->验证码图像的保存  -->验证码图像的检索
        with BytesIO() as output:  # BytesIO()函数用于在内存中创建一个bytes流，用于存储二进制数据
            image.generate_image(self.code).save(output, format="JPEG")
            return raw(output.getvalue(), content_type="image/jpeg")

    class Meta:
        table = "captcha_session"


class AuthenticationSession(Session):
    # AuthenticationSession模型表示用于身份验证和识别客户端的情况。它可以配置为需要第二因素验证。
    """
    用于身份验证和识别客户端的模型。 
    Attributes:
        requires_second_factor (bool): 确定会话是否需要第二因素验证。
    这个模型用于身份验证和识别客户端。它可以配置为需要第二因素验证。
    """
    requires_second_factor: bool = fields.BooleanField(
        default=False)   # 确定会话是否需要第二因素验证。

    def validate(self) -> None:
        """
        验证会话状态是否合法。
        Raises:
            DeletedError: 如果会话已被删除，引发此异常。
            ExpiredError: 如果会话已过期，引发此异常。
            DeactivatedError: 如果会话已被停用，引发此异常。
            SecondFactorRequiredError: 如果需要第二因素验证，引发此异常。
        """
        super().validate()  # 调用父类的validate方法
        if self.requires_second_factor:  # 如果需要第二因素验证
            raise SecondFactorRequiredError()

    @classmethod
    async def new(
            cls, request: Request, account: Account, requires_second_factor: bool = False
    ):
        """
        创建新的身份验证会话。
        Args:
            request (Request): Sanic请求参数。
            account (Account): 与会话关联的帐户。
            requires_second_factor (bool): 确定会话是否需要第二因素验证。
        Returns:
            session: 创建的身份验证会话。
        """
        return await cls.create(
            ip=get_ip(request),
            bearer=account,
            requires_second_factor=requires_second_factor,
        )   # 创建新的身份验证会话。

    class Meta:
        table = "authentication_session"


class Role(BaseModel):
    """
    用于定义用户角色的模型。
    Attributes:
        name (str): 角色的名称。
        permissions (List[str]): 与角色关联的权限列表。
    这个模型用于定义用户角色，每个角色可以包括一组权限。这些角色用于授权用户访问不同的资源和执行不同的操作。
    """
    name: str = fields.CharField(unique=True, max_length=255)
    description: str = fields.CharField(max_length=255, null=True)
    permissions: str = fields.CharField(max_length=255, null=True)

    @property   # 用于将方法转换为属性
    def json(self) -> dict:
        """
        生成一个包含角色信息的JSON可序列化字典。
        Returns:
            dict: 包含角色信息的字典。
        """
        return {"id": self.id, "name": self.name, "permissions": self.permissions}

    def validate(self) -> None:  # 验证角色状态是否合法。
        raise NotImplementedError()

    class Meta:
        table = "role"


class Permission(BaseModel):
    """
    用于定义权限的模型。
    Attributes:
        name (str): 权限的名称。
        description (str): 权限的描述。
    这个模型用于定义不同权限，每个权限可以包括一个名称和描述，以便更好地理解它的作用。
    """
    name: str = fields.CharField(unique=True, max_length=255)
    description: str = fields.CharField(max_length=255, null=True)

    @property
    def json(self) -> dict:
        """
        生成一个包含权限信息的JSON可序列化字典。
        Returns:
            dict: 包含权限信息的字典。
        """
        return {"id": self.id, "name": self.name, "description": self.description}

    def validate(self) -> None:
        """
        验证权限状态是否合法。
        """
        raise NotImplementedError()


class Department(BaseModel):
    """
    用于定义部门的模型。
    Attributes:
        name (str): 部门的名称。
        description (str): 部门的描述。
    这个模型用于定义不同部门，每个部门可以包括一个名称和描述，以便更好地组织和管理用户。
    """
    name: str = fields.CharField(unique=True, max_length=255)
    description: str = fields.CharField(max_length=255, null=True)

    @property
    def json(self) -> dict:
        """
        生成一个包含部门信息的JSON可序列化字典。
        Returns:
            dict: 包含部门信息的字典。
        """
        return {"id": self.id, "name": self.name, "description": self.description}

    def validate(self) -> None:
        """
        验证部门状态是否合法。
        """
        raise NotImplementedError()


class Server(BaseModel):
    """
    服务器模型，表示远程服务器的信息。
    Attributes:
        name (str): 服务器名称。
        ip_address (str): 服务器的IP地址。
        port (int): 服务器的端口号。
        username (str): 用于登录服务器的用户名。
        password (str): 用于登录服务器的密码，应使用安全加密存储。
        is_active (bool): 服务器是否激活。
    """

    name: str = fields.CharField(max_length=255)
    ip_address: str = fields.CharField(max_length=15)  # IPv4格式
    port: int = fields.IntField()
    username: str = fields.CharField(max_length=255)
    password: str = fields.CharField(max_length=255)  # 使用安全加密存储
    is_active: bool = fields.BooleanField(default=True)

    @property
    def json(self) -> dict:
        """
        生成一个包含服务器信息的JSON可序列化字典。
        Returns:
            dict: 包含服务器信息的字典。
        """
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "name": self.name,
            "ip_address": self.ip_address,
            "port": self.port,
            "username": self.username,
            "is_active": self.is_active,
        }


class ScheduledTask(BaseModel):
    """
    定时任务模型，表示需要在服务器上执行的定时任务。
    Attributes:
        name (str): 任务名称。
        command (str): 要执行的命令。
        schedule_type (str): 定时任务的类型，如"interval"或"cron"。
        schedule_value (Union[dict, str]): 定时任务的值，可以是Cron表达式（str）或间隔配置（dict）。
        server (ForeignKey[Server]): 任务所属的服务器。
    """

    name: str = fields.CharField(max_length=255)
    command: str = fields.TextField()
    schedule_type: str = fields.CharField(
        max_length=10, choices=["interval", "cron"]
    )
    schedule_value: Union[dict, str] = fields.JSONField()
    server: fields.ForeignKeyRelation[Server] = fields.ForeignKeyField(
        "models.Server", related_name="scheduled_tasks"
    )

    @property
    def json(self) -> dict:
        """
        生成一个包含定时任务信息的JSON可序列化字典。
        Returns:
            dict: 包含定时任务信息的字典。
        """
        return {
            "id": self.id,
            "date_created": str(self.date_created),
            "date_updated": str(self.date_updated),
            "name": self.name,
            "schedule_type": self.schedule_type,
            "schedule_value": self.schedule_value,
            "server_id": self.server.id,
        }

    def get_schedule_entry(self) -> ScheduleEntry:
        """
        函数 `get_schedule_entry` 根据计划任务的类型和值创建一个 Celery `ScheduleEntry` 对象。
        :return: 一个 Celery ScheduleEntry 对象。
        """
        if self.schedule_type == "interval":
            return schedules.schedule(
                datetime.datetime.timedelta(
                    seconds=self.schedule_value["seconds"])
            )
        elif self.schedule_type == "cron":
            return schedules.crontab(
                minute=self.schedule_value["minute"],
                hour=self.schedule_value["hour"],
                day_of_week=self.schedule_value["day_of_week"],
                day_of_month=self.schedule_value["day_of_month"],
                month_of_year=self.schedule_value["month_of_year"],
            )


class LogEntry(BaseModel):
    """
    日志模型，用于存储日志条目的信息。
    Attributes:
        timestamp (datetime.datetime): 日志条目的时间戳。
        log_level (str): 日志级别（例如：INFO、WARNING、ERROR等）。
        message (str): 日志消息内容。
        # 其他字段可以根据需求添加
    """

    timestamp: datetime.datetime = fields.DatetimeField()
    log_level: str = fields.CharField(max_length=255)
    message: str = fields.TextField()
    # 可以根据需要添加其他字段

    @property
    def json(self) -> dict:
        return {
            "id": self.id,
            "timestamp": str(self.timestamp),
            "log_level": self.log_level,
            "message": self.message,
            # 添加其他字段的序列化
        }


async def get_or_create_record(model_cls: Type, data: Dict):
    """
    函数“get_or_create_record”根据给定数据检查模型中是否存在记录，如果不存在则创建新记录。

    :param model_cls: 参数“model_cls”是您要从中创建或检索记录的模型的类。它应该是数据库模型类的子类，例如 Django 模型或 ORM 模型。
    :type model_cls: Type
    :param data: “data”参数是一个字典，其中包含用于在数据库中查询或创建记录的数据。字典的键代表记录的字段，值代表这些字段的值。
    :type data: Dict
    :return: 函数“get_or_create_record”返回一个记录对象。
    """
    # 构建Q对象来查询记录
    query = Q(**data)
    record = await model_cls.get_or_none(query)
    # print(record.pk)
    if record is None:
        # 如果记录不存在，创建一个新记录
        record = await model_cls.create(**data)
    return record
