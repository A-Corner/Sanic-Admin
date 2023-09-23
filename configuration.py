# Importing the 'environ' object from the 'os' module (从 'os' 模块导入 'environ' 对象)
from os import environ
# Importing 'suppress' from 'contextlib' for exception handling (从 'contextlib' 导入 'suppress' 用于异常处理)
from contextlib import suppress
# Importing 'str_to_bool' from 'sanic.utils' for converting strings to boolean (从 'sanic.utils' 导入 'str_to_bool' 用于将字符串转换为布尔值)
from sanic.utils import str_to_bool

DEFAULT_CONFIG = {
    "SECRET": "This is a big secret. Shhhhh",  # Default secret key (默认的密钥)
    "PUBLIC_SECRET": None,  # Default public secret (默认的公共密钥)
    # Default session SameSite attribute (默认的会话 SameSite 属性)
    "SESSION_SAMESITE": "strict",
    "SESSION_SECURE": True,  # Default session secure flag (默认的会话安全标志)
    # Default session httponly flag (默认的会话 httponly 标志)
    "SESSION_HTTPONLY": True,
    "SESSION_DOMAIN": None,  # Default session domain (默认的会话域)
    "SESSION_PREFIX": "token",  # Default session prefix (默认的会话前缀)
    # Default session encoding algorithm (默认的会话编码算法)
    "SESSION_ENCODING_ALGORITHM": "HS256",
    # Default maximum challenge attempts (默认的最大挑战尝试次数)
    "MAX_CHALLENGE_ATTEMPTS": 5,
    # Default captcha session expiration time (默认的验证码会话过期时间)
    "CAPTCHA_SESSION_EXPIRATION": 60,
    "CAPTCHA_FONT": "captcha-font.ttf",  # Default captcha font (默认的验证码字体)
    # Default two-step session expiration time (默认的两步会话过期时间)
    "TWO_STEP_SESSION_EXPIRATION": 200,
    # Default authentication session expiration time (默认的身份验证会话过期时间)
    "AUTHENTICATION_SESSION_EXPIRATION": 2592000,
    # Default allow login with username flag (默认的允许使用用户名登录标志)
    "ALLOW_LOGIN_WITH_USERNAME": False,
    # Default initial admin email (默认的初始管理员电子邮件)
    "INITIAL_ADMIN_EMAIL": "admin@example.com",
    # Default initial admin password (默认的初始管理员密码)
    "INITIAL_ADMIN_PASSWORD": "admin123",
    # Default test database URL (默认的测试数据库 URL)
    "DATABASE_URL": "sqlite://:memory:",
}


# 'Config' 类是 'dict' 的子类，它加载环境变量并将它们作为属性分配给类实例。
class Config(dict):
    SECRET: str  # Secret key (密钥)
    PUBLIC_SECRET: str  # Public secret key (公共密钥)
    SESSION_SAMESITE: str  # Session SameSite attribute (会话 SameSite 属性)
    SESSION_SECURE: bool  # Session secure flag (会话安全标志)
    SESSION_HTTPONLY: bool  # Session httponly flag (会话 httponly 标志)
    SESSION_DOMAIN: str  # Session domain (会话域)
    SESSION_ENCODING_ALGORITHM: str  # Session encoding algorithm (会话编码算法)
    SESSION_PREFIX: str  # Session prefix (会话前缀)
    MAX_CHALLENGE_ATTEMPTS: int  # Maximum challenge attempts (最大挑战尝试次数)
    # Captcha session expiration time (验证码会话过期时间)
    CAPTCHA_SESSION_EXPIRATION: int
    CAPTCHA_FONT: str  # Captcha font (验证码字体)
    # Two-step session expiration time (两步会话过期时间)
    TWO_STEP_SESSION_EXPIRATION: int
    # Authentication session expiration time (身份验证会话过期时间)
    AUTHENTICATION_SESSION_EXPIRATION: int
    # Allow login with username flag (允许使用用户名登录标志)
    ALLOW_LOGIN_WITH_USERNAME: bool
    INITIAL_ADMIN_EMAIL: str  # Initial admin email (初始管理员电子邮件)
    INITIAL_ADMIN_PASSWORD: str  # Initial admin password (初始管理员密码)
    DATABASE_URL: str  # Test database URL (测试数据库 URL)

    def load_environment_variables(self, load_env="SANIC_SECURITY_") -> None:
        """
        函数“load_environment_variables”加载以指定前缀开头的环境变量，并将其值转换为适当的数据类型。

        :param load_env: `load_env` 参数是一个字符串，表示要加载的环境变量的前缀。在此代码中，它设置为“SANIC_SECURITY_”。
        """
        for key, value in environ.items():
            if not key.startswith(load_env):
                continue

            _, config_key = key.split(load_env, 1)

            for converter in (int, float, str_to_bool, str):
                with suppress(ValueError):
                    self[config_key] = converter(value)
                    break

    def __init__(self):
        super().__init__(DEFAULT_CONFIG)
        self.__dict__ = self
        self.load_environment_variables()


# 创建一个 Config 实例
config = Config()
