#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
配置模块，集中管理所有配置项。

配置契约（B1a 定义，其余模块依赖）：

* 环境由 ``SANIC_ENV`` 决定（development / testing / production，默认 development）。
* ``get_config(name=None)`` 返回对应环境的配置对象（属性访问）；``production`` 缺少必需密钥时
  抛出 ``ConfigError``。
* ``settings`` / ``config`` 为当前环境（``SANIC_ENV``）的配置对象，供其他模块 import。
* ``BaseConfig`` 保留给认证/会话模块使用：``SECRET``（JWT 私钥）、``PUBLIC_SECRET``、
  ``INITIAL_ADMIN_*`` 等，全部来自环境变量，仓库内不含任何密钥。
* ``create_app(config)`` 的 ``config`` 可以是环境名字符串、配置类/对象或字典。

必需密钥环境变量（production 缺失即拒绝启动）：

* ``JWT_PRIVATE_KEY`` / ``JWT_PUBLIC_KEY``：RS256 PEM（换行可写成字面量 ``\\n``）；
  仅给私钥时公钥由私钥推导。
* ``INITIAL_ADMIN_PASSWORD``：初始管理员口令。

development/testing 缺失时自动生成临时值并输出 warning（进程重启后失效）；
production 缺失时抛出 ``ConfigError``（入口负责退出）。

可选环境变量（缺失不报错，取空字符串）：

* ``SECRET_KEY``：应用密钥。**当前实现中不参与任何签名或加密**——JWT 实际使用
  ``BaseConfig.SECRET``（RS256 私钥，来自 ``JWT_PRIVATE_KEY``）。设置它不会增强安全性，
  因此不再作为 production 启动的必需项。
* ``PASSWORD_SALT``：口令盐。**当前实现中不参与口令哈希**——argon2 的
  ``PasswordHasher()`` 自行生成随机 salt 并编入哈希串。同样不再作为必需项。
"""
import logging
import os
import secrets
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("sanic.error")

# 基础目录
BASE_DIR = Path(__file__).parent.parent.absolute()

# 字体文件列表
FONT_LIST = [
    "Chalkduster.ttf",
    "Courier New.ttf",
    "Courier New Bold.ttf",
    "Courier New Bold Italic.ttf",
    "Courier New Italic.ttf",
]

VALID_ENVS = ("development", "testing", "production")


class ConfigError(RuntimeError):
    """配置不合法或缺少必需项（例如生产环境缺少密钥）。"""


def _normalize_env(name: Optional[str]) -> str:
    name = (name or os.getenv("SANIC_ENV") or "development").strip().lower()
    if name == "default":
        name = "development"
    if name not in VALID_ENVS:
        raise ConfigError(f"未知的环境名 {name!r}，可选值: {', '.join(VALID_ENVS)}")
    return name


def _env_secret(var: str, env: str, generator, description: str) -> str:
    """
    从环境变量读取密钥。

    production 缺失 -> ConfigError；development/testing 缺失 -> 生成临时值并 warning。
    """
    value = os.getenv(var)
    if value:
        return value
    if env == "production":
        raise ConfigError(f"生产环境必须通过环境变量 {var} 提供{description}")
    logger.warning(
        "环境变量 %s 未设置，已为 %s 环境生成临时%s（进程重启后失效，请勿用于生产）",
        var, env, description,
    )
    value = generator()
    # 写回环境变量：Sanic 会再启动 worker 子进程重新 import 本模块，
    # 共享同一份临时密钥，避免各进程各生成一份（导致会话签名不一致、口令重复打印）
    os.environ[var] = value
    return value


def _generate_rsa_private_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()


def _derive_public_pem(private_pem: str) -> str:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _load_private_key(pem: str):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    try:
        key = serialization.load_pem_private_key(pem.encode(), password=None)
    except Exception as e:
        raise ConfigError(f"JWT_PRIVATE_KEY 无法解析为 PEM 私钥（{type(e).__name__}）")
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ConfigError("JWT_PRIVATE_KEY 必须是 RSA 私钥（RS256）")
    return key


def load_jwt_keys(env: str) -> Tuple[str, str]:
    """
    返回 (私钥 PEM, 公钥 PEM)，并校验私钥可解析、公钥可解析且与私钥配对；
    任一失败统一抛 ConfigError。
    """
    from cryptography.hazmat.primitives import serialization

    private = os.getenv("JWT_PRIVATE_KEY")
    if private:
        private = private.replace("\\n", "\n")
    else:
        private = _env_secret("JWT_PRIVATE_KEY", env, _generate_rsa_private_pem, " JWT 签名私钥")
    private_key = _load_private_key(private)

    public = os.getenv("JWT_PUBLIC_KEY")
    if not public:
        return private, _derive_public_pem(private)
    public = public.replace("\\n", "\n")
    try:
        public_key = serialization.load_pem_public_key(public.encode())
    except Exception as e:
        raise ConfigError(f"JWT_PUBLIC_KEY 无法解析为 PEM 公钥（{type(e).__name__}）")
    if public_key.public_numbers() != private_key.public_key().public_numbers():
        raise ConfigError("JWT_PUBLIC_KEY 与 JWT_PRIVATE_KEY 不配对")
    return private, public


class DefaultConfig:
    """
    默认配置（不含任何密钥；密钥在 get_config 时按环境注入）
    """
    ENV = "default"
    APP_NAME = "Sanic-Admin"
    APP_VERSION = "1.0.0"

    DEBUG = False
    TESTING = False

    # 服务监听
    HOST = "127.0.0.1"
    PORT = 22222
    WORKERS = 1
    AUTO_RELOAD = False

    # 可选密钥（get_config 注入；当前不参与任何签名或哈希，缺失时为空字符串）
    SECRET_KEY = ""
    PASSWORD_SALT = ""

    # 数据库配置
    DB_HOST = "localhost"
    DB_PORT = 3306
    DB_USER = "root"
    DB_PASSWORD = ""
    DB_NAME = "sanic_admin"
    DB_CHARSET = "utf8mb4"
    DATABASE_URL = ""  # get_config 中按上述字段拼装，可被 DATABASE_URL 环境变量覆盖

    # 会话配置
    SESSION_COOKIE_NAME = "sanic_admin_session"
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "lax"

    # 目录
    STATIC_DIR = str(BASE_DIR / "static")
    UPLOAD_DIR = str(BASE_DIR / "uploads")
    UPLOAD_FOLDER = UPLOAD_DIR  # 兼容旧名称
    # AMIS 管理界面静态目录（由后端同源托管；留空则不挂载）
    AMIS_DIR = str(BASE_DIR / "amis")
    ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

    # 日志配置
    LOG_DIR = str(BASE_DIR / "logs")
    LOG_LEVEL = "INFO"

    # CORS配置（注意：不能叫 CORS_ORIGINS，会与 sanic-ext 的同名配置冲突；列表中含 "*" 表示允许任意来源，此时不发送 credentials 头）
    CORS_ALLOWED_ORIGINS = ["*"]
    CORS = False  # 关闭 sanic-ext 内置 CORS（若已安装），由 app.middleware.security_middleware 处理

    # 响应压缩
    COMPRESSION_MIN_LENGTH = 1024
    COMPRESSION_LEVEL = 6

    # 分页配置
    DEFAULT_PAGE_SIZE = 10
    MAX_PAGE_SIZE = 100

    # 认证配置
    ACCESS_TOKEN_EXPIRE = 3600  # 1小时，以秒为单位
    REFRESH_TOKEN_EXPIRE = 604800  # 7天，以秒为单位

    # 邮件配置
    MAIL_SERVER = "smtp.example.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = ""
    MAIL_PASSWORD = ""
    MAIL_DEFAULT_SENDER = ""

    # 缓存配置
    CACHE_TYPE = "memory"  # 可选 "memory" 或 "redis"
    CACHE_KEY_PREFIX = "sanic_admin"
    CACHE_DEFAULT_TIMEOUT = 300

    # Redis配置（用于Redis缓存和会话存储）
    REDIS_HOST = "localhost"
    REDIS_PORT = 6379
    REDIS_DB = 0
    REDIS_PASSWORD = None
    REDIS_SOCKET_TIMEOUT = 3

    # API 文档路由（/swagger、/swagger.json、/redoc、/docs/*）；production 默认关闭
    ENABLE_API_DOCS = True
    # 登录是否要求二次验证（环境变量 REQUIRE_TWO_FACTOR=true 开启）
    REQUIRE_TWO_FACTOR = False

    USE_CACHE = True
    ROUTE_CACHE_ENABLED = True
    ROUTE_CACHE_TIMEOUT = 60


class DevelopmentConfig(DefaultConfig):
    """开发环境配置"""
    ENV = "development"
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    ROUTE_CACHE_ENABLED = False
    DB_NAME = "sanic_admin_dev"
    # 开发环境默认使用本地 SQLite，免装 MySQL
    DATABASE_URL = f"sqlite://{BASE_DIR / 'sanic_admin_dev.sqlite3'}"


class TestingConfig(DefaultConfig):
    """测试环境配置"""
    ENV = "testing"
    TESTING = True
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    ROUTE_CACHE_ENABLED = False
    DATABASE_URL = "sqlite://:memory:"
    CACHE_TYPE = "memory"
    MAIL_SUPPRESS_SEND = True


class ProductionConfig(DefaultConfig):
    """生产环境配置（全部来自环境变量）"""
    ENV = "production"
    DEBUG = False
    # 生产环境默认不允许任何跨域来源，必须通过 CORS_ALLOWED_ORIGINS 显式配置（逗号分隔）
    CORS_ALLOWED_ORIGINS = []
    ENABLE_API_DOCS = False
    DB_NAME = "sanic_admin_prod"
    CACHE_TYPE = "redis"


_CONFIG_CLASSES = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


_TRUE_VALUES = ("1", "true", "yes", "on")
_FALSE_VALUES = ("0", "false", "no", "off", "")


def _bool_env(var: str, default: bool) -> bool:
    raw = os.getenv(var)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ConfigError(f"环境变量 {var} 必须为布尔值（true/false），当前值: {raw!r}")


def _int_env(var: str, default: int) -> int:
    raw = os.getenv(var)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(f"环境变量 {var} 必须为整数，当前值: {raw!r}")


def get_config(name: Optional[str] = None):
    """
    构造并返回指定环境的配置对象。

    Raises:
        ConfigError: 环境名非法，或 production 缺少必需的密钥。
    """
    env = _normalize_env(name)
    cls = _CONFIG_CLASSES[env]
    cfg = cls()

    # 可选密钥：只来自环境变量，缺失时为空字符串。
    # 这两个值当前不参与任何签名或加密（JWT 用 JWT_PRIVATE_KEY/RS256，口令哈希用 argon2 自带随机 salt），
    # 因此不再走 _env_secret 的 production fail-closed 检查——否则只是"必填但无人使用"的假安全项。
    cfg.SECRET_KEY = os.getenv("SECRET_KEY", "")
    cfg.PASSWORD_SALT = os.getenv("PASSWORD_SALT", "")

    # 通用服务/数据库/缓存环境变量覆盖
    cfg.HOST = os.getenv("HOST", cfg.HOST)
    cfg.PORT = _int_env("PORT", cfg.PORT)
    cfg.DB_HOST = os.getenv("DB_HOST", cfg.DB_HOST)
    cfg.DB_PORT = _int_env("DB_PORT", cfg.DB_PORT)
    cfg.DB_USER = os.getenv("DB_USER", cfg.DB_USER)
    cfg.DB_PASSWORD = os.getenv("DB_PASSWORD", cfg.DB_PASSWORD)
    cfg.DB_NAME = os.getenv("DB_NAME", cfg.DB_NAME)
    if not cfg.DATABASE_URL:
        cfg.DATABASE_URL = (
            f"mysql://{cfg.DB_USER}:{cfg.DB_PASSWORD}@{cfg.DB_HOST}:{cfg.DB_PORT}"
            f"/{cfg.DB_NAME}?charset={cfg.DB_CHARSET}"
        )
    cfg.DATABASE_URL = os.getenv("DATABASE_URL", cfg.DATABASE_URL)
    # 静态目录：AMIS 管理界面（后端同源托管）。置空字符串则不挂载。
    cfg.AMIS_DIR = os.getenv("AMIS_DIR", cfg.AMIS_DIR)
    cfg.CACHE_TYPE = os.getenv("CACHE_TYPE", cfg.CACHE_TYPE)
    cfg.REDIS_HOST = os.getenv("REDIS_HOST", cfg.REDIS_HOST)
    cfg.REDIS_PORT = _int_env("REDIS_PORT", cfg.REDIS_PORT)
    cfg.REDIS_DB = _int_env("REDIS_DB", cfg.REDIS_DB)
    cfg.REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", cfg.REDIS_PASSWORD)
    cfg.MAIL_SERVER = os.getenv("MAIL_SERVER", cfg.MAIL_SERVER)
    cfg.MAIL_PORT = _int_env("MAIL_PORT", cfg.MAIL_PORT)
    cfg.MAIL_USE_TLS = _bool_env("MAIL_USE_TLS", cfg.MAIL_USE_TLS)
    cfg.MAIL_USERNAME = os.getenv("MAIL_USERNAME", cfg.MAIL_USERNAME)
    cfg.MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", cfg.MAIL_PASSWORD)
    cfg.MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", cfg.MAIL_DEFAULT_SENDER)
    cfg.ENABLE_API_DOCS = _bool_env("ENABLE_API_DOCS", cfg.ENABLE_API_DOCS)
    cfg.REQUIRE_TWO_FACTOR = _bool_env("REQUIRE_TWO_FACTOR", cfg.REQUIRE_TWO_FACTOR)
    origins = os.getenv("CORS_ALLOWED_ORIGINS")
    if origins:
        cfg.CORS_ALLOWED_ORIGINS = [o.strip() for o in origins.split(",") if o.strip()]
    return cfg


def config_to_dict(cfg: Any) -> Dict[str, Any]:
    """把配置对象/类转换为 {大写键: 值} 字典，供 Sanic app.config.update 使用。"""
    if isinstance(cfg, dict):
        return dict(cfg)
    return {k: getattr(cfg, k) for k in dir(cfg) if k.isupper()}


# 当前环境配置。production 缺少密钥时在 import 阶段即抛出 ConfigError（fail fast）。
_ACTIVE_ENV = _normalize_env(None)
settings = get_config(_ACTIVE_ENV)
config = settings


def _generate_admin_password(env: str) -> str:
    """生成临时初始管理员口令；仅 development 在控制台 stdout 打印一次（不进入 logger/日志文件）。"""
    password = secrets.token_urlsafe(12)
    if env == "development":
        print(
            "\n" + "=" * 64 + "\n"
            "[开发环境] 已自动生成临时初始管理员口令（仅显示这一次，重启后失效）:\n"
            f"    账号: {os.getenv('INITIAL_ADMIN_EMAIL', 'SAdmin@Sanic.com')}\n"
            f"    口令: {password}\n"
            "设置环境变量 INITIAL_ADMIN_PASSWORD 可固定口令。\n"
            + "=" * 64 + "\n",
            flush=True,
        )
    return password


MIN_ADMIN_PASSWORD_LENGTH = 8


def _initial_admin_password(env: str) -> str:
    """
    初始管理员口令：显式提供（环境变量）时至少 8 位，否则抛 ConfigError；
    缺失时 production 报错、development/testing 生成临时值。
    """
    explicit = os.getenv("INITIAL_ADMIN_PASSWORD")
    if explicit and len(explicit) < MIN_ADMIN_PASSWORD_LENGTH:
        raise ConfigError(f"INITIAL_ADMIN_PASSWORD 至少需要 {MIN_ADMIN_PASSWORD_LENGTH} 位")
    return _env_secret(
        "INITIAL_ADMIN_PASSWORD", env,
        lambda: _generate_admin_password(env), "初始管理员口令",
    )


def _captcha_font() -> Optional[str]:
    """验证码字体路径；文件不存在时返回 None（由 captcha 库使用自带字体）。"""
    path = BASE_DIR / "frontend" / "static" / "fonts" / FONT_LIST[1]
    return str(path) if path.is_file() else None


class BaseConfig:
    """认证/会话模块使用的配置（密钥来自环境变量）"""

    SECRET, PUBLIC_SECRET = load_jwt_keys(_ACTIVE_ENV)

    # 认证与权限配置
    INITIAL_ADMIN_EMAIL = os.getenv("INITIAL_ADMIN_EMAIL", "SAdmin@Sanic.com")
    INITIAL_ADMIN_PASSWORD = _initial_admin_password(_ACTIVE_ENV)
    ALLOW_LOGIN_WITH_USERNAME = True
    SESSION_SECURE = _ACTIVE_ENV == "production"
    SESSION_ENCODING_ALGORITHM = "RS256"
    AUTHENTICATION_SESSION_EXPIRATION = 604800  # 7天

    # 验证码配置
    CAPTCHA_FONT = _captcha_font()

    # 应用配置（与 settings 保持一致，兼容旧用法）
    HOST = settings.HOST
    PORT = settings.PORT
    WORKERS = settings.WORKERS
    DEBUG = settings.DEBUG
    AUTO_RELOAD = settings.AUTO_RELOAD


class Config:
    """配置工厂类（兼容旧接口）"""

    @staticmethod
    def get_config(config_name):
        """根据名称获取对应环境的配置对象"""
        return get_config(config_name)
