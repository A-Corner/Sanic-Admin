#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
配置模块，集中管理所有配置项
"""
import os
from pathlib import Path
from typing import Dict, Any, List

from sanic.config import Config

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

class DefaultConfig(Config):
    """
    默认配置
    """
    # 应用名称
    APP_NAME = "Sanic-Admin"
    
    # 调试模式
    DEBUG = False
    
    # 密钥
    SECRET_KEY = "your-secret-key"
    
    # 数据库配置
    DB_HOST = "localhost"
    DB_PORT = 3306
    DB_USER = "root"
    DB_PASSWORD = ""
    DB_NAME = "sanic_admin"
    DB_CHARSET = "utf8mb4"
    DATABASE_URL = f"mysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset={DB_CHARSET}"
    
    # 会话配置
    SESSION_COOKIE_NAME = "sanic_admin_session"
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "lax"
    
    # 上传文件配置
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "uploads")
    ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    
    # 日志配置
    LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
    LOG_LEVEL = "INFO"
    
    # CORS配置
    CORS_ORIGINS = ["*"]
    
    # 分页配置
    DEFAULT_PAGE_SIZE = 10
    MAX_PAGE_SIZE = 100
    
    # 认证配置
    ACCESS_TOKEN_EXPIRE = 3600  # 1小时，以秒为单位
    REFRESH_TOKEN_EXPIRE = 604800  # 7天，以秒为单位
    
    # 密码哈希配置
    PASSWORD_SALT = "your-password-salt"
    
    # 邮件配置
    MAIL_SERVER = "smtp.example.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = "your-email@example.com"
    MAIL_PASSWORD = "your-email-password"
    MAIL_DEFAULT_SENDER = "your-email@example.com"
    
    # 缓存配置
    CACHE_TYPE = "memory"  # 可选 "memory" 或 "redis"
    CACHE_KEY_PREFIX = "sanic_admin"  # 缓存键前缀
    CACHE_DEFAULT_TIMEOUT = 300  # 默认缓存过期时间，单位为秒
    
    # Redis配置（用于Redis缓存和会话存储）
    REDIS_HOST = "localhost"
    REDIS_PORT = 6379
    REDIS_DB = 0
    REDIS_PASSWORD = None
    REDIS_SOCKET_TIMEOUT = 3
    
    # 是否使用缓存
    USE_CACHE = True
    
    # 路由缓存配置
    ROUTE_CACHE_ENABLED = True
    ROUTE_CACHE_TIMEOUT = 60  # 路由缓存过期时间，单位为秒


class DevelopmentConfig(DefaultConfig):
    """
    开发环境配置
    """
    DEBUG = True
    SECRET_KEY = "dev-secret-key"
    SESSION_COOKIE_SECURE = False
    ROUTE_CACHE_ENABLED = False
    
    # 数据库配置
    DB_HOST = "localhost"
    DB_PORT = 3306
    DB_USER = "root"
    DB_PASSWORD = "password"
    DB_NAME = "sanic_admin_dev"
    DATABASE_URL = f"mysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset={DefaultConfig.DB_CHARSET}"


class TestingConfig(DefaultConfig):
    """
    测试环境配置
    """
    TESTING = True
    DEBUG = True
    SECRET_KEY = "test-secret-key"
    SESSION_COOKIE_SECURE = False
    ROUTE_CACHE_ENABLED = False
    
    # 数据库配置 - 使用内存数据库
    DATABASE_URL = "sqlite:///:memory:"
    
    # 使用内存缓存
    CACHE_TYPE = "memory"
    
    # 禁用邮件发送
    MAIL_SUPPRESS_SEND = True


class ProductionConfig(DefaultConfig):
    """
    生产环境配置
    """
    DEBUG = False
    
    # 数据库配置从环境变量读取
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", "3306"))
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_NAME = os.getenv("DB_NAME", "sanic_admin_prod")
    DATABASE_URL = f"mysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset={DefaultConfig.DB_CHARSET}"
    
    # 密钥从环境变量读取
    SECRET_KEY = os.getenv("SECRET_KEY", "prod-secret-key")
    
    # 缓存配置
    CACHE_TYPE = os.getenv("CACHE_TYPE", "redis")
    
    # Redis配置
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB = int(os.getenv("REDIS_DB", "0"))
    REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)
    
    # 邮件配置
    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.example.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True") == "True"
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", "")


# 配置字典
config_dict: Dict[str, DefaultConfig] = {
    "development": DevelopmentConfig(),
    "testing": TestingConfig(),
    "production": ProductionConfig(),
    "default": DevelopmentConfig(),
}

# 当前配置
config = config_dict.get(os.getenv("SANIC_ENV", "default"))

class BaseConfig:
    """基础配置类"""
    
    # 安全配置
    SECRET = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAww3pEiUx6wMFawJNAHCI80Qj3eyrP6Yx3LNNluQZXMyZkd+6ugBN9e1hw7v2z2PwmJENhYrqbBHU4vHCHEEZjdZIQRqwriFpeeoqMA1
ecgwJz3fOuYo6WrUbS6pEyJ9vtjh5TaeZLzER+KIK2uvsjsQnFVt41hh3Xd+tR9p+QXT8aRep9hp4XLF87QlDVDrZIStfVn25+ZfSfKH+WYBUglZBmz/K6uW
41mSRuuH3Pu/lnPgGvsxtT7KE8dkbyrI+Tyg0pniOYdxBxgpu06S6LTC8Zou0U0SGd6uOMUHT86H8uxbDTa8CNiGI251QMHlkstd6FFYu5lJQcuppOm79iQI
DAQABAoIBAACRz1RBMmV9ruIFWtcNu24u1SBw8FAniW4SGuPBbxeg1KcmOlegx3IdkBhG7j9hBF5+S/3ZhGTGhYdglYcS2aSMK0Q6ofd4NDMk+bzlIdEZNTV
bTnlle1vBjVjxOoIP7aL6mC/HFO7T+SYqjIGkjsxYFHf1DFu0nHS5OA/rOoEt1SZA5DO0dCd1IjuPvKsvJIRErjnFuW6bs9K7XNpE2gHKvtvzVFRQC2F7AY7
b45cx6QZ08yCbToITRI59RzGgrpqIsJI0N5yT96DUALQDkAJz4XzhS8+bHoCDGeTPfJLq4xXcLrtFSk5Mhp4eIOPCI/fv3IO8JnSopgeP+y+NeFMCgYEA/rq
0R5v9JuxtcbXsFXua5KWoDojOvHkeP93F5eGSDu8iRo/4zhyHWGhZuMIuMARAOJ7tAyWxDTzoSILhC4+fF6WQJKiBIlLLGXFyJ9qgq2eN+Z/b9+k6PotQV9z
unmIN8vuCrtPBlVbOMrofGHG85zSDyDDDUXZoh7ko8tJ3nosCgYEAxAb/8E/fmEADxJZSFoqwlElXm6h7sfThrhjf12ENwBv7AvH8XsiNVQsIGnoVxeHQJ7U
0pROucD/iykf8I9+ou9ZBQyfoRJiOkzExeMWEyhmGyGmcNCZ1kKK/RZu6Bks/EoqnpVH9bUjjAwSXeFRZE3zfsAclQr3BYjqFjQzuSrsCgYEA7RhLBPwkPT6
C//wcqkJKgdfO/PhJtRPnG/sIYFf84vmiJZuMMgxLzfYSzO2wn/DU9d63LN7AVVoDurpXTbN4mUH5UKWmzJPThvMZFg9gzSmt9FLfI3lqRRzWw3FYiQMriKa
hlKh03tPVSVID73SuJ2Wx43u/0OstkGa/voQ34tECgYA+G2mjnerdtgp7kpTXh4GCueoD61GlhEyseD0TZDCTGUpiGIE5FpmQxDoBCYU0eOMWcZcIZj/yWIt
mQ4BjbU1slel/eXlhomQpxoBCH3J/Ba9qd+uBql29QZMQXtKFg/mryjprapq8sUcbgazr9u1x+zJz9w+bIbvPf3MoyVwGWQKBgQDXKMG9fV+/61imgsOZTyd
2ld8MnIWAeUGgk5e6P+niAOPGFSPue3FgGvLURiJtuu05dM9U9pQhtGVrCwHcT9Yixiwpnyw31DQp3uU91DhrtHyRIf3H/ywrWLwY4Z+TsktW6UPoe2cyGbN
1G1CHHo/vq8zPNkVWmhciIUeHR3YJbw==
-----END RSA PRIVATE KEY-----
"""
    
    # 公钥
    PUBLIC_SECRET = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAww3pEiUx6wMFawJNAHCI80Qj3eyrP6Yx3LNNluQZXMyZkd+6ugBN9e1hw7v2z2PwmJENhYrqbBHU
4vHCHEEZjdZIQRqwriFpeeoqMA1ecgwJz3fOuYo6WrUbS6pEyJ9vtjh5TaeZLzER+KIK2uvsjsQnFVt41hh3Xd+tR9p+QXT8aRep9hp4XLF87QlDVDrZIStf
Vn25+ZfSfKH+WYBUglZBmz/K6uW41mSRuuH3Pu/lnPgGvsxtT7KE8dkbyrI+Tyg0pniOYdxBxgpu06S6LTC8Zou0U0SGd6uOMUHT86H8uxbDTa8CNiGI251Q
MHlkstd6FFYu5lJQcuppOm79iQIDAQAB
-----END PUBLIC KEY-----
"""
    
    # 认证与权限配置
    INITIAL_ADMIN_EMAIL = "SAdmin@Sanic.com"
    INITIAL_ADMIN_PASSWORD = "SAdmin@123"
    ALLOW_LOGIN_WITH_USERNAME = True
    SESSION_SECURE = False
    SESSION_ENCODING_ALGORITHM = "RS256"
    AUTHENTICATION_SESSION_EXPIRATION = 604800  # 7天
    
    # 验证码配置
    CAPTCHA_FONT = f"frontend/static/fonts/{FONT_LIST[1]}"
    
    # 应用配置
    HOST = "127.0.0.1"
    PORT = 22222
    WORKERS = 1
    AUTO_RELOAD = False


class Config:
    """配置工厂类"""
    
    @staticmethod
    def get_config(config_name):
        """
        根据名称获取对应的配置类
        
        Args:
            config_name: 配置名称
            
        Returns:
            配置类
        """
        config_mapping = {
            'development': DevelopmentConfig,
            'testing': TestingConfig,
            'production': ProductionConfig
        }
        
        return config_mapping.get(config_name, DevelopmentConfig) 