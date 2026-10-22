#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SanicAdmin 应用入口点

环境由 SANIC_ENV 决定（默认 development）；production 必须通过环境变量提供
JWT_PRIVATE_KEY（RS256 私钥；可选 JWT_PUBLIC_KEY，未提供时由私钥推导）与
INITIAL_ADMIN_PASSWORD，缺失时直接退出。

SECRET_KEY 与 PASSWORD_SALT 是可选的兼容项：当前实现中不参与任何签名或加密
（JWT 用 JWT_PRIVATE_KEY/RS256，口令哈希用 argon2 自带的随机 salt），设置它们
不会增强安全性，因此不再是 production 启动的必需项。
"""
import sys

try:
    from app import create_app
    from app.config import settings
    app = create_app(settings)
except Exception as exc:  # noqa: BLE001
    if exc.__class__.__name__ == "ConfigError":
        sys.exit(f"配置错误: {exc}")
    raise

if __name__ == "__main__":
    app.run(
        host=settings.HOST,
        port=settings.PORT,
        workers=settings.WORKERS,
        debug=settings.DEBUG,
        auto_reload=settings.AUTO_RELOAD,
    )
