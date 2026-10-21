#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SanicAdmin 应用入口点

环境由 SANIC_ENV 决定（默认 development）；production 必须通过环境变量提供
SECRET_KEY / JWT_PRIVATE_KEY / INITIAL_ADMIN_PASSWORD / PASSWORD_SALT，缺失时直接退出。
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
