#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SanicAdmin 应用入口点
"""
from app import create_app
from app.config import BaseConfig

app = create_app('development')

if __name__ == "__main__":
    app.run(
        host=BaseConfig.HOST,
        port=BaseConfig.PORT,
        workers=BaseConfig.WORKERS,
        debug=BaseConfig.DEBUG,
        auto_reload=BaseConfig.AUTO_RELOAD
    )
