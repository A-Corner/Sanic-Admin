#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
统一错误处理：自定义异常、Sanic 框架异常与未捕获异常。

由原 ``app/middleware.py`` 的 ``register_error_middleware`` 迁入。
"""

import traceback

from sanic import Request, Sanic, response
from sanic.exceptions import SanicException
from sanic.log import logger

from app.services.exceptions import BaseError


def setup_error_handlers(app: Sanic) -> None:
    @app.exception(BaseError)
    async def handle_custom_exception(request: Request, exception: BaseError):
        return response.json(exception.to_dict(), status=exception.status_code)

    @app.exception(SanicException)
    async def handle_sanic_exception(request: Request, exception: SanicException):
        status_code = getattr(exception, 'status_code', 500)
        return response.json(
            {"error": "SANIC_ERROR", "message": str(exception), "status": status_code},
            status=status_code,
        )

    @app.exception(Exception)
    async def handle_generic_exception(request: Request, exception: Exception):
        logger.error(f"未处理的异常: {str(exception)}")
        logger.error(traceback.format_exc())
        error_dict = {"error": "INTERNAL_ERROR", "message": "服务器内部错误", "status": 500}
        if app.config.DEBUG:
            error_dict["detail"] = str(exception)
            error_dict["traceback"] = traceback.format_exc()
        return response.json(error_dict, status=500)
