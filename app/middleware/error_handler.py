#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
统一错误处理：自定义异常、Sanic 框架异常与未捕获异常。

所有错误响应体统一为 ``{"success": false, "message": ..., "error": "<CODE>"}``。
非 DEBUG 模式下不向客户端返回原始异常文本或堆栈，原始信息只写服务端日志。
"""

import traceback

from sanic import Request, Sanic, response
from sanic.exceptions import SanicException
from sanic.log import logger

from app.services.exceptions import BaseError


def _error_body(message: str, error_code: str) -> dict:
    """构造统一格式的错误响应体。"""
    return {"success": False, "message": message, "error": error_code}


def setup_error_handlers(app: Sanic) -> None:
    @app.exception(BaseError)
    async def handle_custom_exception(request: Request, exception: BaseError):
        # 业务异常（认证/授权/校验/资源不存在等）本身携带可安全展示的文案
        return response.json(
            _error_body(exception.message, exception.error_code),
            status=exception.status_code,
        )

    @app.exception(SanicException)
    async def handle_sanic_exception(request: Request, exception: SanicException):
        status_code = getattr(exception, 'status_code', 500)
        error_code = {
            404: "NOT_FOUND",
            405: "METHOD_NOT_ALLOWED",
            400: "BAD_REQUEST",
        }.get(status_code, "SANIC_ERROR")
        message = {
            404: "请求的资源不存在",
            405: "请求方法不被允许",
            400: "请求参数不合法",
        }.get(status_code, "请求处理失败")
        logger.warning(f"框架异常 {status_code}: {str(exception)}")
        return response.json(_error_body(message, error_code), status=status_code)

    @app.exception(Exception)
    async def handle_generic_exception(request: Request, exception: Exception):
        logger.error(f"未处理的异常: {str(exception)}")
        logger.error(traceback.format_exc())
        error_dict = _error_body("服务器内部错误", "INTERNAL_ERROR")
        if app.config.get("DEBUG"):
            error_dict["detail"] = str(exception)
            error_dict["traceback"] = traceback.format_exc()
        return response.json(error_dict, status=500)
