#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
API路由模块，定义所有API端点
"""
from sanic import Blueprint, Sanic
from app.api.resources.account import account_api
from app.api.resources.role import role_api


# 创建API蓝图
api_bp = Blueprint('api', url_prefix='/api')

# 各资源API蓝图
api_bp.blueprint(account_api)
api_bp.blueprint(role_api)


def register_api_blueprints(app: Sanic):
    """
    注册所有API相关的蓝图
    
    Args:
        app: Sanic应用实例
    """
    app.blueprint(api_bp) 