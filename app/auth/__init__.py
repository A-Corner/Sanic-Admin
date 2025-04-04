#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
认证和授权模块
"""
from sanic import Sanic
from app.auth.routes import (
    auth_bp, 
    capt_bp, 
    two_step_bp, 
    role_bp, 
    account_bp
)


def register_auth_blueprints(app: Sanic):
    """
    注册所有认证相关的蓝图
    
    Args:
        app: Sanic应用实例
    """
    app.blueprint(auth_bp)
    app.blueprint(capt_bp)
    app.blueprint(two_step_bp)
    app.blueprint(role_bp)
    app.blueprint(account_bp) 