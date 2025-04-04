#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Web路由模块，处理前端页面路由
"""
import jinja2
from sanic_jinja2 import SanicJinja2
from sanic import Blueprint, Sanic
from app.auth.authentication import requires_authentication


# 创建蓝图
login_bp = Blueprint('login', url_prefix='/login')
index_bp = Blueprint('index', url_prefix='/index')


@login_bp.route('/', methods=['GET', 'POST'])
async def login_form(request):
    """
    登录页面
    """
    app = Sanic.get_app()
    jinja = SanicJinja2(app, loader=jinja2.FileSystemLoader('frontend/templates'))
    return jinja.render('login.html', request)


@index_bp.route('/')
@requires_authentication()
async def index_form(request):
    """
    主页
    """
    app = Sanic.get_app()
    jinja = SanicJinja2(app, loader=jinja2.FileSystemLoader('frontend/templates'))
    return jinja.render('site.html', request)


def register_web_blueprints(app: Sanic):
    """
    注册所有Web相关的蓝图
    
    Args:
        app: Sanic应用实例
    """
    app.blueprint(login_bp)
    app.blueprint(index_bp) 