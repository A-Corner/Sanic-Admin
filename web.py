# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# File       : web.py
# Time       ：12/9/2023 9:01 pm
# Author     ：author A-Corner
# version    ：python 3.11
# Description：
"""
import jinja2
from sanic_jinja2 import SanicJinja2
from sanic import Sanic
from sanic import Blueprint
from auth import requires_authentication


login_bp = Blueprint('login', url_prefix='/login')
index_bp = Blueprint('index', url_prefix='/index')


@login_bp.route('/', methods=['GET', 'POST'])
async def login_form(request):
    app = Sanic.get_app()
    jinja = SanicJinja2(app, loader=jinja2.FileSystemLoader('amis'))
    return jinja.render('login.html', request)


@index_bp.route('/')  # type: ignore
@requires_authentication()
async def index_form(request):
    app = Sanic.get_app()
    jinja = SanicJinja2(app, loader=jinja2.FileSystemLoader('amis'))
    # 将 AMIS 表单的 JSON 配置传递给 Jinja2 模板
    # 配置方式为amis 可视化编辑器的json配置，把{ }换成""" """即可"
    return jinja.render('site.html', request,)
