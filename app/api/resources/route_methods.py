#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
资源路由注册辅助模块：让"方法不匹配"稳定返回 405 而不是 404/500。

背景（Sanic 23.6 的行为）
=========================
Sanic 23.6 的 ``sanic_routing.BaseRouter.resolve()`` 把 ``NoMethod``
（路径匹配上了、但方法不匹配）与 ``NotFound`` 一起吞掉，统一抛
``self.exception``（即 ``NotFound``）：

.. code-block:: python

    except (NotFound, NoMethod) as e:
        ...
        raise self.exception(str(e), path=path)   # NotFound —— 404

后果分两种：

* **静态路径**（如 ``/api/v1/accounts``）走 ``static_routes`` 分支，
  路由表里没有该方法时框架抛 ``MethodNotAllowed`` → **405**（符合预期）；
* **动态路径**（如 ``/api/v1/accounts/<id>``）走生成的匹配树，
  树里对不匹配的方法显式 ``raise NoMethod``，而 ``resolve()`` 又把它
  转成 ``NotFound`` → **404**（方法不匹配被谎报成"资源不存在"）。

另一个坑：``Blueprint.add_route(handler, uri, methods=[...])`` 遇到
``HTTPMethodView`` 处理器时，会**忽略传入的 methods**，改成"按视图类
实现了哪些方法来算路由支持哪些方法"。于是把同一个视图注册到多个 URI 时，
每个 URI 都会拿到该视图的**全部**方法；命中一个签名不匹配的处理函数时
（例如 ``PUT /accounts`` 命中需要 ``account_id`` 的 ``AccountResource.put``）
会抛 TypeError → **500**。

本模块的做法
============
1. 一律用 ``Blueprint.route(uri, methods=[...])`` 注册 —— 它原样使用传入的
   methods，不会被视图类反推覆盖；
2. 对每个 URI，除了注册视图**实际支持**的方法外，再注册一个兜底处理函数
   覆盖其余方法，显式返回 **405 Method Not Allowed**。

这样无论静态还是动态路径，方法不匹配都稳定返回 405，
不会再出现 500（缺参数）或 404（谎报不存在）。
"""

from typing import Sequence

from sanic import Blueprint
from sanic.response import json
from sanic.views import HTTPMethodView

#: Sanic 路由支持的全部 HTTP 方法（``sanic.constants.HTTP_METHODS`` 的字面量形式）。
#:
#: ``OPTIONS`` 由项目的 CORS 预检中间件在路由之前就返回 204，不走这里；
#: ``HEAD`` 由 ``HTTPMethodView.dispatch_request`` 自动回落到 ``get``，
#: 两者都不进兜底分支（见 ``register_view`` 的说明）。
ALL_HTTP_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")


def _method_not_allowed_handler(request, **kwargs):
    """
    方法不匹配时的兜底处理函数：返回统一格式的 405。

    注意：**不能**在这里做认证/授权判断 —— 路由匹配已经失败，
    处理函数拿不到视图的权限装饰器语义；405 表达的是"这个 URI 不支持
    这个方法"，与"有没有权限"无关（权限不足由视图自己返回 403）。
    """
    return json(
        {
            "success": False,
            "message": "请求方法不被允许",
            "error": "METHOD_NOT_ALLOWED",
        },
        status=405,
    )


def register_view(blueprint: Blueprint, uri: str, view: HTTPMethodView,
                  methods: Sequence[str], name: str) -> None:
    """
    把视图注册到 URI 上，并保证方法不匹配返回 405。

    Args:
        blueprint: 目标蓝图
        uri: 路由 URI（如 ``/accounts/<account_id:int>``）
        view: 视图实例
        methods: 该 URI **期望支持**的方法集合
        name: 路由名（Sanic 23.6 要求同名路由必须唯一，故兜底路由另起名字）
    """
    expected = [m.upper() for m in methods]

    # 视图实际实现了哪些方法（决定哪些方法交给视图处理）
    implemented = [m for m in expected if hasattr(view, m.lower())]

    # GET 存在时，HEAD 由 HTTPMethodView.dispatch_request 自动回落到 get，
    # 因此把 HEAD 交给视图，而不是兜底分支。
    if "GET" in implemented and "HEAD" not in implemented:
        implemented.append("HEAD")

    # 其余方法落到兜底处理函数 → 405。
    # HEAD 永不进兜底：GET 存在时它已交给视图；GET 不存在时它本就无意义
    # （交给 Sanic 处理即可，不必占用兜底名下的方法位）。
    fallback = [m for m in ALL_HTTP_METHODS
                if m not in implemented and m != "HEAD"]

    blueprint.route(uri, methods=implemented, name=name)(view.as_view())

    if fallback:
        blueprint.route(uri, methods=fallback, name=f"{name}_method_not_allowed")(
            _method_not_allowed_handler)
