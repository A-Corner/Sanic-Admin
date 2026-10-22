#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Swagger UI集成模块

提供Swagger UI界面，用于可视化浏览API文档
"""

import os
import re
from typing import Dict, Any, Optional
from sanic import Sanic
from sanic.response import html, redirect

# Swagger UI版本
SWAGGER_UI_VERSION = "4.15.5"


def setup_swagger_ui(app: Sanic, swagger_url: str = "/swagger", 
                     swagger_json_url: str = "/swagger.json") -> None:
    """
    设置Swagger UI界面
    
    Args:
        app: Sanic应用实例
        swagger_url: Swagger UI界面URL
        swagger_json_url: OpenAPI规范JSON文件URL
    """
    # 确保URL以斜杠开头
    if not swagger_url.startswith("/"):
        swagger_url = f"/{swagger_url}"
    
    if not swagger_json_url.startswith("/"):
        swagger_json_url = f"/{swagger_json_url}"
    
    # 注册Swagger UI路由
    @app.route(swagger_url)
    async def swagger_ui(request):
        return redirect(f"{swagger_url}/index.html")
    
    @app.route(f"{swagger_url}/index.html")
    async def swagger_ui_html(request):
        return html(_get_swagger_ui_html(swagger_json_url))


def _get_swagger_ui_html(swagger_json_url: str) -> str:
    """
    生成Swagger UI HTML页面
    
    Args:
        swagger_json_url: OpenAPI规范JSON文件URL
        
    Returns:
        Swagger UI HTML页面内容
    """
    return f"""
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <title>Sanic-Admin API文档</title>
        <link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/{SWAGGER_UI_VERSION}/swagger-ui.css">
        <link rel="icon" type="image/png" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/{SWAGGER_UI_VERSION}/favicon-32x32.png" sizes="32x32" />
        <link rel="icon" type="image/png" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/{SWAGGER_UI_VERSION}/favicon-16x16.png" sizes="16x16" />
        <style>
            html {{
                box-sizing: border-box;
                overflow: -moz-scrollbars-vertical;
                overflow-y: scroll;
            }}
            
            *,
            *:before,
            *:after {{
                box-sizing: inherit;
            }}
            
            body {{
                margin: 0;
                background: #fafafa;
            }}
            
            .swagger-ui .topbar {{
                background-color: #4f46e5;
            }}
            
            .swagger-ui .info .title {{
                color: #4f46e5;
            }}
            
            .swagger-ui .btn.authorize {{
                background-color: #4f46e5;
                color: #fff;
            }}
            
            .swagger-ui .btn.authorize svg {{
                fill: #fff;
            }}
        </style>
    </head>
    <body>
        <div id="swagger-ui"></div>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/{SWAGGER_UI_VERSION}/swagger-ui-bundle.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/{SWAGGER_UI_VERSION}/swagger-ui-standalone-preset.js"></script>
        <script>
            window.onload = function() {{
                const ui = SwaggerUIBundle({{
                    url: "{swagger_json_url}",
                    dom_id: "#swagger-ui",
                    deepLinking: true,
                    presets: [
                        SwaggerUIBundle.presets.apis,
                        SwaggerUIStandalonePreset
                    ],
                    plugins: [
                        SwaggerUIBundle.plugins.DownloadUrl
                    ],
                    layout: "StandaloneLayout",
                    docExpansion: "none",
                    tagsSorter: "alpha",
                    operationsSorter: "alpha",
                    supportedSubmitMethods: ["get", "post", "put", "delete", "patch"],
                    validatorUrl: null,
                    persistAuthorization: true
                }});
                
                window.ui = ui;
            }};
        </script>
    </body>
    </html>
    """


def get_redoc_html(swagger_json_url: str) -> str:
    """
    生成ReDoc HTML页面
    
    Args:
        swagger_json_url: OpenAPI规范JSON文件URL
        
    Returns:
        ReDoc HTML页面内容
    """
    return f"""
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <title>Sanic-Admin API文档 - ReDoc</title>
        <link rel="icon" type="image/png" href="https://cdn.jsdelivr.net/npm/redoc@next/src/favicon.png" sizes="32x32" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{
                margin: 0;
                padding: 0;
            }}
        </style>
    </head>
    <body>
        <div id="redoc"></div>
        <script src="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"></script>
        <script>
            Redoc.init('{swagger_json_url}', {{
                scrollYOffset: 0,
                hideDownloadButton: false,
                expandResponses: "all",
                pathInMiddlePanel: true
            }}, document.getElementById('redoc'));
        </script>
    </body>
    </html>
    """ 