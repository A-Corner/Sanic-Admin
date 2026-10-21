# Sanic-Admin

> **项目状态（请先阅读）**
>
> - 主线正在重构中，**尚不可用于生产环境**。当前代码可能无法启动，部分模块和测试尚不可运行，下文功能描述是设计目标，不代表已经验证可用。
> - 前端方向：以 AMIS 为前端主线；`frontend/` 下的 Vue 前端为实验性，尚未完成。
> - 默认管理员口令（`SAdmin@Sanic.com` / `SAdmin@123`）**仅用于本地开发**，任何部署前必须修改。
> - JWT 签名私钥必须通过环境变量配置，不得使用仓库中提交的示例密钥。仓库历史中的示例私钥视为已泄露，请勿用于任何真实环境。
> - 安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。

Sanic-Admin是一个基于Sanic框架的高性能、可扩展的后台管理系统。

## 功能特点

- 用户认证与授权管理
- 权限控制系统
- 角色管理
- 系统设置
- 操作日志记录
- 用户资料管理
- 安全策略设置
- 高性能API设计
- 自动化API文档生成

## API文档自动生成

Sanic-Admin集成了全面的API文档自动生成功能，基于OpenAPI 3.0规范，可以通过简单的装饰器注解自动生成API文档。

### 功能介绍

- **OpenAPI规范生成**：自动收集API路由信息，生成符合OpenAPI 3.0规范的API描述文档
- **装饰器系统**：提供丰富的装饰器用于标记和注解API路由
- **Swagger UI集成**：提供交互式API文档界面，方便开发和测试
- **ReDoc支持**：提供另一种风格的API文档界面，适合阅读和参考
- **模型文档生成**：从Pydantic和Tortoise ORM模型自动生成文档模式

### 装饰器示例

```python
from app.docs import api_tags, api_summary, api_response

@app.route("/api/example/<id:int>")
@api_tags("示例")
@api_summary("获取示例详情")
@api_response(model=ExampleResponse)
async def get_example(request, id):
    # 实现逻辑
    ...
```

### 使用方法

1. 在你的API路由上添加装饰器注解
2. 运行应用程序，访问 `/swagger` 查看Swagger UI文档
3. 访问 `/redoc` 查看ReDoc文档

### 可用装饰器

- `api_tags`：指定API标签
- `api_summary`：设置API摘要
- `api_description`：设置API详细描述
- `api_body`：指定请求体模型
- `api_response`：定义响应模型
- `api_response_list`：定义列表响应
- `api_response_pagination`：定义分页响应
- `api_param`：添加API参数
- `api_paginated_params`：添加标准分页参数
- `api_security`：指定安全要求
- `api_exclude`：从文档中排除某个路由

## 安装与配置

### 安装依赖

```bash
pip install -r requirements.txt
```

### 运行开发服务器

```bash
python main.py
```

### 访问API文档

启动服务器后，访问以下URL：

- Swagger UI: http://localhost:22222/swagger
- ReDoc: http://localhost:22222/redoc

## 贡献指南

欢迎贡献代码、报告问题或提出改进建议。请遵循以下步骤：

1. Fork 项目仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

## 许可证

本项目采用 Apache License 2.0 许可证（Apache-2.0）。详情参见 [LICENSE](LICENSE) 文件。

## 联系方式

如有问题或建议，请通过Issue Tracker提出。
